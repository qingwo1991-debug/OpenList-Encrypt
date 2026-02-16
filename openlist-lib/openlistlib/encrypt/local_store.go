package encrypt

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type StreamStrategy string

const (
	StreamStrategyRange   StreamStrategy = "range"
	StreamStrategyChunked StreamStrategy = "chunked"
)

type storeRecordKind int

const (
	recordKindSize storeRecordKind = iota
	recordKindStrategy
)

type storeRecord struct {
	kind         storeRecordKind
	key          string
	providerHost string
	originalPath string
	networkType  string
	strategy     StreamStrategy
	size         int64
	accessedAt   time.Time
}

type localStore struct {
	db             *sql.DB
	mu             sync.Mutex
	buffer         []storeRecord
	flushThreshold int
	flushing       bool
	closed         bool
}

type LocalSizeRecord struct {
	Key          string `json:"key"`
	ProviderHost string `json:"provider_host"`
	OriginalPath string `json:"original_path"`
	Size         int64  `json:"size"`
	LastAccessed int64  `json:"last_accessed"`
	UpdatedAt    int64  `json:"updated_at"`
}

type LocalStrategyRecord struct {
	Key          string `json:"key"`
	NetworkType  string `json:"network_type"`
	Strategy     string `json:"strategy"`
	ProviderHost string `json:"provider_host"`
	OriginalPath string `json:"original_path"`
	LastAccessed int64  `json:"last_accessed"`
	UpdatedAt    int64  `json:"updated_at"`
}

type LocalExport struct {
	Sizes      []LocalSizeRecord     `json:"sizes"`
	Strategies []LocalStrategyRecord `json:"strategies"`
}

const defaultFlushThreshold = 20

func newLocalStore(baseDir string) (*localStore, error) {
	if baseDir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(baseDir, "local_media.db")
	dsn := dbPath + "?_journal=WAL&_busy_timeout=5000&_foreign_keys=ON"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := initLocalSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &localStore{
		db:             db,
		flushThreshold: defaultFlushThreshold,
	}, nil
}

func initLocalSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS local_media_size (
            key TEXT PRIMARY KEY,
            provider_host TEXT NOT NULL,
            original_path TEXT NOT NULL,
            size INTEGER NOT NULL,
            last_accessed INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );`,
		`CREATE INDEX IF NOT EXISTS idx_local_media_size_accessed ON local_media_size(last_accessed);`,
		`CREATE TABLE IF NOT EXISTS local_media_strategy (
            key TEXT NOT NULL,
            network_type TEXT NOT NULL,
            strategy TEXT NOT NULL,
            provider_host TEXT NOT NULL,
            original_path TEXT NOT NULL,
            last_accessed INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (key, network_type)
        );`,
		`CREATE INDEX IF NOT EXISTS idx_local_media_strategy_accessed ON local_media_strategy(last_accessed);`,
		`CREATE TABLE IF NOT EXISTS local_sync_checkpoint (
            name TEXT PRIMARY KEY,
            since INTEGER NOT NULL,
            cursor TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL
        );`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *localStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.Flush(true)
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *localStore) Cleanup(sizeOlderThan, strategyOlderThan time.Duration) error {
	if s == nil || s.db == nil {
		return nil
	}
	if sizeOlderThan <= 0 {
		sizeOlderThan = time.Duration(defaultLocalSizeRetentionDays) * 24 * time.Hour
	}
	if strategyOlderThan <= 0 {
		strategyOlderThan = time.Duration(defaultLocalStrategyRetentionDays) * 24 * time.Hour
	}
	sizeCutoff := time.Now().Add(-sizeOlderThan).Unix()
	if _, err := s.db.Exec("DELETE FROM local_media_size WHERE last_accessed < ?", sizeCutoff); err != nil {
		return err
	}
	strategyCutoff := time.Now().Add(-strategyOlderThan).Unix()
	if _, err := s.db.Exec("DELETE FROM local_media_strategy WHERE last_accessed < ?", strategyCutoff); err != nil {
		return err
	}
	return nil
}

func (s *localStore) GetSize(key string) (int64, bool) {
	if s == nil || s.db == nil || key == "" {
		return 0, false
	}
	row := s.db.QueryRow("SELECT size FROM local_media_size WHERE key = ?", key)
	var size int64
	if err := row.Scan(&size); err != nil {
		return 0, false
	}
	if size <= 0 {
		return 0, false
	}
	return size, true
}

func (s *localStore) GetStrategy(key, networkType string) (StreamStrategy, bool) {
	if s == nil || s.db == nil || key == "" || networkType == "" {
		return "", false
	}
	row := s.db.QueryRow("SELECT strategy FROM local_media_strategy WHERE key = ? AND network_type = ?", key, strings.ToLower(networkType))
	var strategy string
	if err := row.Scan(&strategy); err != nil {
		return "", false
	}
	if strategy == "" {
		return "", false
	}
	return StreamStrategy(strategy), true
}

func (s *localStore) AddSize(key, providerHost, originalPath string, size int64, accessedAt time.Time) {
	if s == nil || key == "" || size <= 0 || providerHost == "" || originalPath == "" {
		return
	}
	if GetNetworkState() == NetworkStateOffline {
		return
	}
	s.enqueue(storeRecord{
		kind:         recordKindSize,
		key:          key,
		providerHost: providerHost,
		originalPath: originalPath,
		size:         size,
		accessedAt:   accessedAt,
	})
}

func (s *localStore) AddStrategy(key, providerHost, originalPath, networkType string, strategy StreamStrategy, accessedAt time.Time) {
	if s == nil || key == "" || providerHost == "" || originalPath == "" || networkType == "" || strategy == "" {
		return
	}
	if GetNetworkState() == NetworkStateOffline {
		return
	}
	s.enqueue(storeRecord{
		kind:         recordKindStrategy,
		key:          key,
		providerHost: providerHost,
		originalPath: originalPath,
		networkType:  strings.ToLower(networkType),
		strategy:     strategy,
		accessedAt:   accessedAt,
	})
}

func (s *localStore) Flush(force bool) error {
	if s == nil || s.db == nil {
		return nil
	}
	if GetNetworkState() == NetworkStateOffline {
		return nil
	}
	s.mu.Lock()
	if len(s.buffer) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := s.buffer
	s.buffer = nil
	s.flushing = true
	s.mu.Unlock()

	err := s.flushBatch(batch)

	s.mu.Lock()
	s.flushing = false
	s.mu.Unlock()

	return err
}

func (s *localStore) enqueue(record storeRecord) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.buffer = append(s.buffer, record)
	if len(s.buffer) < s.flushThreshold || s.flushing {
		s.mu.Unlock()
		return
	}
	batch := s.buffer
	s.buffer = nil
	s.flushing = true
	s.mu.Unlock()

	go s.flushBatchAsync(batch)
}

func (s *localStore) flushBatchAsync(batch []storeRecord) {
	_ = s.flushBatch(batch)

	s.mu.Lock()
	s.flushing = false
	if len(s.buffer) < s.flushThreshold {
		s.mu.Unlock()
		return
	}
	next := s.buffer
	s.buffer = nil
	s.flushing = true
	s.mu.Unlock()

	go s.flushBatchAsync(next)
}

func (s *localStore) flushBatch(batch []storeRecord) error {
	if s.db == nil {
		return nil
	}
	if len(batch) == 0 {
		return nil
	}
	if GetNetworkState() == NetworkStateOffline {
		s.mu.Lock()
		if !s.closed {
			s.buffer = append(batch, s.buffer...)
		}
		s.mu.Unlock()
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	insertSize, err := tx.Prepare(`INSERT INTO local_media_size
        (key, provider_host, original_path, size, last_accessed, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
        provider_host=excluded.provider_host,
        original_path=excluded.original_path,
        size=excluded.size,
        last_accessed=excluded.last_accessed,
        updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer insertSize.Close()

	insertStrategy, err := tx.Prepare(`INSERT INTO local_media_strategy
        (key, network_type, strategy, provider_host, original_path, last_accessed, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key, network_type) DO UPDATE SET
        strategy=excluded.strategy,
        provider_host=excluded.provider_host,
        original_path=excluded.original_path,
        last_accessed=excluded.last_accessed,
        updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer insertStrategy.Close()

	for _, record := range batch {
		ts := record.accessedAt.Unix()
		switch record.kind {
		case recordKindSize:
			if _, err := insertSize.Exec(record.key, record.providerHost, record.originalPath, record.size, ts, ts); err != nil {
				return err
			}
		case recordKindStrategy:
			if _, err := insertStrategy.Exec(record.key, record.networkType, record.strategy, record.providerHost, record.originalPath, ts, ts); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

func (s *localStore) GetSnapshot(key string) (*LocalSizeRecord, []LocalStrategyRecord, error) {
	if s == nil || s.db == nil || key == "" {
		return nil, nil, nil
	}
	row := s.db.QueryRow("SELECT provider_host, original_path, size, last_accessed, updated_at FROM local_media_size WHERE key = ?", key)
	var sizeRec LocalSizeRecord
	sizeRec.Key = key
	if err := row.Scan(&sizeRec.ProviderHost, &sizeRec.OriginalPath, &sizeRec.Size, &sizeRec.LastAccessed, &sizeRec.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	rows, err := s.db.Query("SELECT network_type, strategy, provider_host, original_path, last_accessed, updated_at FROM local_media_strategy WHERE key = ?", key)
	if err != nil {
		return &sizeRec, nil, err
	}
	defer rows.Close()

	strategies := make([]LocalStrategyRecord, 0)
	for rows.Next() {
		var rec LocalStrategyRecord
		rec.Key = key
		if err := rows.Scan(&rec.NetworkType, &rec.Strategy, &rec.ProviderHost, &rec.OriginalPath, &rec.LastAccessed, &rec.UpdatedAt); err != nil {
			return &sizeRec, strategies, err
		}
		strategies = append(strategies, rec)
	}
	if err := rows.Err(); err != nil {
		return &sizeRec, strategies, err
	}
	return &sizeRec, strategies, nil
}

func (s *localStore) ExportAll() (*LocalExport, error) {
	if s == nil || s.db == nil {
		return &LocalExport{}, nil
	}
	data := &LocalExport{}

	rows, err := s.db.Query("SELECT key, provider_host, original_path, size, last_accessed, updated_at FROM local_media_size")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rec LocalSizeRecord
		if err := rows.Scan(&rec.Key, &rec.ProviderHost, &rec.OriginalPath, &rec.Size, &rec.LastAccessed, &rec.UpdatedAt); err != nil {
			_ = rows.Close()
			return nil, err
		}
		data.Sizes = append(data.Sizes, rec)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	rows, err = s.db.Query("SELECT key, network_type, strategy, provider_host, original_path, last_accessed, updated_at FROM local_media_strategy")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rec LocalStrategyRecord
		if err := rows.Scan(&rec.Key, &rec.NetworkType, &rec.Strategy, &rec.ProviderHost, &rec.OriginalPath, &rec.LastAccessed, &rec.UpdatedAt); err != nil {
			_ = rows.Close()
			return nil, err
		}
		data.Strategies = append(data.Strategies, rec)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	return data, nil
}

func (s *localStore) Import(data *LocalExport) error {
	if s == nil || s.db == nil || data == nil {
		return nil
	}
	if GetNetworkState() == NetworkStateOffline {
		return errors.New("network offline: import blocked")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	insertSize, err := tx.Prepare(`INSERT INTO local_media_size
        (key, provider_host, original_path, size, last_accessed, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
        provider_host=excluded.provider_host,
        original_path=excluded.original_path,
        size=excluded.size,
        last_accessed=excluded.last_accessed,
        updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer insertSize.Close()

	insertStrategy, err := tx.Prepare(`INSERT INTO local_media_strategy
        (key, network_type, strategy, provider_host, original_path, last_accessed, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key, network_type) DO UPDATE SET
        strategy=excluded.strategy,
        provider_host=excluded.provider_host,
        original_path=excluded.original_path,
        last_accessed=excluded.last_accessed,
        updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer insertStrategy.Close()

	now := time.Now().Unix()
	for _, rec := range data.Sizes {
		key := rec.Key
		if key == "" && rec.ProviderHost != "" && rec.OriginalPath != "" {
			key = buildLocalKey(rec.ProviderHost, rec.OriginalPath)
		}
		if key == "" || rec.ProviderHost == "" || rec.OriginalPath == "" || rec.Size <= 0 {
			continue
		}
		lastAccessed := rec.LastAccessed
		updatedAt := rec.UpdatedAt
		if lastAccessed <= 0 {
			lastAccessed = now
		}
		if updatedAt <= 0 {
			updatedAt = now
		}
		if _, err := insertSize.Exec(key, rec.ProviderHost, rec.OriginalPath, rec.Size, lastAccessed, updatedAt); err != nil {
			return err
		}
	}

	for _, rec := range data.Strategies {
		key := rec.Key
		if key == "" && rec.ProviderHost != "" && rec.OriginalPath != "" {
			key = buildLocalKey(rec.ProviderHost, rec.OriginalPath)
		}
		if key == "" || rec.ProviderHost == "" || rec.OriginalPath == "" || rec.Strategy == "" || rec.NetworkType == "" {
			continue
		}
		lastAccessed := rec.LastAccessed
		updatedAt := rec.UpdatedAt
		if lastAccessed <= 0 {
			lastAccessed = now
		}
		if updatedAt <= 0 {
			updatedAt = now
		}
		if _, err := insertStrategy.Exec(key, strings.ToLower(rec.NetworkType), rec.Strategy, rec.ProviderHost, rec.OriginalPath, lastAccessed, updatedAt); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *localStore) Counts() (int, int, error) {
	if s == nil || s.db == nil {
		return 0, 0, nil
	}
	row := s.db.QueryRow("SELECT COUNT(1) FROM local_media_size")
	var sizeCount int
	if err := row.Scan(&sizeCount); err != nil {
		return 0, 0, err
	}
	row = s.db.QueryRow("SELECT COUNT(1) FROM local_media_strategy")
	var strategyCount int
	if err := row.Scan(&strategyCount); err != nil {
		return sizeCount, 0, err
	}
	return sizeCount, strategyCount, nil
}

func (s *localStore) GetSyncCheckpoint(name string) (int64, string, error) {
	if s == nil || s.db == nil || name == "" {
		return 0, "", nil
	}
	row := s.db.QueryRow("SELECT since, cursor FROM local_sync_checkpoint WHERE name = ?", name)
	var since int64
	var cursor string
	if err := row.Scan(&since, &cursor); err != nil {
		if err == sql.ErrNoRows {
			return 0, "", nil
		}
		return 0, "", err
	}
	return since, cursor, nil
}

func (s *localStore) SaveSyncCheckpoint(name string, since int64, cursor string) error {
	if s == nil || s.db == nil || name == "" {
		return nil
	}
	if since < 0 {
		since = 0
	}
	_, err := s.db.Exec(`INSERT INTO local_sync_checkpoint (name, since, cursor, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
        since=excluded.since,
        cursor=excluded.cursor,
        updated_at=excluded.updated_at`, name, since, cursor, time.Now().Unix())
	return err
}
