package middlewares

import (
	"io"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/gin-gonic/gin"
)

func MaxAllowed(n int) gin.HandlerFunc {
	sem := make(chan struct{}, n)
	acquire := func() { sem <- struct{}{} }
	release := func() { <-sem }
	return func(c *gin.Context) {
		acquire()
		defer release()
		c.Next()
	}
}

func isDataPlanePath(requestPath string) bool {
	p := strings.ToLower(requestPath)
	return strings.Contains(p, "/d/") ||
		strings.Contains(p, "/p/") ||
		strings.Contains(p, "/ad/") ||
		strings.Contains(p, "/ap/") ||
		strings.Contains(p, "/ae/") ||
		strings.Contains(p, "/sd/") ||
		strings.Contains(p, "/sad/") ||
		strings.Contains(p, "/dav")
}

func classifyPath(requestPath string) string {
	p := strings.ToLower(requestPath)
	switch {
	case strings.Contains(p, "/auth/"), strings.Contains(p, "/me"), strings.Contains(p, "/webauthn"), strings.Contains(p, "/login"):
		return "auth"
	case strings.Contains(p, "/dav"):
		return "webdav"
	case isDataPlanePath(p):
		return "download"
	default:
		return "api"
	}
}

// MaxAllowedByClass 将并发隔离为 auth/api/download/webdav 四类
func MaxAllowedByClass(authN, apiN, downloadN, webdavN int) gin.HandlerFunc {
	if authN <= 0 {
		authN = 1
	}
	if apiN <= 0 {
		apiN = 1
	}
	if downloadN <= 0 {
		downloadN = 1
	}
	if webdavN <= 0 {
		webdavN = 1
	}
	authSem := make(chan struct{}, authN)
	apiSem := make(chan struct{}, apiN)
	downloadSem := make(chan struct{}, downloadN)
	webdavSem := make(chan struct{}, webdavN)

	return func(c *gin.Context) {
		var sem chan struct{}
		switch classifyPath(c.Request.URL.Path) {
		case "auth":
			sem = authSem
		case "webdav":
			sem = webdavSem
		case "download":
			sem = downloadSem
		default:
			sem = apiSem
		}
		sem <- struct{}{}
		defer func() { <-sem }()
		c.Next()
	}
}

func UploadRateLimiter(limiter stream.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = &stream.RateLimitReader{
			Reader:  c.Request.Body,
			Limiter: limiter,
			Ctx:     c,
		}
		c.Next()
	}
}

type ResponseWriterWrapper struct {
	gin.ResponseWriter
	WrapWriter io.Writer
}

func (w *ResponseWriterWrapper) Write(p []byte) (n int, err error) {
	return w.WrapWriter.Write(p)
}

func DownloadRateLimiter(limiter stream.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer = &ResponseWriterWrapper{
			ResponseWriter: c.Writer,
			WrapWriter: &stream.RateLimitWriter{
				Writer:  c.Writer,
				Limiter: limiter,
				Ctx:     c,
			},
		}
		c.Next()
	}
}
