import Foundation

/// Manages OpenList core server lifecycle (iOS)
/// Android 逻辑不受任何影响
class OpenListManager: NSObject {
    static let shared = OpenListManager()

    private var isInitialized = false
    private var isServerRunning = false
    private var dataDir: String?

    // Strong references to prevent deallocation
    var eventHandler: OpenListEventHandler?
    var logCallback: OpenListLogCallback?

    private override init() {
        super.init()
    }

    private func ensureInitializedForConfig() throws {
        if isInitialized { return }

        let eventHandler = OpenListEventHandler()
        let logCallback = OpenListLogCallback()

        let appDelegate = UIApplication.shared.delegate as? AppDelegate
        eventHandler.eventAPI = appDelegate?.eventAPI
        logCallback.eventAPI = appDelegate?.eventAPI

        self.eventHandler = eventHandler
        self.logCallback = logCallback

        try initialize(event: eventHandler, logger: logCallback)
    }

    // MARK: - Initialization

    func initialize(event: OpenListEventHandler, logger: OpenListLogCallback) throws {
        guard !isInitialized else {
            print("[OpenListManager] Already initialized")
            return
        }

        // Get data directory from AppConfigBridge
        let appConfig = AppConfigBridge()
        let dataDirPath: String
        do {
            dataDirPath = try appConfig.getDataDir()
            self.dataDir = dataDirPath
            print("[OpenListManager] Data directory: \(dataDirPath)")
        } catch {
            print("[OpenListManager] Failed to get data directory: \(error)")
            throw error
        }

        // Set data directory for OpenList core
        OpenlistlibSetConfigData(dataDirPath)

        // Enable stdout logging
        OpenlistlibSetConfigLogStd(true)

        var error: NSError?
        OpenlistlibInit(event, logger, &error)
        if let err = error {
            print("[OpenListManager] Initialization failed: \(err)")
            throw err
        }

        isInitialized = true
        print("[OpenListManager] Initialized successfully with data directory: \(dataDirPath)")
    }

    // MARK: - Server Control

    func startServer() {
        print("[OpenListManager] Start server request received")

        if !isInitialized {
            print("[OpenListManager] Not initialized, attempting initialization...")
            let eventHandler = OpenListEventHandler()
            let logCallback = OpenListLogCallback()

            let appDelegate = UIApplication.shared.delegate as? AppDelegate
            eventHandler.eventAPI = appDelegate?.eventAPI
            logCallback.eventAPI = appDelegate?.eventAPI

            OpenListManager.shared.eventHandler = eventHandler
            OpenListManager.shared.logCallback = logCallback

            do {
                try initialize(event: eventHandler, logger: logCallback)
                print("[OpenListManager] Initialization completed, proceeding to start server")
            } catch {
                print("[OpenListManager] Initialization failed: \(error), cannot start server")
                return
            }
        }

        guard !isServerRunning else {
            print("[OpenListManager] Server already running")
            return
        }

        print("[OpenListManager] Starting OpenList server...")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            OpenlistlibStart()

            // Small delay to ensure server is ready
            Thread.sleep(forTimeInterval: 0.5)

            DispatchQueue.main.async {
                self?.isServerRunning = true
                print("[OpenListManager] Server started successfully")

                // Notify Flutter side
                if let eventAPI = (UIApplication.shared.delegate as? AppDelegate)?.eventAPI {
                    eventAPI.onServiceStatusChanged(isRunning: true) { result in
                        if case .failure(let error) = result {
                            print("[OpenListManager] Failed to notify Flutter: \(error)")
                        }
                    }
                }
            }
        }
    }

    func stopServer(timeout: Int64 = 5000) {
        guard isServerRunning else {
            print("[OpenListManager] Server not running")
            return
        }

        print("[OpenListManager] Stopping OpenList server...")
        var error: NSError?
        OpenlistlibShutdown(timeout, &error)
        if let err = error {
            print("[OpenListManager] Failed to stop server: \(err)")
            return
        }
        isServerRunning = false
        print("[OpenListManager] Server stopped")
    }

    func isRunning() -> Bool {
        return isServerRunning && OpenlistlibIsRunning("http")
    }

    func getHttpPort() -> Int {
        return 5244
    }

    func setAdminPassword(_ pwd: String) throws {
        try ensureInitializedForConfig()

        if let dataDir = dataDir {
            OpenlistlibSetConfigData(dataDir)
        }

        OpenlistlibSetAdminPassword(pwd)
        print("[OpenListManager] Admin password updated")
    }

    func forceDBSync() {
        var error: NSError?
        OpenlistlibForceDBSync(&error)
        if let err = error {
            print("[OpenListManager] Database sync failed: \(err)")
            return
        }
        print("[OpenListManager] Database sync completed")
    }
}

// MARK: - Event Handler

class OpenListEventHandler: NSObject, OpenlistlibEventProtocol {
    weak var eventAPI: Event?

    func onStartError(_ t: String?, err: String?) {
        print("[OpenListEvent] Start error - Type: \(t ?? "unknown"), Error: \(err ?? "unknown")")
    }

    func onShutdown(_ t: String?) {
        print("[OpenListEvent] Shutdown - Type: \(t ?? "unknown")")
    }

    func onProcessExit(_ code: Int) {
        print("[OpenListEvent] Process exit - Code: \(code)")
    }
}

// MARK: - Log Callback

class OpenListLogCallback: NSObject, OpenlistlibLogCallbackProtocol {
    weak var eventAPI: Event?

    func onLog(_ level: Int16, time: Int64, message: String?) {
        let logMessage = message ?? ""
        print("[OpenListLog] Level: \(level), Message: \(logMessage)")

        if let api = eventAPI {
            api.onServerLog(level: Int64(level), time: "\(time)", log: logMessage) { result in
                if case .failure(let error) = result {
                    print("[OpenListLog] Failed to send log to Flutter: \(error)")
                }
            }
        }
    }
}
