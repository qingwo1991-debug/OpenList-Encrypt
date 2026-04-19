import Flutter
import Foundation

/// Bridge implementation for Encrypt Proxy management (iOS)
/// 这是 OpenList-Encrypt 特有的功能，上游 OpenList-Mobile 没有
/// Android 逻辑不受任何影响
class EncryptProxyBridge: NSObject, EncryptProxy {

    override init() {
        super.init()
    }

    func initEncryptProxy(configPath: String) throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] initEncryptProxy: \(configPath)")
        var error: NSError?
        OpenlistlibInitEncryptProxy(configPath, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to init encrypt proxy: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping initEncryptProxy")
        #endif
    }

    func startEncryptProxy() throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] startEncryptProxy")
        var error: NSError?
        OpenlistlibStartEncryptProxy(&error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to start encrypt proxy: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping startEncryptProxy")
        #endif
    }

    func stopEncryptProxy() throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] stopEncryptProxy")
        var error: NSError?
        OpenlistlibStopEncryptProxy(&error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to stop encrypt proxy: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping stopEncryptProxy")
        #endif
    }

    func restartEncryptProxy() throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] restartEncryptProxy")
        var error: NSError?
        OpenlistlibRestartEncryptProxy(&error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to restart encrypt proxy: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping restartEncryptProxy")
        #endif
    }

    func isEncryptProxyRunning() throws -> Bool {
        #if canImport(Openlistlib)
        return OpenlistlibIsEncryptProxyRunning()
        #else
        return false
        #endif
    }

    func getEncryptProxyPort() throws -> Int64 {
        #if canImport(Openlistlib)
        return OpenlistlibGetEncryptProxyPort()
        #else
        return 0
        #endif
    }

    func setEncryptAlistHost(host: String, port: Int64, https: Bool) throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] setEncryptAlistHost: host=\(host), port=\(port), https=\(https)")
        var error: NSError?
        OpenlistlibSetEncryptAlistHost(host, port, https, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set alist host: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping setEncryptAlistHost")
        #endif
    }

    func setEncryptProxyPort(port: Int64) throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] setEncryptProxyPort: port=\(port)")
        var error: NSError?
        OpenlistlibSetEncryptProxyPort(port, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set proxy port: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping setEncryptProxyPort")
        #endif
    }

    func setEncryptEnableH2C(enable: Bool) throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] setEncryptEnableH2C: enable=\(enable)")
        var error: NSError?
        OpenlistlibSetEncryptEnableH2C(enable, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set H2C: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping setEncryptEnableH2C")
        #endif
    }

    func getEncryptEnableH2C() throws -> Bool {
        #if canImport(Openlistlib)
        return OpenlistlibGetEncryptEnableH2C()
        #else
        return false
        #endif
    }

    func setEncryptDbExportSyncConfig(enable: Bool, baseUrl: String, intervalSeconds: Int64, authEnabled: Bool, username: String, password: String) throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] setEncryptDbExportSyncConfig: enable=\(enable), baseUrl=\(baseUrl)")
        var error: NSError?
        OpenlistlibSetEncryptDbExportSyncConfig(enable, baseUrl, intervalSeconds, authEnabled, username, password, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set DB export sync config: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping setEncryptDbExportSyncConfig")
        #endif
    }

    func setEncryptNetworkPolicy(upstreamTimeoutSeconds: Int64, probeTimeoutSeconds: Int64, probeBudgetSeconds: Int64, upstreamBackoffSeconds: Int64, enableLocalBypass: Bool) throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] setEncryptNetworkPolicy: enableLocalBypass=\(enableLocalBypass)")
        var error: NSError?
        OpenlistlibSetEncryptNetworkPolicy(upstreamTimeoutSeconds, probeTimeoutSeconds, probeBudgetSeconds, upstreamBackoffSeconds, enableLocalBypass, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set network policy: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping setEncryptNetworkPolicy")
        #endif
    }

    func addEncryptPath(path: String, password: String, encType: String, encName: Bool, encSuffix: String) throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] addEncryptPath: path=\(path)")
        var error: NSError?
        OpenlistlibAddEncryptPathConfig(path, password, encType, encName, encSuffix, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to add encrypt path: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping addEncryptPath")
        #endif
    }

    func updateEncryptPath(index: Int64, path: String, password: String, encType: String, encName: Bool, encSuffix: String, enable: Bool) throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] updateEncryptPath: index=\(index)")
        var error: NSError?
        OpenlistlibUpdateEncryptPathConfig(index, path, password, encType, encName, encSuffix, enable, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to update encrypt path: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping updateEncryptPath")
        #endif
    }

    func removeEncryptPath(index: Int64) throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] removeEncryptPath: index=\(index)")
        var error: NSError?
        OpenlistlibRemoveEncryptPathConfig(index, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to remove encrypt path: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping removeEncryptPath")
        #endif
    }

    func getEncryptPathsJson() throws -> String {
        #if canImport(Openlistlib)
        return OpenlistlibGetEncryptPathsJson()
        #else
        return "[]"
        #endif
    }

    func getEncryptConfigJson() throws -> String {
        #if canImport(Openlistlib)
        return OpenlistlibGetEncryptConfigJson()
        #else
        return "{}"
        #endif
    }

    func setEncryptAdminPassword(password: String) throws {
        #if canImport(Openlistlib)
        print("[EncryptProxyBridge] setEncryptAdminPassword")
        var error: NSError?
        OpenlistlibSetEncryptAdminPassword(password, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set admin password: \(err)")
            throw err
        }
        #else
        print("[EncryptProxyBridge] Openlistlib not available, skipping setEncryptAdminPassword")
        #endif
    }

    func verifyEncryptAdminPassword(password: String) throws -> Bool {
        #if canImport(Openlistlib)
        return OpenlistlibVerifyEncryptAdminPassword(password)
        #else
        return false
        #endif
    }
}
