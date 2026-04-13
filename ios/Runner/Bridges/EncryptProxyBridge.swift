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
        print("[EncryptProxyBridge] initEncryptProxy: \(configPath)")
        var error: NSError?
        OpenlistlibInitEncryptProxy(configPath, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to init encrypt proxy: \(err)")
            throw err
        }
    }

    func startEncryptProxy() throws {
        print("[EncryptProxyBridge] startEncryptProxy")
        var error: NSError?
        OpenlistlibStartEncryptProxy(&error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to start encrypt proxy: \(err)")
            throw err
        }
    }

    func stopEncryptProxy() throws {
        print("[EncryptProxyBridge] stopEncryptProxy")
        var error: NSError?
        OpenlistlibStopEncryptProxy(&error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to stop encrypt proxy: \(err)")
            throw err
        }
    }

    func restartEncryptProxy() throws {
        print("[EncryptProxyBridge] restartEncryptProxy")
        var error: NSError?
        OpenlistlibRestartEncryptProxy(&error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to restart encrypt proxy: \(err)")
            throw err
        }
    }

    func isEncryptProxyRunning() throws -> Bool {
        return OpenlistlibIsEncryptProxyRunning()
    }

    func getEncryptProxyPort() throws -> Int64 {
        return OpenlistlibGetEncryptProxyPort()
    }

    func setEncryptAlistHost(host: String, port: Int64, https: Bool) throws {
        print("[EncryptProxyBridge] setEncryptAlistHost: host=\(host), port=\(port), https=\(https)")
        var error: NSError?
        OpenlistlibSetEncryptAlistHost(host, port, https, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set alist host: \(err)")
            throw err
        }
    }

    func setEncryptProxyPort(port: Int64) throws {
        print("[EncryptProxyBridge] setEncryptProxyPort: port=\(port)")
        var error: NSError?
        OpenlistlibSetEncryptProxyPort(port, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set proxy port: \(err)")
            throw err
        }
    }

    func setEncryptEnableH2C(enable: Bool) throws {
        print("[EncryptProxyBridge] setEncryptEnableH2C: enable=\(enable)")
        var error: NSError?
        OpenlistlibSetEncryptEnableH2C(enable, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set H2C: \(err)")
            throw err
        }
    }

    func getEncryptEnableH2C() throws -> Bool {
        return OpenlistlibGetEncryptEnableH2C()
    }

    func setEncryptDbExportSyncConfig(enable: Bool, baseUrl: String, intervalSeconds: Int64, authEnabled: Bool, username: String, password: String) throws {
        print("[EncryptProxyBridge] setEncryptDbExportSyncConfig: enable=\(enable), baseUrl=\(baseUrl)")
        var error: NSError?
        OpenlistlibSetEncryptDbExportSyncConfig(enable, baseUrl, intervalSeconds, authEnabled, username, password, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set DB export sync config: \(err)")
            throw err
        }
    }

    func setEncryptNetworkPolicy(upstreamTimeoutSeconds: Int64, probeTimeoutSeconds: Int64, probeBudgetSeconds: Int64, upstreamBackoffSeconds: Int64, enableLocalBypass: Bool) throws {
        print("[EncryptProxyBridge] setEncryptNetworkPolicy: enableLocalBypass=\(enableLocalBypass)")
        var error: NSError?
        OpenlistlibSetEncryptNetworkPolicy(upstreamTimeoutSeconds, probeTimeoutSeconds, probeBudgetSeconds, upstreamBackoffSeconds, enableLocalBypass, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set network policy: \(err)")
            throw err
        }
    }

    func addEncryptPath(path: String, password: String, encType: String, encName: Bool, encSuffix: String) throws {
        print("[EncryptProxyBridge] addEncryptPath: path=\(path)")
        var error: NSError?
        OpenlistlibAddEncryptPathConfig(path, password, encType, encName, encSuffix, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to add encrypt path: \(err)")
            throw err
        }
    }

    func updateEncryptPath(index: Int64, path: String, password: String, encType: String, encName: Bool, encSuffix: String, enable: Bool) throws {
        print("[EncryptProxyBridge] updateEncryptPath: index=\(index)")
        var error: NSError?
        OpenlistlibUpdateEncryptPathConfig(index, path, password, encType, encName, encSuffix, enable, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to update encrypt path: \(err)")
            throw err
        }
    }

    func removeEncryptPath(index: Int64) throws {
        print("[EncryptProxyBridge] removeEncryptPath: index=\(index)")
        var error: NSError?
        OpenlistlibRemoveEncryptPathConfig(index, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to remove encrypt path: \(err)")
            throw err
        }
    }

    func getEncryptPathsJson() throws -> String {
        return OpenlistlibGetEncryptPathsJson()
    }

    func getEncryptConfigJson() throws -> String {
        return OpenlistlibGetEncryptConfigJson()
    }

    func setEncryptAdminPassword(password: String) throws {
        print("[EncryptProxyBridge] setEncryptAdminPassword")
        var error: NSError?
        OpenlistlibSetEncryptAdminPassword(password, &error)
        if let err = error {
            print("[EncryptProxyBridge] Failed to set admin password: \(err)")
            throw err
        }
    }

    func verifyEncryptAdminPassword(password: String) throws -> Bool {
        return OpenlistlibVerifyEncryptAdminPassword(password)
    }
}
