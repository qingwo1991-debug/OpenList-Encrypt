import Flutter
import Foundation

/// Bridge implementation for App Configuration APIs (iOS)
/// Android 逻辑不受任何影响
class AppConfigBridge: NSObject, AppConfig {
    private let defaults = UserDefaults.standard

    private enum Keys {
        static let wakeLock = "app_config_wake_lock"
        static let startAtBoot = "app_config_start_at_boot"
        static let autoCheckUpdate = "app_config_auto_check_update"
        static let autoOpenWebPage = "app_config_auto_open_web_page"
        static let dataDir = "app_config_data_dir"
        static let silentJumpApp = "app_config_silent_jump_app"
    }

    func isWakeLockEnabled() throws -> Bool {
        return defaults.bool(forKey: Keys.wakeLock)
    }

    func setWakeLockEnabled(enabled: Bool) throws {
        defaults.set(enabled, forKey: Keys.wakeLock)
    }

    func isStartAtBootEnabled() throws -> Bool {
        return defaults.bool(forKey: Keys.startAtBoot)
    }

    func setStartAtBootEnabled(enabled: Bool) throws {
        defaults.set(enabled, forKey: Keys.startAtBoot)
    }

    func isAutoCheckUpdateEnabled() throws -> Bool {
        return defaults.bool(forKey: Keys.autoCheckUpdate)
    }

    func setAutoCheckUpdateEnabled(enabled: Bool) throws {
        defaults.set(enabled, forKey: Keys.autoCheckUpdate)
    }

    func isAutoOpenWebPageEnabled() throws -> Bool {
        return defaults.bool(forKey: Keys.autoOpenWebPage)
    }

    func setAutoOpenWebPageEnabled(enabled: Bool) throws {
        defaults.set(enabled, forKey: Keys.autoOpenWebPage)
    }

    func getDataDir() throws -> String {
        if let customDir = defaults.string(forKey: Keys.dataDir), !customDir.isEmpty {
            return customDir
        }

        // Default to app's document directory with openlist_data subdirectory
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        let documentsDirectory = paths[0]
        let openlistDataDir = documentsDirectory.appendingPathComponent("openlist_data")

        if !FileManager.default.fileExists(atPath: openlistDataDir.path) {
            try FileManager.default.createDirectory(at: openlistDataDir, withIntermediateDirectories: true, attributes: nil)
        }

        return openlistDataDir.path
    }

    func setDataDir(dir: String) throws {
        if dir.isEmpty {
            defaults.removeObject(forKey: Keys.dataDir)
        } else {
            // iOS: only allow paths within app's container
            let appDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].path
            if dir.hasPrefix(appDir) {
                defaults.set(dir, forKey: Keys.dataDir)
            } else {
                print("[AppConfigBridge] Rejected data directory outside app container: \(dir)")
            }
        }
    }

    func isSilentJumpAppEnabled() throws -> Bool {
        return defaults.bool(forKey: Keys.silentJumpApp)
    }

    func setSilentJumpAppEnabled(enabled: Bool) throws {
        defaults.set(enabled, forKey: Keys.silentJumpApp)
    }
}
