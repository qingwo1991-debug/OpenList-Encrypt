import Flutter
import Foundation
import UIKit

/// Bridge implementation for common native APIs (iOS)
/// Android 逻辑不受任何影响
class CommonBridge: NSObject, NativeCommon {
    private let viewController: UIViewController?

    init(viewController: UIViewController? = nil) {
        self.viewController = viewController
        super.init()
    }

    func startActivityFromUri(intentUri: String) throws -> Bool {
        guard let url = URL(string: intentUri) else { return false }
        guard UIApplication.shared.canOpenURL(url) else { return false }
        UIApplication.shared.open(url, options: [:]) { success in
            print("[CommonBridge] Open URL result: \(success)")
        }
        return true
    }

    func getDeviceSdkInt() throws -> Int64 {
        // iOS: return major version as SDK int equivalent
        let systemVersion = UIDevice.current.systemVersion
        let majorVersion = systemVersion.components(separatedBy: ".").first ?? "0"
        return Int64(majorVersion) ?? 0
    }

    func getDeviceCPUABI() throws -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machineMirror = Mirror(reflecting: systemInfo.machine)
        let identifier = machineMirror.children.reduce("") { identifier, element in
            guard let value = element.value as? Int8, value != 0 else { return identifier }
            return identifier + String(UnicodeScalar(UInt8(value)))
        }
        return identifier
    }

    func getVersionName() throws -> String {
        return Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
    }

    func getVersionCode() throws -> Int64 {
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return Int64(build) ?? 1
    }

    func toast(msg: String) throws {
        showToast(message: msg, duration: 2.0)
    }

    func longToast(msg: String) throws {
        showToast(message: msg, duration: 4.0)
    }

    // MARK: - Toast Helper

    private func showToast(message: String, duration: TimeInterval) {
        DispatchQueue.main.async { [weak self] in
            guard let window = UIApplication.shared.connectedScenes
                .compactMap({ $0 as? UIWindowScene })
                .flatMap({ $0.windows })
                .first(where: { $0.isKeyWindow }) else {
                print("[CommonBridge] Toast fallback: \(msg)")
                return
            }

            let toastLabel = UILabel()
            toastLabel.backgroundColor = UIColor.black.withAlphaComponent(0.7)
            toastLabel.textColor = UIColor.white
            toastLabel.textAlignment = .center
            toastLabel.font = UIFont.systemFont(ofSize: 14)
            toastLabel.text = message
            toastLabel.alpha = 0.0
            toastLabel.layer.cornerRadius = 10
            toastLabel.clipsToBounds = true
            toastLabel.numberOfLines = 0

            let maxSize = CGSize(width: window.frame.width - 80, height: window.frame.height)
            let expectedSize = toastLabel.sizeThatFits(maxSize)
            toastLabel.frame = CGRect(
                x: (window.frame.width - expectedSize.width - 20) / 2,
                y: window.frame.height - 150,
                width: expectedSize.width + 20,
                height: expectedSize.height + 20
            )

            window.addSubview(toastLabel)
            UIView.animate(withDuration: 0.3, animations: {
                toastLabel.alpha = 1.0
            }) { _ in
                UIView.animate(withDuration: 0.3, delay: duration, options: [], animations: {
                    toastLabel.alpha = 0.0
                }) { _ in
                    toastLabel.removeFromSuperview()
                }
            }
        }
    }
}
