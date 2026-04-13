import 'dart:async';
import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart';

import '../contant/native_bridge.dart';

/// 服务管理器 - 管理OpenList后台服务的启动、停止和状态监控
/// Android: 使用 ServiceBridge MethodChannel (原有逻辑，一字不改)
/// iOS:     使用 Pigeon API (Android/EncryptProxy) + 独立 MethodChannel
class ServiceManager {
  static const String _androidChannelName = 'com.openlist.mobile/service';
  static const MethodChannel _androidChannel = MethodChannel(_androidChannelName);

  // iOS: separate channel for stopService (not in Pigeon Android interface)
  static const String _iosChannelName = 'com.openlistencrypt/service';
  static const MethodChannel _iosChannel = MethodChannel(_iosChannelName);

  static ServiceManager? _instance;
  static ServiceManager get instance => _instance ??= ServiceManager._();

  ServiceManager._();

  // 服务状态流控制器
  final StreamController<bool> _serviceStatusController = StreamController<bool>.broadcast();

  /// 服务状态流
  Stream<bool> get serviceStatusStream => _serviceStatusController.stream;

  bool _isServiceRunning = false;
  Timer? _statusCheckTimer;

  /// 当前服务是否运行
  bool get isServiceRunning => _isServiceRunning;

  /// 初始化服务管理器
  Future<void> initialize() async {
    // === Android path (unchanged) ===
    if (Platform.isAndroid) {
      try {
        _androidChannel.setMethodCallHandler(_handleMethodCall);
        _startStatusCheck();
        await checkServiceStatus();
        debugPrint('ServiceManager initialized (Android)');
      } catch (e) {
        debugPrint('Failed to initialize ServiceManager: $e');
      }
      return;
    }

    // === iOS path (new) ===
    if (Platform.isIOS) {
      try {
        _iosChannel.setMethodCallHandler(_handleMethodCall);
        _startStatusCheck();
        await checkServiceStatus();
        debugPrint('ServiceManager initialized (iOS)');
      } catch (e) {
        debugPrint('Failed to initialize ServiceManager on iOS: $e');
      }
      return;
    }

    // Other platforms: no-op
  }

  /// 处理来自原生端的方法调用
  Future<dynamic> _handleMethodCall(MethodCall call) async {
    debugPrint('ServiceManager received method call: ${call.method}');
    switch (call.method) {
      case 'onServiceStatusChanged':
        final bool isRunning = call.arguments['isRunning'] ?? false;
        debugPrint('ServiceManager status change notification: $isRunning');
        _updateServiceStatus(isRunning);
        break;
      default:
        debugPrint('Unknown method call: ${call.method}');
    }
  }

  /// 启动OpenList服务
  Future<bool> startService() async {
    // === Android path (unchanged) ===
    if (Platform.isAndroid) {
      try {
        final bool result = await _androidChannel.invokeMethod('startService');
        debugPrint('Start service result: $result');
        Timer(const Duration(seconds: 2), () => checkServiceStatus());
        return result;
      } catch (e) {
        debugPrint('Failed to start service: $e');
        return false;
      }
    }

    // === iOS path (new) ===
    if (Platform.isIOS) {
      try {
        await NativeBridge.android.startService();
        debugPrint('Start service called (iOS via Pigeon)');
        Timer(const Duration(seconds: 2), () => checkServiceStatus());
        return true;
      } catch (e) {
        debugPrint('Failed to start service on iOS: $e');
        return false;
      }
    }

    return false;
  }

  /// 停止OpenList服务
  Future<bool> stopService() async {
    // === Android path (unchanged) ===
    if (Platform.isAndroid) {
      try {
        final bool result = await _androidChannel.invokeMethod('stopService');
        debugPrint('Stop service result: $result');
        if (result) {
          _updateServiceStatus(false);
        }
        Timer(const Duration(seconds: 1), () => checkServiceStatus());
        return result;
      } catch (e) {
        debugPrint('Failed to stop service: $e');
        return false;
      }
    }

    // === iOS path (new) ===
    if (Platform.isIOS) {
      try {
        final bool result = await _iosChannel.invokeMethod('stopService');
        debugPrint('Stop service result (iOS): $result');
        if (result) {
          _updateServiceStatus(false);
        }
        Timer(const Duration(seconds: 1), () => checkServiceStatus());
        return result;
      } catch (e) {
        debugPrint('Failed to stop service on iOS: $e');
        return false;
      }
    }

    return false;
  }

  /// 检查服务状态
  Future<bool> checkServiceStatus() async {
    // === Android path (unchanged) ===
    if (Platform.isAndroid) {
      try {
        final bool isRunning = await _androidChannel.invokeMethod('isServiceRunning');
        _updateServiceStatus(isRunning);
        return isRunning;
      } catch (e) {
        debugPrint('Failed to check service status: $e');
        return false;
      }
    }

    // === iOS path (new) ===
    if (Platform.isIOS) {
      try {
        final bool isRunning = await NativeBridge.android.isRunning();
        _updateServiceStatus(isRunning);
        return isRunning;
      } catch (e) {
        debugPrint('Failed to check service status on iOS: $e');
        return false;
      }
    }

    return false;
  }

  /// 重启服务
  Future<bool> restartService() async {
    if (!Platform.isAndroid && !Platform.isIOS) return false;

    try {
      await stopService();
      await Future.delayed(const Duration(seconds: 2));
      return await startService();
    } catch (e) {
      debugPrint('Failed to restart service: $e');
      return false;
    }
  }

  /// 检查是否在电池优化白名单中
  Future<bool> isBatteryOptimizationIgnored() async {
    if (!Platform.isAndroid) return true;

    try {
      final bool result = await _androidChannel.invokeMethod('isBatteryOptimizationIgnored');
      return result;
    } catch (e) {
      debugPrint('Failed to check battery optimization status: $e');
      return false;
    }
  }

  /// 请求忽略电池优化
  Future<bool> requestIgnoreBatteryOptimization() async {
    if (!Platform.isAndroid) return true;

    try {
      final bool result = await _androidChannel.invokeMethod('requestIgnoreBatteryOptimization');
      return result;
    } catch (e) {
      debugPrint('Failed to request battery optimization exemption: $e');
      return false;
    }
  }

  /// 打开电池优化设置
  Future<bool> openBatteryOptimizationSettings() async {
    if (!Platform.isAndroid) return false;

    try {
      final bool result = await _androidChannel.invokeMethod('openBatteryOptimizationSettings');
      return result;
    } catch (e) {
      debugPrint('Failed to open battery optimization settings: $e');
      return false;
    }
  }

  /// 打开自启动设置
  Future<bool> openAutoStartSettings() async {
    if (!Platform.isAndroid) return false;

    try {
      final bool result = await _androidChannel.invokeMethod('openAutoStartSettings');
      return result;
    } catch (e) {
      debugPrint('Failed to open auto start settings: $e');
      return false;
    }
  }

  /// 获取服务地址
  Future<String> getServiceAddress() async {
    // === Android path (unchanged) ===
    if (Platform.isAndroid) {
      try {
        final String address = await _androidChannel.invokeMethod('getServiceAddress');
        return address;
      } catch (e) {
        debugPrint('Failed to get service address: $e');
        return '';
      }
    }

    // === iOS path: use Go lib to get IP ===
    if (Platform.isIOS) {
      try {
        // On iOS, we use NativeCommon to get device info, IP from Go
        return await NativeBridge.common.getDeviceCPUABI(); // fallback
      } catch (e) {
        debugPrint('Failed to get service address on iOS: $e');
        return '';
      }
    }

    return '';
  }

  /// 开始定期检查服务状态
  void _startStatusCheck() {
    _statusCheckTimer?.cancel();
    _statusCheckTimer = Timer.periodic(const Duration(seconds: 30), (timer) {
      checkServiceStatus();
    });
  }

  /// 停止状态检查
  void _stopStatusCheck() {
    _statusCheckTimer?.cancel();
    _statusCheckTimer = null;
  }

  /// 更新服务状态
  void _updateServiceStatus(bool isRunning) {
    if (_isServiceRunning != isRunning) {
      _isServiceRunning = isRunning;
      _serviceStatusController.add(isRunning);
      debugPrint('Service status changed: $isRunning');
    }
  }

  /// 释放资源
  void dispose() {
    _stopStatusCheck();
    _serviceStatusController.close();
  }
}