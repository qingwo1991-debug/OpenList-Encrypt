# OpenList-Encrypt 构建指南

本文档详细说明如何从源码构建 OpenList-Encrypt 项目。

## 环境要求

### 必需工具

| 工具 | 版本 | 说明 |
|------|------|------|
| Flutter | 3.32.7+ | UI 框架 |
| Dart | 3.2.4+ | Flutter 附带 |
| Go | 1.21+ | 后端语言 |
| Android SDK | 34+ | Android 开发 |
| Android NDK | r25+ | 原生编译 |
| gomobile | 最新 | Go 移动端绑定 |

### 可选工具

| 工具 | 用途 |
|------|------|
| Android Studio | IDE 和 SDK 管理 |
| VS Code | 代码编辑 |
| Xcode | iOS 开发（macOS） |

## 环境配置

### 1. 安装 Flutter

```bash
# 下载 Flutter SDK
git clone https://github.com/flutter/flutter.git -b stable
export PATH="$PATH:`pwd`/flutter/bin"

# 验证安装
flutter doctor
```

### 2. 安装 Go

```bash
# macOS (Homebrew)
brew install go

# Ubuntu/Debian
sudo apt install golang-go

# Windows (Scoop)
scoop install go

# 验证安装
go version
```

### 3. 配置 Android SDK

```bash
# 设置环境变量
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools

# 安装必要组件（通过 Android Studio 或命令行）
sdkmanager "platforms;android-34"
sdkmanager "build-tools;34.0.0"
sdkmanager "ndk;25.2.9519653"
```

### 4. 安装 gomobile

```bash
# 安装 gomobile
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest

# 初始化 gomobile
gomobile init

# 验证安装
gomobile version
```

## 构建步骤

### 第一步：克隆项目

```bash
git clone https://github.com/your-repo/OpenList-Encrypt.git
cd OpenList-Encrypt
```

### 第二步：初始化 Go 依赖

```bash
cd openlist-lib
go mod tidy

# 如果需要初始化 OpenList 依赖
./scripts/init_openlist.sh
```

### 第三步：构建 Go 绑定库

```bash
# 进入脚本目录
cd openlist-lib/scripts

# 初始化 gomobile（首次构建）
./init_gomobile.sh

# 构建 Android 绑定
./gobind.sh

# 或者手动构建
cd ..
gomobile bind -target=android -androidapi=21 \
    -o ../android/app/libs/openlistlib.aar \
    ./openlistlib
```

### 第四步：获取 Flutter 依赖

```bash
cd ../..  # 回到项目根目录
flutter pub get
```

### 第五步：构建 APK

```bash
# Debug 版本
flutter build apk --debug

# Release 版本
flutter build apk --release

# 分架构构建（更小的包）
flutter build apk --split-per-abi
```

构建产物位置：`build/app/outputs/flutter-apk/`

### 第六步：构建 App Bundle（可选）

```bash
flutter build appbundle
```

## 测试（可选）

部分测试依赖 SQLite CGO 或 aria2 RPC 服务。若当前环境不需要这些依赖，可跳过对应包：

```bash
cd openlist-lib
go test $(go list ./... | grep -v '/internal/op$' | grep -v '/pkg/aria2/rpc$')
```

## iOS 构建（macOS 环境）

### 1. 安装依赖

```bash
cd ios
pod install
```

### 2. 构建 iOS 绑定

```bash
cd ../openlist-lib/scripts
./gobind_ios.sh
```

### 3. 构建 IPA

```bash
cd ../..
flutter build ios
```

## 常见问题

### Q: gomobile bind 失败

**错误**: `cannot find package`

**解决**: 
```bash
go mod tidy
go get -u ./...
```

### Q: Android NDK 版本不匹配

**错误**: `NDK not found`

**解决**:
```bash
# 检查已安装的 NDK
ls $ANDROID_HOME/ndk/

# 设置 NDK 路径
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/25.2.9519653
```

### Q: Flutter 构建缓慢

**解决**:
```bash
# 清理缓存
flutter clean

# 预下载依赖
flutter pub get --offline
```

### Q: Go 版本太低

**错误**: `go: go.mod requires go >= 1.21`

**解决**: 升级 Go 版本
```bash
# macOS
brew upgrade go

# 或下载最新版本
# https://go.dev/dl/
```

## 调试技巧

### 查看 Go 库日志

```dart
// 在 Flutter 中监听日志
NativeBridge.log.onLog((level, time, message) {
  print('[$level] $message');
});
```

### 检查服务状态

```dart
// 检查 OpenList 服务
final running = await NativeBridge.service.isRunning();
print('OpenList running: $running');

// 检查加密代理
final proxyRunning = await EncryptProxy.isRunning();
print('Encrypt proxy running: $proxyRunning');
```

### 查看构建日志

```bash
# 详细构建日志
flutter build apk --verbose

# Go 构建日志
gomobile bind -v -target=android ./openlistlib
```

## 发布准备

### 1. 更新版本号

编辑 `pubspec.yaml`:
```yaml
version: 1.0.0+1  # 格式: major.minor.patch+buildNumber
```

### 2. 签名配置

创建 `android/key.properties`:
```properties
storePassword=your_store_password
keyPassword=your_key_password
keyAlias=your_key_alias
storeFile=/path/to/keystore.jks
```

编辑 `android/app/build.gradle`:
```gradle
def keystoreProperties = new Properties()
def keystorePropertiesFile = rootProject.file('key.properties')
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(new FileInputStream(keystorePropertiesFile))
}

android {
    signingConfigs {
        release {
            keyAlias keystoreProperties['keyAlias']
            keyPassword keystoreProperties['keyPassword']
            storeFile file(keystoreProperties['storeFile'])
            storePassword keystoreProperties['storePassword']
        }
    }
    buildTypes {
        release {
            signingConfig signingConfigs.release
        }
    }
}
```

### 3. 混淆配置

编辑 `android/app/proguard-rules.pro`:
```proguard
# Go 绑定
-keep class go.** { *; }
-keep class openlistlib.** { *; }

# Flutter
-keep class io.flutter.** { *; }
```

### 4. 构建发布版

```bash
flutter build apk --release
```

## 持续集成

### GitHub Actions 示例

```yaml
name: Build APK

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      
      - name: Setup Java
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '17'
      
      - name: Setup Flutter
        uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.32.7'
      
      - name: Setup Android SDK
        uses: android-actions/setup-android@v3
      
      - name: Install gomobile
        run: |
          go install golang.org/x/mobile/cmd/gomobile@latest
          go install golang.org/x/mobile/cmd/gobind@latest
          gomobile init
      
      - name: Build Go bindings
        run: |
          cd openlist-lib
          go mod tidy
          gomobile bind -target=android -androidapi=21 \
              -o ../android/app/libs/openlistlib.aar \
              ./openlistlib
      
      - name: Build APK
        run: |
          flutter pub get
          flutter build apk --release
      
      - name: Upload APK
        uses: actions/upload-artifact@v4
        with:
          name: app-release
          path: build/app/outputs/flutter-apk/app-release.apk
```

## 联系方式

如有问题，请通过以下方式联系：

- GitHub Issues
- 讨论群组

祝构建顺利！