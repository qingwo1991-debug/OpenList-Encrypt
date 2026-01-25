# OpenEncrypt

<div align="center">
  <img src="assets/openlist.svg" height="100px" alt="OpenList Encrypt Logo">
  <h1>OpenEncrypt (原 OpenList-Encrypt)</h1>
  <p>OpenList 移动端 + 强大的透明加密代理</p>
</div>

## 项目简介

**OpenEncrypt** (App名称) 是基于 [OpenList-Mobile](https://github.com/OpenListTeam/OpenList-Mobile) 的增强版本，集成了 [alist-encrypt](https://github.com/traceless/alist-encrypt) 的加密核心逻辑，专为移动端隐私安全打造。

它不仅是一个文件服务器，更是一个强大的透明加密网关：

- ✅ **独立App**: 包名已更改为 `com.openlist.mobile.encrypt`，可与原版 OpenList 共存。
- ✅ **全能WebDAV**: 完美支持 WebDAV 协议，支持挂载到 Raidrive、Noklayer、Vidhub 等客户端。
- ✅ **智能加密/解密**:
  - **上传自动加密**: 通过 WebDAV 或网页上传到加密目录的文件会自动加密存储。
  - **下载自动解密**: 访问加密文件时自动解密，支持视频流的 Range 请求（在线播放无压力）。
  - **目录不加密**: 智能识别目录，保持目录名为明文，方便浏览；仅对文件进行加密混淆。
- ✅ **文件名混淆**: 支持文件名加密（MixBase64），并在 WebDAV 列表浏览时自动还原为明文显示。
- ✅ **多种算法**: 支持高效的 AES-CTR（推荐）和兼容性好的 RC4 算法。

## 功能特性

### 1. OpenList 服务器
- 内置完整的 OpenList 服务器
- 支持多种云盘挂载
- 提供 Web 界面访问
- 支持 WebDAV 协议

### 2. 加密代理
- **透明代理**: 无缝集成 Alist/OpenList 服务。
- **路径匹配**: 支持按路径通配符配置加密策略（如 `/encrypt/*`）。
- **文件名混淆**: 支持 `MixBase64` 文件名加密，保护隐私。目录名保持明文，避免混乱。
- **防二次加密**: 智能检测机制，防止对已经是密文的文件重复加密。
- **WebDAV 兼容**:
    - 针对 `PROPFIND` 进行了深度优化，解决目录浏览 404 问题。
    - 支持 `PUT` 上传时的 `Content-Length` 修正（支持 Chunked 传输）。
    - 自动处理 `COPY` 和 `MOVE` 操作的目标路径加密。

### 3. 在线播放
- **流式解密**: 基于 AES-CTR 流式解密，无需下载完整文件即可播放。
- **Range 支持**: 完美支持 HTTP Range 请求，拖动进度条秒加载。
- **格式支持**: 支持视频、图片、文档在线预览。

## 技术架构

```
┌─────────────────────────────────────────────────┐
│                Flutter UI 层                     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐ │
│  │ Web视图 │ │ OpenList│ │加密配置 │ │ 设置  │ │
│  └─────────┘ └─────────┘ └─────────┘ └────────┘ │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│               Go 后端层 (gomobile)              │
│  ┌─────────────────┐  ┌─────────────────────┐  │
│  │ OpenList 服务器 │  │    加密代理服务      │  │
│  │   (端口 5244)   │  │    (端口 5344)      │  │
│  └─────────────────┘  └─────────────────────┘  │
│                            │                    │
│  ┌─────────────────────────┴──────────────────┐│
│  │           加密模块 (encrypt/)              ││
│  │  ┌───────────┐  ┌───────────┐  ┌────────┐ ││
│  │  │ AES-CTR   │  │  RC4-MD5  │  │ 配置   │ ││
│  │  └───────────┘  └───────────┘  └────────┘ ││
│  └────────────────────────────────────────────┘│
└─────────────────────────────────────────────────┘
```

## 目录结构

```
OpenList-Encrypt/
├── lib/                          # Flutter UI 代码
│   ├── main.dart                 # 应用入口
│   ├── pages/
│   │   ├── encrypt/              # 加密配置页面
│   │   │   └── encrypt_config_page.dart
│   │   ├── openlist/             # OpenList 页面
│   │   ├── settings/             # 设置页面
│   │   └── web/                  # Web 视图页面
│   └── utils/                    # 工具类
├── openlist-lib/                 # Go 后端代码
│   ├── openlistlib/
│   │   ├── server.go            # OpenList 服务器
│   │   ├── encrypt_server.go    # 加密代理入口
│   │   └── encrypt/             # 加密模块
│   │       ├── crypto.go        # 加密算法实现
│   │       ├── proxy.go         # 代理服务器
│   │       └── config.go        # 配置管理
│   └── scripts/                 # 构建脚本
├── android/                     # Android 原生代码
└── ios/                         # iOS 原生代码
```

## 使用说明

### 1. 启动服务

1. 打开应用，OpenList 服务会自动启动
2. 进入"加密"页面配置加密代理
3. 设置 Alist 服务器地址（如果使用外部 Alist）
4. 添加加密路径配置
5. 启动加密代理服务

### 2. 配置加密路径

在"加密"页面添加加密路径：

- **路径**: 支持通配符，如 `/encrypt/*`、`/movies/*`
- **密码**: 加密密码
- **算法**: 推荐使用 AES-CTR
- **加密文件名**: 是否加密文件名

### 3. 访问加密内容

通过加密代理地址访问：
- 默认代理端口: 5344
- 访问地址: `http://设备IP:5344`
- 加密路径下的文件会自动加解密

### 4. WebDAV 使用

使用 WebDAV 客户端连接：
- 地址: `http://设备IP:5344/dav/`
- 用户名和密码: 与 Alist 相同
- 上传到加密路径会自动加密
- 下载加密文件会自动解密

## 加密算法说明

### AES-CTR（推荐）
- 基于 AES-256 的 CTR 模式
- 性能优秀，大部分现代 CPU 有硬件加速
- 安全性高，适合大文件

### RC4-MD5
- 基于 RC4 流密码
- 兼容性更好，适合老旧设备
- 性能适中

## 构建说明

### 环境要求

- Flutter 3.32.7+
- Go 1.21+
- Android SDK 34+
- gomobile

### 构建步骤

1. 初始化 gomobile:
```bash
cd openlist-lib/scripts
./init_gomobile.sh
```

2. 构建 Go 库:
```bash
./gobind.sh
```

3. 构建 Flutter 应用:
```bash
flutter pub get
flutter build apk
```

## 注意事项

1. **首次使用**: 建议先测试小文件，确认加密配置正确
2. **密码安全**: 请妥善保管加密密码，丢失无法恢复
3. **性能**: AES-CTR 在 ARM64 设备上性能最佳
4. **网络**: 代理服务需要与 Alist 在同一网络或可访问

## 相关项目

- [OpenList](https://github.com/OpenListTeam/OpenList) - OpenList 主项目
- [OpenList-Mobile](https://github.com/OpenListTeam/OpenList-Mobile) - OpenList 移动端
- [alist-encrypt](https://github.com/traceless/alist-encrypt) - Alist 加密代理

## 许可证

本项目采用 AGPL-3.0 许可证。

## 更新日志

### 2025-01-25
- **修复**: 将默认数据目录从外部存储 (`getExternalFilesDir`) 改为内部存储 (`getFilesDir`)，确保应用卸载时加密配置等数据会被自动清除
  - 之前：某些厂商 ROM（如 MIUI、EMUI）在卸载应用时不会清除外部存储中的数据
  - 现在：使用内部存储路径，卸载时数据始终会被清除
- **修复**: WebDAV 和下载请求在非 2xx 响应时跳过解密
  - 当后端返回错误响应（如 4xx、5xx）时，不再尝试解密错误内容
  - 解决联通云盘等某些存储返回错误时导致播放失败的问题
- **优化**: 对齐 alist-encrypt 的加密逻辑
  - 上传文件时自动加密文件名
  - WebDAV PUT 操作支持文件缓存
  - Content-Disposition 响应头中的文件名自动解密

## 致谢

- OpenList 团队
- alist-encrypt 作者
- Google Gemini & Google
- OpenList-Mobile 作者团队
- [Antigravity](https://github.com/Start-sys/Antigravity-Manager) & [Antigravity-Manager](https://github.com/lbjlaq/Antigravity-Manager)
- 所有贡献者
