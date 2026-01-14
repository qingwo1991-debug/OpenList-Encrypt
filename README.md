# OpenList-Encrypt

<div align="center">
  <img src="assets/openlist.svg" height="100px" alt="OpenList Encrypt Logo">
  <h1>OpenList-Encrypt</h1>
  <p>OpenList 移动端 + 加密代理功能</p>
</div>

## 项目简介

**OpenList-Encrypt** 是基于 [OpenList-Mobile](https://github.com/OpenListTeam/OpenList-Mobile) 和 [alist-encrypt](https://github.com/traceless/alist-encrypt) 的合并项目，在移动端实现了：

- ✅ 内置 OpenList 文件服务器
- ✅ 内置加密代理服务
- ✅ 支持 AES-CTR 和 RC4 加密算法
- ✅ 在线播放加密视频
- ✅ 查看加密图片和文件
- ✅ WebDAV 加密上传/下载
- ✅ 透明代理，自动加解密

## 功能特性

### 1. OpenList 服务器
- 内置完整的 OpenList 服务器
- 支持多种云盘挂载
- 提供 Web 界面访问
- 支持 WebDAV 协议

### 2. 加密代理
- 透明代理 Alist/OpenList 服务
- 支持按路径配置加密
- 支持 AES-CTR（推荐）和 RC4 算法
- 可选加密文件名
- 支持密码派生

### 3. 在线播放
- 支持在线播放加密视频
- 支持在线查看加密图片
- 支持在线预览加密文档
- 支持断点续传和范围请求

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

## 致谢

- OpenList 团队
- alist-encrypt 作者
- 所有贡献者
