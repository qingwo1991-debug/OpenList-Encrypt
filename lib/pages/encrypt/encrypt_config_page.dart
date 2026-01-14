import 'package:flutter/material.dart';
import 'package:get/get.dart';
import '../../generated/l10n.dart';
import '../../contant/native_bridge.dart';

/// 加密配置页面
class EncryptConfigPage extends StatefulWidget {
  const EncryptConfigPage({super.key});

  @override
  State<EncryptConfigPage> createState() => _EncryptConfigPageState();
}

class _EncryptConfigPageState extends State<EncryptConfigPage> {
  final _formKey = GlobalKey<FormState>();
  
  // Alist 服务器配置
  final _alistHostController = TextEditingController(text: '127.0.0.1');
  final _alistPortController = TextEditingController(text: '5244');
  bool _alistHttps = false;
  
  // 代理端口
  final _proxyPortController = TextEditingController(text: '5344');
  
  // 加密路径列表
  List<EncryptPathConfig> _encryptPaths = [];
  
  bool _isLoading = true;
  bool _proxyRunning = false;

  @override
  void initState() {
    super.initState();
    _loadConfig();
    _checkProxyStatus();
  }

  Future<void> _loadConfig() async {
    setState(() => _isLoading = true);
    try {
      // TODO: 从原生端加载配置
      // final config = await NativeBridge.encrypt.getConfig();
      // 暂时使用默认值
      setState(() {
        _encryptPaths = [
          EncryptPathConfig(
            path: '/encrypt/*',
            password: '',
            encType: 'aes-ctr',
            encName: false,
            enable: true,
          ),
        ];
      });
    } catch (e) {
      debugPrint('Failed to load encrypt config: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _checkProxyStatus() async {
    try {
      // TODO: 检查代理状态
      // final running = await NativeBridge.encrypt.isProxyRunning();
      setState(() => _proxyRunning = false);
    } catch (e) {
      debugPrint('Failed to check proxy status: $e');
    }
  }

  Future<void> _saveConfig() async {
    if (!_formKey.currentState!.validate()) return;
    
    try {
      // TODO: 保存配置到原生端
      // await NativeBridge.encrypt.setAlistHost(
      //   _alistHostController.text,
      //   int.parse(_alistPortController.text),
      //   _alistHttps,
      // );
      // await NativeBridge.encrypt.setProxyPort(
      //   int.parse(_proxyPortController.text),
      // );
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(S.current.saved)),
      );
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('保存失败: $e')),
      );
    }
  }

  Future<void> _toggleProxy() async {
    try {
      if (_proxyRunning) {
        // TODO: 停止代理
        // await NativeBridge.encrypt.stopProxy();
      } else {
        // TODO: 启动代理
        // await NativeBridge.encrypt.startProxy();
      }
      setState(() => _proxyRunning = !_proxyRunning);
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('操作失败: $e')),
      );
    }
  }

  void _showAddPathDialog() {
    final pathController = TextEditingController();
    final passwordController = TextEditingController();
    String encType = 'aes-ctr';
    bool encName = false;
    
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('添加加密路径'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: pathController,
                decoration: const InputDecoration(
                  labelText: '路径',
                  hintText: '例: /encrypt/* 或 /movies/*',
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: passwordController,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: '密码',
                ),
              ),
              const SizedBox(height: 16),
              StatefulBuilder(
                builder: (context, setDialogState) => Column(
                  children: [
                    DropdownButtonFormField<String>(
                      value: encType,
                      decoration: const InputDecoration(
                        labelText: '加密算法',
                      ),
                      items: const [
                        DropdownMenuItem(value: 'aes-ctr', child: Text('AES-CTR (推荐)')),
                        DropdownMenuItem(value: 'rc4md5', child: Text('RC4-MD5')),
                      ],
                      onChanged: (value) {
                        setDialogState(() => encType = value!);
                      },
                    ),
                    const SizedBox(height: 16),
                    SwitchListTile(
                      title: const Text('加密文件名'),
                      value: encName,
                      onChanged: (value) {
                        setDialogState(() => encName = value);
                      },
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(S.current.cancel),
          ),
          FilledButton(
            onPressed: () {
              if (pathController.text.isEmpty || passwordController.text.isEmpty) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('请填写完整')),
                );
                return;
              }
              setState(() {
                _encryptPaths.add(EncryptPathConfig(
                  path: pathController.text,
                  password: passwordController.text,
                  encType: encType,
                  encName: encName,
                  enable: true,
                ));
              });
              Navigator.pop(context);
            },
            child: Text(S.current.confirm),
          ),
        ],
      ),
    );
  }

  void _editPath(int index) {
    final config = _encryptPaths[index];
    final pathController = TextEditingController(text: config.path);
    final passwordController = TextEditingController(text: config.password);
    String encType = config.encType;
    bool encName = config.encName;
    bool enable = config.enable;
    
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('编辑加密路径'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: pathController,
                decoration: const InputDecoration(
                  labelText: '路径',
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: passwordController,
                obscureText: true,
                decoration: const InputDecoration(
                  labelText: '密码',
                ),
              ),
              const SizedBox(height: 16),
              StatefulBuilder(
                builder: (context, setDialogState) => Column(
                  children: [
                    DropdownButtonFormField<String>(
                      value: encType,
                      decoration: const InputDecoration(
                        labelText: '加密算法',
                      ),
                      items: const [
                        DropdownMenuItem(value: 'aes-ctr', child: Text('AES-CTR (推荐)')),
                        DropdownMenuItem(value: 'rc4md5', child: Text('RC4-MD5')),
                      ],
                      onChanged: (value) {
                        setDialogState(() => encType = value!);
                      },
                    ),
                    const SizedBox(height: 16),
                    SwitchListTile(
                      title: const Text('加密文件名'),
                      value: encName,
                      onChanged: (value) {
                        setDialogState(() => encName = value);
                      },
                    ),
                    SwitchListTile(
                      title: const Text('启用'),
                      value: enable,
                      onChanged: (value) {
                        setDialogState(() => enable = value);
                      },
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () {
              setState(() => _encryptPaths.removeAt(index));
              Navigator.pop(context);
            },
            style: TextButton.styleFrom(foregroundColor: Colors.red),
            child: const Text('删除'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(S.current.cancel),
          ),
          FilledButton(
            onPressed: () {
              setState(() {
                _encryptPaths[index] = EncryptPathConfig(
                  path: pathController.text,
                  password: passwordController.text,
                  encType: encType,
                  encName: encName,
                  enable: enable,
                );
              });
              Navigator.pop(context);
            },
            child: Text(S.current.confirm),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _alistHostController.dispose();
    _alistPortController.dispose();
    _proxyPortController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('加密代理配置'),
        actions: [
          IconButton(
            icon: const Icon(Icons.save),
            onPressed: _saveConfig,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // 代理状态卡片
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(16),
                        child: Row(
                          children: [
                            Icon(
                              _proxyRunning ? Icons.check_circle : Icons.cancel,
                              color: _proxyRunning ? Colors.green : Colors.grey,
                              size: 48,
                            ),
                            const SizedBox(width: 16),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    _proxyRunning ? '代理运行中' : '代理已停止',
                                    style: Theme.of(context).textTheme.titleLarge,
                                  ),
                                  if (_proxyRunning)
                                    Text(
                                      '访问地址: http://127.0.0.1:${_proxyPortController.text}',
                                      style: Theme.of(context).textTheme.bodySmall,
                                    ),
                                ],
                              ),
                            ),
                            FilledButton.tonal(
                              onPressed: _toggleProxy,
                              child: Text(_proxyRunning ? '停止' : '启动'),
                            ),
                          ],
                        ),
                      ),
                    ),
                    
                    const SizedBox(height: 24),
                    
                    // Alist 服务器配置
                    Text(
                      'Alist 服务器',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        Expanded(
                          flex: 3,
                          child: TextFormField(
                            controller: _alistHostController,
                            decoration: const InputDecoration(
                              labelText: '主机地址',
                              hintText: '127.0.0.1',
                            ),
                            validator: (value) {
                              if (value == null || value.isEmpty) {
                                return '请输入主机地址';
                              }
                              return null;
                            },
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          flex: 1,
                          child: TextFormField(
                            controller: _alistPortController,
                            decoration: const InputDecoration(
                              labelText: '端口',
                            ),
                            keyboardType: TextInputType.number,
                            validator: (value) {
                              if (value == null || value.isEmpty) {
                                return '请输入端口';
                              }
                              final port = int.tryParse(value);
                              if (port == null || port < 1 || port > 65535) {
                                return '端口无效';
                              }
                              return null;
                            },
                          ),
                        ),
                      ],
                    ),
                    SwitchListTile(
                      title: const Text('使用 HTTPS'),
                      value: _alistHttps,
                      onChanged: (value) => setState(() => _alistHttps = value),
                    ),
                    
                    const SizedBox(height: 24),
                    
                    // 代理端口配置
                    Text(
                      '代理端口',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    TextFormField(
                      controller: _proxyPortController,
                      decoration: const InputDecoration(
                        labelText: '代理端口',
                        hintText: '5344',
                      ),
                      keyboardType: TextInputType.number,
                      validator: (value) {
                        if (value == null || value.isEmpty) {
                          return '请输入代理端口';
                        }
                        final port = int.tryParse(value);
                        if (port == null || port < 1 || port > 65535) {
                          return '端口无效';
                        }
                        return null;
                      },
                    ),
                    
                    const SizedBox(height: 24),
                    
                    // 加密路径配置
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          '加密路径',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        IconButton(
                          icon: const Icon(Icons.add),
                          onPressed: _showAddPathDialog,
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    if (_encryptPaths.isEmpty)
                      Card(
                        child: Padding(
                          padding: const EdgeInsets.all(24),
                          child: Center(
                            child: Column(
                              children: [
                                Icon(
                                  Icons.folder_off,
                                  size: 48,
                                  color: Theme.of(context).hintColor,
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  '暂无加密路径',
                                  style: TextStyle(
                                    color: Theme.of(context).hintColor,
                                  ),
                                ),
                                const SizedBox(height: 8),
                                TextButton.icon(
                                  onPressed: _showAddPathDialog,
                                  icon: const Icon(Icons.add),
                                  label: const Text('添加'),
                                ),
                              ],
                            ),
                          ),
                        ),
                      )
                    else
                      ListView.builder(
                        shrinkWrap: true,
                        physics: const NeverScrollableScrollPhysics(),
                        itemCount: _encryptPaths.length,
                        itemBuilder: (context, index) {
                          final config = _encryptPaths[index];
                          return Card(
                            child: ListTile(
                              leading: Icon(
                                config.enable
                                    ? Icons.lock
                                    : Icons.lock_open,
                                color: config.enable
                                    ? Colors.green
                                    : Colors.grey,
                              ),
                              title: Text(config.path),
                              subtitle: Text(
                                '${config.encType.toUpperCase()} | '
                                '${config.encName ? "加密文件名" : "不加密文件名"}',
                              ),
                              trailing: Switch(
                                value: config.enable,
                                onChanged: (value) {
                                  setState(() {
                                    _encryptPaths[index] = EncryptPathConfig(
                                      path: config.path,
                                      password: config.password,
                                      encType: config.encType,
                                      encName: config.encName,
                                      enable: value,
                                    );
                                  });
                                },
                              ),
                              onTap: () => _editPath(index),
                            ),
                          );
                        },
                      ),
                    
                    const SizedBox(height: 24),
                    
                    // 使用说明
                    ExpansionTile(
                      title: const Text('使用说明'),
                      children: [
                        Padding(
                          padding: const EdgeInsets.all(16),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: const [
                              Text('1. 配置 Alist 服务器地址和端口'),
                              SizedBox(height: 8),
                              Text('2. 添加需要加密的路径，支持通配符 *'),
                              SizedBox(height: 8),
                              Text('3. 设置每个路径的加密密码'),
                              SizedBox(height: 8),
                              Text('4. 启动代理服务'),
                              SizedBox(height: 8),
                              Text('5. 通过代理地址访问 Alist，加密路径下的文件会自动加解密'),
                              SizedBox(height: 16),
                              Text(
                                '提示：AES-CTR 算法性能更好，推荐使用',
                                style: TextStyle(color: Colors.grey),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
    );
  }
}

/// 加密路径配置
class EncryptPathConfig {
  final String path;
  final String password;
  final String encType;
  final bool encName;
  final bool enable;

  EncryptPathConfig({
    required this.path,
    required this.password,
    required this.encType,
    required this.encName,
    required this.enable,
  });
}