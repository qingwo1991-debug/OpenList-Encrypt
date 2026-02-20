import 'package:dio/dio.dart';
import 'package:flutter/material.dart';

class ProviderRoutingPage extends StatefulWidget {
  const ProviderRoutingPage({super.key, required this.proxyPort});

  final int proxyPort;

  @override
  State<ProviderRoutingPage> createState() => _ProviderRoutingPageState();
}

class _ProviderRoutingPageState extends State<ProviderRoutingPage> {
  final Dio _dio = Dio(BaseOptions(
    connectTimeout: const Duration(seconds: 3),
    receiveTimeout: const Duration(seconds: 5),
    sendTimeout: const Duration(seconds: 5),
  ));

  static const Map<String, String> _providerZhMap = {
    'aliyundriveopen': '阿里云盘',
    'baidunetdisk': '百度网盘',
    'baiduphoto': '百度相册',
    'cloud189': '天翼云盘',
    'cloud189pc': '天翼云盘PC',
    'open123': '123网盘',
    'pan115': '115网盘',
    'quarkoruc': '夸克/UC网盘',
    'weiyun': '微云',
    'wps': 'WPS网盘',
    'onedrive': 'OneDrive',
    'onedriveapp': 'OneDrive App',
    'googlephoto': 'Google Photos',
    'mega': 'MEGA',
    'mediafire': 'MediaFire',
    'protondrive': 'Proton Drive',
    'dropbox': 'Dropbox',
    'github': 'GitHub',
  };

  bool _loading = true;
  bool _saving = false;
  bool _enableLocalBypass = true;
  bool _enableRouting = true;
  List<String> _providerCandidates = [];
  List<_RoutingRule> _rules = [];

  String get _baseUrl => 'http://127.0.0.1:${widget.proxyPort}';

  @override
  void initState() {
    super.initState();
    _loadAll();
  }

  String _providerLabel(String raw) {
    final key = raw.trim().toLowerCase();
    final zh = _providerZhMap[key];
    if (zh == null || zh.isEmpty) {
      return raw;
    }
    return '$raw ($zh)';
  }

  Future<void> _loadAll() async {
    setState(() => _loading = true);
    try {
      await Future.wait([_loadConfig(), _loadCandidates()]);
    } catch (_) {
      // keep page usable with partial data
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _loadConfig() async {
    final resp = await _dio.get('$_baseUrl/api/encrypt/v2/config');
    final root = resp.data is Map<String, dynamic>
        ? resp.data as Map<String, dynamic>
        : const <String, dynamic>{};
    final data = root['data'] as Map<String, dynamic>?;
    final config = data?['config'] as Map<String, dynamic>?;
    if (config == null) return;
    final rawRules = (config['providerRoutingRules'] as List<dynamic>? ?? []);
    final rules = rawRules.whereType<Map>().map((item) {
      final m = item.map((k, v) => MapEntry(k.toString(), v));
      return _RoutingRule(
        id: (m['id'] ?? '').toString(),
        // UI 仅保留 provider 规则，driver 规则自动收敛。
        matchType: 'provider',
        matchValue: (m['matchValue'] ?? '').toString().trim().toLowerCase(),
        action: (m['action'] ?? 'direct').toString(),
        enabled: m['enabled'] is bool ? m['enabled'] as bool : true,
        priority: int.tryParse((m['priority'] ?? 100).toString()) ?? 100,
      );
    }).toList();
    setState(() {
      _enableLocalBypass = config['enableLocalBypass'] is bool
          ? config['enableLocalBypass'] as bool
          : true;
      _enableRouting = (config['routingMode'] ?? 'by_provider').toString() != 'off';
      _rules = rules;
    });
  }

  Future<void> _loadCandidates() async {
    final resp = await _dio.get('$_baseUrl/api/encrypt/provider-routing-candidates');
    final root = resp.data is Map<String, dynamic>
        ? resp.data as Map<String, dynamic>
        : const <String, dynamic>{};
    final data = root['data'] as Map<String, dynamic>?;
    final providers = (data?['providers'] as List<dynamic>? ?? [])
        .map((e) => e.toString().trim().toLowerCase())
        .where((e) => e.isNotEmpty)
        .toSet()
        .toList()
      ..sort();
    setState(() {
      _providerCandidates = providers;
    });
  }

  Future<void> _save() async {
    setState(() => _saving = true);
    try {
      final filteredRules = _rules
          .where((e) => e.matchValue.trim().isNotEmpty)
          .map((e) => e.toJson())
          .toList();
      await _dio.post(
        '$_baseUrl/api/encrypt/v2/config',
        data: {
          'version': 2,
          'config': {
            'enableLocalBypass': _enableLocalBypass,
            'routingMode': _enableRouting ? 'by_provider' : 'off',
            'providerRuleSource': 'builtin+custom',
            'providerRoutingRules': filteredRules,
          }
        },
        options: Options(contentType: 'application/json'),
      );
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: Text('网盘分流规则已保存')));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('保存失败: $e')));
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  void _addRule() {
    setState(() {
      _rules.add(_RoutingRule(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        matchType: 'provider',
        matchValue: _providerCandidates.isNotEmpty ? _providerCandidates.first : '',
        action: 'direct',
        enabled: true,
        priority: _rules.length + 1,
      ));
    });
  }

  List<String> _candidateWithCurrent(String current) {
    final list = <String>[];
    list.addAll(_providerCandidates);
    final c = current.trim().toLowerCase();
    if (c.isNotEmpty && !list.contains(c)) {
      list.insert(0, c);
    }
    return list;
  }

  Widget _buildProviderItem(String value) {
    final label = _providerLabel(value);
    return Tooltip(
      message: label,
      child: Text(
        label,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
    );
  }

  Widget _buildRuleCard(int index) {
    final rule = _rules[index];
    final candidates = _candidateWithCurrent(rule.matchValue);
    final dropdownValue = rule.matchValue.isEmpty
        ? (candidates.isNotEmpty ? candidates.first : null)
        : rule.matchValue;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          children: [
            Row(
              children: [
                Expanded(
                  child: DropdownButtonFormField<String>(
                    value: dropdownValue,
                    isExpanded: true,
                    decoration: const InputDecoration(
                      labelText: 'Provider（可选）',
                      hintText: '选择网盘 Provider',
                    ),
                    items: candidates
                        .map(
                          (c) => DropdownMenuItem<String>(
                            value: c,
                            child: _buildProviderItem(c),
                          ),
                        )
                        .toList(),
                    onChanged: (v) {
                      if (v == null) return;
                      setState(() => rule.matchValue = v.trim().toLowerCase());
                    },
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: DropdownButtonFormField<String>(
                    value: rule.action,
                    decoration: const InputDecoration(labelText: '动作'),
                    items: const [
                      DropdownMenuItem(value: 'direct', child: Text('直连')),
                      DropdownMenuItem(value: 'proxy', child: Text('代理')),
                    ],
                    onChanged: (v) {
                      if (v == null) return;
                      setState(() => rule.action = v);
                    },
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            TextFormField(
              initialValue: rule.matchValue,
              decoration: const InputDecoration(
                labelText: '自定义 Provider（可选）',
                hintText: '下拉没有时可手动输入',
              ),
              onChanged: (v) => rule.matchValue = v.trim().toLowerCase(),
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: TextFormField(
                    initialValue: rule.priority.toString(),
                    decoration: const InputDecoration(labelText: '优先级（数字越小越先匹配）'),
                    keyboardType: TextInputType.number,
                    onChanged: (v) => rule.priority = int.tryParse(v) ?? 100,
                  ),
                ),
                const SizedBox(width: 8),
                Switch(
                  value: rule.enabled,
                  onChanged: (v) => setState(() => rule.enabled = v),
                ),
                IconButton(
                  icon: const Icon(Icons.delete_outline),
                  tooltip: '删除规则',
                  onPressed: () => setState(() => _rules.removeAt(index)),
                ),
              ],
            )
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('网盘分流规则'),
        actions: [
          IconButton(
            onPressed: _loadAll,
            icon: const Icon(Icons.refresh),
            tooltip: '刷新',
          ),
          IconButton(
            onPressed: _saving ? null : _save,
            icon: const Icon(Icons.save),
            tooltip: '保存',
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _addRule,
        child: const Icon(Icons.add),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                SwitchListTile(
                  title: const Text('启用按网盘分流'),
                  subtitle: const Text('关闭后按原网络行为处理（仅私网直连 + 系统代理）'),
                  value: _enableRouting,
                  onChanged: (v) => setState(() => _enableRouting = v),
                ),
                SwitchListTile(
                  title: const Text('本地/私网直连'),
                  subtitle: const Text('仅对 localhost/私网地址生效'),
                  value: _enableLocalBypass,
                  onChanged: (v) => setState(() => _enableLocalBypass = v),
                ),
                const Card(
                  child: Padding(
                    padding: EdgeInsets.all(12),
                    child: Text(
                      '说明: 规则按优先级从小到大匹配；当前页面仅使用 provider 规则。未命中规则时走内置分组，再回退系统代理策略。',
                    ),
                  ),
                ),
                const SizedBox(height: 8),
                if (_rules.isEmpty)
                  const Card(
                    child: Padding(
                      padding: EdgeInsets.all(12),
                      child: Text('暂无规则，可点击右下角 + 添加。每条规则都支持删除。'),
                    ),
                  ),
                ...List.generate(_rules.length, _buildRuleCard),
              ],
            ),
    );
  }
}

class _RoutingRule {
  _RoutingRule({
    required this.id,
    required this.matchType,
    required this.matchValue,
    required this.action,
    required this.enabled,
    required this.priority,
  });

  String id;
  String matchType;
  String matchValue;
  String action;
  bool enabled;
  int priority;

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'matchType': 'provider',
      'matchValue': matchValue.trim().toLowerCase(),
      'action': action,
      'enabled': enabled,
      'priority': priority,
    };
  }
}
