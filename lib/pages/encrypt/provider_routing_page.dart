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

  bool _loading = true;
  bool _saving = false;
  bool _enableLocalBypass = true;
  bool _enableRouting = true;
  List<String> _providerCandidates = [];
  List<String> _driverCandidates = [];
  List<_RoutingRule> _rules = [];

  String get _baseUrl => 'http://127.0.0.1:${widget.proxyPort}';

  @override
  void initState() {
    super.initState();
    _loadAll();
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
    final root = resp.data is Map<String, dynamic> ? resp.data as Map<String, dynamic> : const <String, dynamic>{};
    final data = root['data'] as Map<String, dynamic>?;
    final config = data?['config'] as Map<String, dynamic>?;
    if (config == null) return;
    final rawRules = (config['providerRoutingRules'] as List<dynamic>? ?? []);
    final rules = rawRules.whereType<Map>().map((item) {
      final m = item.map((k, v) => MapEntry(k.toString(), v));
      return _RoutingRule(
        id: (m['id'] ?? '').toString(),
        matchType: (m['matchType'] ?? 'provider').toString(),
        matchValue: (m['matchValue'] ?? '').toString(),
        action: (m['action'] ?? 'direct').toString(),
        enabled: m['enabled'] is bool ? m['enabled'] as bool : true,
        priority: int.tryParse((m['priority'] ?? 100).toString()) ?? 100,
      );
    }).toList();
    setState(() {
      _enableLocalBypass = config['enableLocalBypass'] is bool ? config['enableLocalBypass'] as bool : true;
      _enableRouting = (config['routingMode'] ?? 'by_provider').toString() != 'off';
      _rules = rules;
    });
  }

  Future<void> _loadCandidates() async {
    final resp = await _dio.get('$_baseUrl/api/encrypt/provider-routing-candidates');
    final root = resp.data is Map<String, dynamic> ? resp.data as Map<String, dynamic> : const <String, dynamic>{};
    final data = root['data'] as Map<String, dynamic>?;
    final providers = (data?['providers'] as List<dynamic>? ?? []).map((e) => e.toString()).toList();
    final drivers = (data?['drivers'] as List<dynamic>? ?? []).map((e) => e.toString()).toList();
    setState(() {
      _providerCandidates = providers;
      _driverCandidates = drivers;
    });
  }

  Future<void> _save() async {
    setState(() => _saving = true);
    try {
      await _dio.post(
        '$_baseUrl/api/encrypt/v2/config',
        data: {
          'version': 2,
          'config': {
            'enableLocalBypass': _enableLocalBypass,
            'routingMode': _enableRouting ? 'by_provider' : 'off',
            'providerRuleSource': 'builtin+custom',
            'providerRoutingRules': _rules.map((e) => e.toJson()).toList(),
          }
        },
        options: Options(contentType: 'application/json'),
      );
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('网盘分流规则已保存')));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('保存失败: $e')));
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
        matchValue: '',
        action: 'direct',
        enabled: true,
        priority: _rules.length + 1,
      ));
    });
  }

  Widget _buildRuleCard(int index) {
    final rule = _rules[index];
    final candidates = rule.matchType == 'driver' ? _driverCandidates : _providerCandidates;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          children: [
            Row(
              children: [
                Expanded(
                  child: DropdownButtonFormField<String>(
                    value: rule.matchType,
                    decoration: const InputDecoration(labelText: '匹配类型'),
                    items: const [
                      DropdownMenuItem(value: 'provider', child: Text('provider')),
                      DropdownMenuItem(value: 'driver', child: Text('driver')),
                    ],
                    onChanged: (v) {
                      if (v == null) return;
                      setState(() => rule.matchType = v);
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
              decoration: InputDecoration(
                labelText: '匹配值',
                hintText: candidates.isNotEmpty ? '例如: ${candidates.first}' : '例如: onedrive / aliyundriveopen',
              ),
              onChanged: (v) => rule.matchValue = v.trim().toLowerCase(),
            ),
            if (candidates.isNotEmpty) ...[
              const SizedBox(height: 8),
              Wrap(
                spacing: 6,
                runSpacing: 6,
                children: candidates.take(20).map((c) {
                  return ActionChip(
                    label: Text(c),
                    onPressed: () => setState(() => rule.matchValue = c),
                  );
                }).toList(),
              ),
            ],
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: TextFormField(
                    initialValue: rule.priority.toString(),
                    decoration: const InputDecoration(labelText: '优先级（数值越小越先匹配）'),
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
          IconButton(onPressed: _loadAll, icon: const Icon(Icons.refresh), tooltip: '刷新'),
          IconButton(onPressed: _saving ? null : _save, icon: const Icon(Icons.save), tooltip: '保存'),
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
                      '说明: 规则按优先级从小到大匹配；provider 取自 /api/fs/get 返回；driver 来自上游 storage 列表映射。未命中规则时走内置分组，再回退到系统代理策略。',
                    ),
                  ),
                ),
                const SizedBox(height: 8),
                if (_rules.isEmpty)
                  const Card(
                    child: Padding(
                      padding: EdgeInsets.all(12),
                      child: Text('暂无规则，可点击右下角 + 添加。'),
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
      'matchType': matchType,
      'matchValue': matchValue,
      'action': action,
      'enabled': enabled,
      'priority': priority,
    };
  }
}
