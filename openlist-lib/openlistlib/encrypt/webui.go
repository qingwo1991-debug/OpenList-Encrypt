package encrypt

import (
	"html/template"
	"strings"
)

// WebUI HTML 模板（嵌入式）
const webUIHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenList-Encrypt 管理后台</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 30px;
            margin-bottom: 20px;
        }
        
        .card-title {
            font-size: 1.3em;
            color: #333;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-title .icon {
            font-size: 1.5em;
        }
        
        .status-card {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .status-info {
            flex: 1;
        }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
        }
        
        .status-running {
            background: #d4edda;
            color: #155724;
        }
        
        .status-stopped {
            background: #f8d7da;
            color: #721c24;
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        .status-running .status-dot {
            background: #28a745;
        }
        
        .status-stopped .status-dot {
            background: #dc3545;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        
        .form-row {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        
        .form-row .form-group {
            flex: 1;
            min-width: 200px;
        }
        
        input, select {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1em;
            transition: border-color 0.3s, box-shadow 0.3s;
        }
        
        input:focus, select:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        }
        
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-success {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
        }
        
        .btn-danger {
            background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%);
            color: white;
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        
        .btn-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .path-list {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .path-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 15px 20px;
            border-bottom: 1px solid #e0e0e0;
            transition: background 0.2s;
        }
        
        .path-item:last-child {
            border-bottom: none;
        }
        
        .path-item:hover {
            background: #f8f9fa;
        }
        
        .path-info {
            flex: 1;
        }
        
        .path-name {
            font-weight: 600;
            color: #333;
            font-family: monospace;
            font-size: 1.1em;
        }
        
        .path-meta {
            font-size: 0.9em;
            color: #666;
            margin-top: 4px;
        }
        
        .path-actions {
            display: flex;
            gap: 8px;
        }
        
        .path-actions .btn {
            padding: 8px 16px;
            font-size: 0.9em;
        }
        
        .toggle-switch {
            position: relative;
            width: 50px;
            height: 26px;
        }
        
        .toggle-switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        
        .toggle-slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: 0.4s;
            border-radius: 26px;
        }
        
        .toggle-slider:before {
            position: absolute;
            content: "";
            height: 20px;
            width: 20px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: 0.4s;
            border-radius: 50%;
        }
        
        input:checked + .toggle-slider {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        input:checked + .toggle-slider:before {
            transform: translateX(24px);
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #888;
        }
        
        .empty-state .icon {
            font-size: 3em;
            margin-bottom: 10px;
        }
        
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        
        .modal-overlay.active {
            display: flex;
        }
        
        .modal {
            background: white;
            border-radius: 16px;
            padding: 30px;
            max-width: 500px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
        }
        
        .modal-title {
            font-size: 1.5em;
            margin-bottom: 20px;
            color: #333;
        }
        
        .modal-actions {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 20px;
        }
        
        .access-info {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
        }
        
        .access-info h4 {
            margin-bottom: 10px;
            color: #555;
        }
        
        .access-url {
            font-family: monospace;
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            padding: 8px 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .access-url code {
            color: #667eea;
            word-break: break-all;
        }
        
        .copy-btn {
            background: none;
            border: none;
            color: #667eea;
            cursor: pointer;
            padding: 4px 8px;
        }
        
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #333;
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            z-index: 2000;
            transform: translateY(100px);
            opacity: 0;
            transition: all 0.3s;
        }
        
        .toast.show {
            transform: translateY(0);
            opacity: 1;
        }
        
        .toast.success {
            background: #28a745;
        }
        
        .toast.error {
            background: #dc3545;
        }
        
        @media (max-width: 600px) {
            .header h1 {
                font-size: 1.8em;
            }
            
            .status-card {
                flex-direction: column;
                align-items: stretch;
            }
            
            .form-row {
                flex-direction: column;
            }
            
            .form-row .form-group {
                min-width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 OpenList-Encrypt</h1>
            <p>加密代理管理后台</p>
        </div>
        
        <!-- 状态卡片 -->
        <div class="card">
            <div class="status-card">
                <div class="status-info">
                    <h3 class="card-title"><span class="icon">📊</span> 服务状态</h3>
                    <div id="status-badge" class="status-badge status-running">
                        <div class="status-dot"></div>
                        <span id="status-text">运行中</span>
                    </div>
                </div>
                <div class="btn-group">
                    <button id="btn-restart" class="btn btn-secondary" onclick="restartProxy()">重启服务</button>
                </div>
            </div>
            
            <div class="access-info">
                <h4>访问地址</h4>
                <div class="access-url">
                    <code id="local-url">http://127.0.0.1:5344</code>
                    <button class="copy-btn" onclick="copyUrl('local-url')">📋 复制</button>
                </div>
                <div class="access-url">
                    <code id="external-url">http://{{.ExternalIP}}:5344</code>
                    <button class="copy-btn" onclick="copyUrl('external-url')">📋 复制</button>
                </div>
            </div>
        </div>
        
        <!-- Alist 服务器配置 -->
        <div class="card">
            <h3 class="card-title"><span class="icon">⚙️</span> Alist 服务器配置</h3>
            <form id="server-form" onsubmit="saveServerConfig(event)">
                <div class="form-row">
                    <div class="form-group">
                        <label>主机地址</label>
                        <input type="text" id="alist-host" value="{{.AlistHost}}" placeholder="127.0.0.1">
                    </div>
                    <div class="form-group">
                        <label>端口</label>
                        <input type="number" id="alist-port" value="{{.AlistPort}}" placeholder="5244">
                    </div>
                </div>
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <label class="toggle-switch">
                            <input type="checkbox" id="alist-https" {{if .AlistHttps}}checked{{end}}>
                            <span class="toggle-slider"></span>
                        </label>
                        使用 HTTPS
                    </label>
                </div>
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <label class="toggle-switch">
                            <input type="checkbox" id="probe-download">
                            <span class="toggle-slider"></span>
                        </label>
                        探测远程文件大小（提高解密兼容性）
                    </label>
                    <div style="margin-top:8px; color:#666; font-size:0.9em;">开启后会在下载时尝试 HEAD 或请求首字节以获取文件总大小，减少解密失败的概率，可能增加少量请求延迟。</div>
                </div>
                <div class="form-group">
                    <label style="font-weight: 700;">性能与稳定性</label>
                    <div style="margin-top:8px; display:flex; flex-direction:column; gap:12px;">
                        <label style="display: flex; align-items: center; gap: 10px;">
                            <label class="toggle-switch">
                                <input type="checkbox" id="enable-size-map">
                                <span class="toggle-slider"></span>
                            </label>
                            启用长期文件大小映射缓存
                        </label>
                        <div class="form-group" style="margin-bottom:0;">
                            <label>映射缓存 TTL（分钟）</label>
                            <input type="number" id="size-map-ttl" placeholder="1440">
                        </div>
                        <div style="color:#666; font-size:0.9em;">
                            视频播放策略已固定为高性能兼容模式：长期 Range 兼容缓存、并行解密、2MB 流缓冲与更积极的 WebDAV 回退已在后端启用。
                        </div>
                    </div>
                </div>
                <div class="btn-group">
                    <button type="submit" class="btn btn-primary">保存配置</button>
                </div>
            </form>
        </div>
        
        <!-- 加密路径配置 -->
        <div class="card">
            <h3 class="card-title">
                <span class="icon">📁</span> 加密路径配置
                <button class="btn btn-success" style="margin-left: auto;" onclick="showAddPathModal()">+ 添加路径</button>
            </h3>
            
            <div id="path-list" class="path-list">
                <!-- 动态生成 -->
            </div>
            
            <div id="empty-state" class="empty-state" style="display: none;">
                <div class="icon">📂</div>
                <p>暂无加密路径配置</p>
                <p style="margin-top: 10px;">
                    <button class="btn btn-success" onclick="showAddPathModal()">添加第一个路径</button>
                </p>
            </div>
        </div>
        
        <!-- 使用说明 -->
        <div class="card">
            <h3 class="card-title"><span class="icon">📖</span> 使用说明</h3>
            <ol style="line-height: 2; color: #555; padding-left: 20px;">
                <li>配置 Alist 服务器地址和端口</li>
                <li>添加需要加密的路径（支持通配符 *）</li>
                <li>通过代理地址访问 Alist，加密路径下的文件会自动加解密</li>
                <li>WebDAV 地址：<code style="background: #f0f0f0; padding: 2px 6px; border-radius: 4px;">http://设备IP:5344/dav/</code></li>
            </ol>
            <div style="margin-top: 15px; padding: 15px; background: #fff3cd; border-radius: 8px; color: #856404;">
                <strong>💡 提示：</strong>AES-CTR 算法性能最佳，推荐优先使用。
            </div>
        </div>
    </div>
    
    <!-- 添加/编辑路径模态框 -->
    <div id="path-modal" class="modal-overlay">
        <div class="modal">
            <h3 class="modal-title" id="modal-title">添加加密路径</h3>
            <form id="path-form" onsubmit="savePath(event)">
                <input type="hidden" id="path-index" value="-1">
                <div class="form-group">
                    <label>路径 <span style="color: #888; font-weight: normal;">（支持通配符 *）</span></label>
                    <input type="text" id="path-pattern" placeholder="/encrypt/*" required>
                </div>
                <div class="form-group">
                    <label>加密密码</label>
                    <input type="password" id="path-password" placeholder="请输入加密密码" required>
                </div>
                <div class="form-group">
                    <label>加密算法</label>
                    <select id="path-enctype">
                        <option value="aes-ctr">AES-CTR（推荐）</option>
                        <option value="rc4md5">RC4-MD5</option>
                        <option value="mix">Mix 混淆</option>
                    </select>
                </div>
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <label class="toggle-switch">
                            <input type="checkbox" id="path-encname">
                            <span class="toggle-slider"></span>
                        </label>
                        加密文件名
                    </label>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeModal()">取消</button>
                    <button type="submit" class="btn btn-primary">保存</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Toast 消息 -->
    <div id="toast" class="toast"></div>
    
    <script>
        // 配置数据
        let encryptPaths = [];
        
        // 初始化
        document.addEventListener('DOMContentLoaded', function() {
            loadConfig();
            checkStatus();
            setInterval(checkStatus, 10000); // 每10秒检查状态
        });
        
        // 加载配置
        async function loadConfig() {
                try {
                    const response = await fetch('/api/encrypt/config');
                    const data = await response.json();
                    if (data.code === 200) {
                        // 兼容后端返回的 passwdList 格式，转换为前端使用的 encryptPaths
                        if (data.data.passwdList) {
                            encryptPaths = [];
                            for (const item of data.data.passwdList) {
                                const encPaths = item.encPath || [];
                                let encType = item.encType || '';
                                if (encType === 'aesctr') encType = 'aes-ctr';
                                if (encType === 'rc4') encType = 'rc4md5';
                                for (const p of encPaths) {
                                    encryptPaths.push({ path: p, password: item.password, encType: encType || 'aes-ctr', encName: item.encName || false, encSuffix: item.encSuffix || '', enable: item.enable !== false });
                                }
                            }
                        } else {
                            encryptPaths = data.data.encryptPaths || [];
                        }
                        // 填充 Alist 配置
                        if (data.data.alistHost) document.getElementById('alist-host').value = data.data.alistHost;
                        if (data.data.alistPort) document.getElementById('alist-port').value = data.data.alistPort;
                        if (data.data.https !== undefined) document.getElementById('alist-https').checked = data.data.https;
                        if (data.data.probeOnDownload !== undefined) document.getElementById('probe-download').checked = data.data.probeOnDownload;
                        if (data.data.enableSizeMap !== undefined) document.getElementById('enable-size-map').checked = data.data.enableSizeMap;
                        if (data.data.sizeMapTtlMinutes !== undefined) document.getElementById('size-map-ttl').value = data.data.sizeMapTtlMinutes;
                        renderPaths();
                    }
                } catch (error) {
                    console.error('加载配置失败:', error);
                }
        }
        
        // 检查服务状态
        async function checkStatus() {
            try {
                const response = await fetch('/ping');
                const data = await response.json();
                updateStatus(data.status === 'ok');
            } catch (error) {
                updateStatus(false);
            }
        }
        
        // 更新状态显示
        function updateStatus(running) {
            const badge = document.getElementById('status-badge');
            const text = document.getElementById('status-text');
            
            if (running) {
                badge.className = 'status-badge status-running';
                text.textContent = '运行中';
            } else {
                badge.className = 'status-badge status-stopped';
                text.textContent = '已停止';
            }
        }
        
        // 保存服务器配置
        async function saveServerConfig(event) {
            event.preventDefault();
            
            const host = document.getElementById('alist-host').value;
            const port = parseInt(document.getElementById('alist-port').value);
            const https = document.getElementById('alist-https').checked;
            const probe = document.getElementById('probe-download').checked;
            const enableSizeMap = document.getElementById('enable-size-map').checked;
            const sizeMapTtlMinutes = parseInt(document.getElementById('size-map-ttl').value) || 0;

            try {
                const response = await fetch('/api/encrypt/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        alistHost: host,
                        alistPort: port,
                        alistHttps: https,
                        probeOnDownload: probe,
                        enableSizeMap: enableSizeMap,
                        sizeMapTtlMinutes: sizeMapTtlMinutes
                    })
                });

                const data = await response.json();
                if (data.code === 200) {
                    showToast('配置已保存', 'success');
                } else {
                    showToast('保存失败: ' + data.message, 'error');
                }
            } catch (error) {
                showToast('保存失败: ' + error.message, 'error');
            }
        }
        
        // 渲染路径列表
        function renderPaths() {
            const container = document.getElementById('path-list');
            const emptyState = document.getElementById('empty-state');
            
            if (encryptPaths.length === 0) {
                container.style.display = 'none';
                emptyState.style.display = 'block';
                return;
            }
            
            container.style.display = 'block';
            emptyState.style.display = 'none';
            
            container.innerHTML = encryptPaths.map((path, index) =>
                '<div class="path-item">' +
                    '<div class="path-info">' +
                        '<div class="path-name">' + escapeHtml(path.path) + '</div>' +
                        '<div class="path-meta">' +
                            path.encType.toUpperCase() + ' | ' +
                            (path.encName ? '加密文件名' : '不加密文件名') +
                        '</div>' +
                    '</div>' +
                    '<div class="path-actions">' +
                        '<label class="toggle-switch">' +
                            '<input type="checkbox" ' + (path.enable ? 'checked' : '') + ' onchange="togglePath(' + index + ', this.checked)">' +
                            '<span class="toggle-slider"></span>' +
                        '</label>' +
                        '<button class="btn btn-secondary" onclick="editPath(' + index + ')">编辑</button>' +
                        '<button class="btn btn-danger" onclick="deletePath(' + index + ')">删除</button>' +
                    '</div>' +
                '</div>'
            ).join('');
        }
        
        // 显示添加路径模态框
        function showAddPathModal() {
            document.getElementById('modal-title').textContent = '添加加密路径';
            document.getElementById('path-index').value = -1;
            document.getElementById('path-form').reset();
            document.getElementById('path-modal').classList.add('active');
        }
        
        // 编辑路径
        function editPath(index) {
            const path = encryptPaths[index];
            document.getElementById('modal-title').textContent = '编辑加密路径';
            document.getElementById('path-index').value = index;
            document.getElementById('path-pattern').value = path.path;
            document.getElementById('path-password').value = path.password || '';
            document.getElementById('path-enctype').value = path.encType;
            document.getElementById('path-encname').checked = path.encName;
            document.getElementById('path-modal').classList.add('active');
        }
        
        // 关闭模态框
        function closeModal() {
            document.getElementById('path-modal').classList.remove('active');
        }
        
        // 保存路径
        async function savePath(event) {
            event.preventDefault();
            
            const index = parseInt(document.getElementById('path-index').value);
                const pathData = {
                    path: document.getElementById('path-pattern').value,
                    password: document.getElementById('path-password').value,
                    encType: document.getElementById('path-enctype').value,
                    encName: document.getElementById('path-encname').checked,
                    encSuffix: index >= 0 && encryptPaths[index] ? (encryptPaths[index].encSuffix || '') : '',
                    enable: true
                };
            
            if (index >= 0) {
                encryptPaths[index] = pathData;
            } else {
                encryptPaths.push(pathData);
            }
            
            await savePathsToServer();
            renderPaths();
            closeModal();
            showToast('路径配置已保存', 'success');
        }
        
        // 切换路径启用状态
        async function togglePath(index, enable) {
            encryptPaths[index].enable = enable;
            await savePathsToServer();
            showToast(enable ? '已启用' : '已禁用', 'success');
        }
        
        // 删除路径
        async function deletePath(index) {
            if (confirm('确定要删除这个加密路径吗？')) {
                encryptPaths.splice(index, 1);
                await savePathsToServer();
                renderPaths();
                showToast('已删除', 'success');
            }
        }
        
        // 保存路径到服务器
        async function savePathsToServer() {
            try {
                await fetch('/api/encrypt/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ encryptPaths: encryptPaths })
                });
            } catch (error) {
                showToast('保存失败: ' + error.message, 'error');
            }
        }
        
        // 重启代理
        async function restartProxy() {
            try {
                const response = await fetch('/api/encrypt/restart', { method: 'POST' });
                const data = await response.json();
                showToast('服务正在重启...', 'success');
                setTimeout(checkStatus, 3000);
            } catch (error) {
                showToast('重启失败: ' + error.message, 'error');
            }
        }
        
        // 复制 URL
        function copyUrl(elementId) {
            const text = document.getElementById(elementId).textContent;
            navigator.clipboard.writeText(text).then(() => {
                showToast('已复制到剪贴板', 'success');
            });
        }
        
        // 显示 Toast 消息
        function showToast(message, type = '') {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = 'toast ' + type + ' show';
            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }
        
        // HTML 转义
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
`

// WebUIData 模板数据
type WebUIData struct {
	AlistHost  string
	AlistPort  int
	AlistHttps bool
	ExternalIP string
	ProxyPort  int
}

// GetExternalIP 获取外部 IP
func GetExternalIP() string {
	// 简单实现，实际应该获取真实的外网 IP
	return "设备IP"
}

// RenderWebUI 渲染 Web UI
func RenderWebUI(config *ProxyConfig) (string, error) {
	tmpl, err := template.New("webui").Parse(webUIHTML)
	if err != nil {
		return "", err
	}

	data := WebUIData{
		AlistHost:  config.AlistHost,
		AlistPort:  config.AlistPort,
		AlistHttps: config.AlistHttps,
		ExternalIP: GetExternalIP(),
		ProxyPort:  config.ProxyPort,
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}
