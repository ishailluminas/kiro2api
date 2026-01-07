/**
 * UI UX Pro Max - Dashboard Controller
 * 中文版 - 极致毛玻璃交互体验
 */

// 认证管理器
class AuthManager {
    constructor() {
        this.tokenKey = 'dashboard_token';
        this.loginModal = document.getElementById('loginModal');
        this.loginForm = document.getElementById('loginForm');
        this.bindEvents();
    }

    bindEvents() {
        if (this.loginForm) {
            this.loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }
    }

    getToken() {
        return localStorage.getItem(this.tokenKey);
    }

    setToken(token) {
        localStorage.setItem(this.tokenKey, token);
    }

    clearToken() {
        localStorage.removeItem(this.tokenKey);
    }

    showLoginModal() {
        if (this.loginModal) {
            this.loginModal.classList.add('open');
            // 聚焦用户名输入框
            setTimeout(() => document.getElementById('loginUsername')?.focus(), 100);
        }
    }

    hideLoginModal() {
        if (this.loginModal) {
            this.loginModal.classList.remove('open');
            this.loginForm.reset();
        }
    }

    async handleLogin(e) {
        e.preventDefault();
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;
        const btn = this.loginForm.querySelector('button[type="submit"]');

        const originalText = btn.textContent;
        btn.textContent = '验证中...';
        btn.disabled = true;

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok && data.token) {
                this.setToken(data.token);
                this.hideLoginModal();
                document.body.classList.remove('auth-locked'); // 解锁界面
                tokenDashboard.showToast('登录成功，喵！', 'success');
                // 刷新当前页面数据
                tokenDashboard.refreshTokens();
                if (tokenDashboard.currentTab === 'auth-config') {
                    authConfigManager.loadConfigs();
                }
            } else {
                tokenDashboard.showToast(data.error || '登录失败', 'error');
            }
        } catch (error) {
            console.error('Login error:', error);
            tokenDashboard.showToast('登录请求失败', 'error');
        } finally {
            btn.textContent = originalText;
            btn.disabled = false;
        }
    }
}

// 全局认证Fetch包装器
async function authenticatedFetch(url, options = {}) {
    // 确保 headers 对象存在
    options.headers = options.headers || {};

    // 如果是普通对象，转换为 Headers 对象可能会更安全，但这里为了兼容简单对象写法，直接操作
    // 注意：fetch 的 headers 可以是 Headers 对象，也可以是普通对象
    // 这里统一处理为普通对象合并（如果传入的是 Headers 对象需要额外处理，但本项目中都是简单对象）

    const token = authManager.getToken();
    if (token) {
        // 判断 headers 是 Headers 实例还是普通对象
        if (options.headers instanceof Headers) {
            options.headers.append('Authorization', `Bearer ${token}`);
        } else {
            options.headers['Authorization'] = `Bearer ${token}`;
        }
    }

    try {
        const response = await fetch(url, options);

        if (response.status === 401) {
            authManager.clearToken();
            authManager.showLoginModal();
            // 抛出特定的认证错误，中断后续处理
            throw new Error('Unauthorized');
        }

        return response;
    } catch (error) {
        // 如果是 401 引起的错误，已经在上面处理了（弹窗）
        // 这里继续抛出，让调用者知道请求失败了
        throw error;
    }
}

class TokenDashboard {
    constructor() {
        this.apiBaseUrl = '/api';
        this.currentTab = 'tokens';
        this.autoRefreshInterval = null;
        this.isAutoRefreshEnabled = false;

        // 初始化
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.refreshTokens();

        // 入场动画
        document.querySelector('.container').style.opacity = '1';
    }

    setupEventListeners() {
        // Tab 切换
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e.target));
        });

        // Token 刷新
        const refreshBtn = document.getElementById('refreshTokensBtn');
        if (refreshBtn) refreshBtn.addEventListener('click', () => {
            this.animateButton(refreshBtn);
            this.refreshTokens();
        });

        // 自动刷新开关
        const autoSwitch = document.getElementById('autoRefreshSwitch');
        if (autoSwitch) autoSwitch.addEventListener('click', () => this.toggleAutoRefresh());
    }

    animateButton(btn) {
        btn.style.transform = 'scale(0.95)';
        setTimeout(() => btn.style.transform = 'scale(1)', 150);
    }

    switchTab(targetBtn) {
        const tabName = targetBtn.dataset.tab;

        // 更新按钮状态
        document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
        targetBtn.classList.add('active');

        // 更新内容区域 (带淡入动画)
        document.querySelectorAll('.tab-content').forEach(content => {
            if (content.id === `${tabName}-tab`) {
                content.style.display = 'block';
                // 强制重绘以触发动画
                void content.offsetWidth;
                content.classList.add('fade-enter');
            } else {
                content.style.display = 'none';
                content.classList.remove('fade-enter');
            }
        });

        this.currentTab = tabName;
        if (tabName === 'tokens') this.refreshTokens();
        else if (tabName === 'auth-config') authConfigManager.loadConfigs();
    }

    async refreshTokens() {
        const tbody = document.getElementById('tokenTableBody');
        if (!tbody) return;

        // 柔和的加载状态
        if (!tbody.querySelector('.spinner')) {
            tbody.style.opacity = '0.5';
            tbody.style.transition = 'opacity 0.3s';
        }

        try {
            const response = await authenticatedFetch(`${this.apiBaseUrl}/tokens`);
            if (!response.ok) throw new Error('网络响应异常');

            const data = await response.json();

            this.renderTokenTable(data.tokens || []);
            this.updateStatusBar(data);
            this.updateLastUpdate();

        } catch (error) {
            console.error('Fetch error:', error);
            this.showToast('Token 刷新失败', 'error');
        } finally {
            tbody.style.opacity = '1';
        }
    }

    renderTokenTable(tokens) {
        const tbody = document.getElementById('tokenTableBody');
        if (!tokens.length) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 40px; color: var(--text-muted);">暂无 Token 数据</td></tr>`;
            return;
        }

        tbody.innerHTML = tokens.map(token => `
            <tr>
                <td>${token.user_email || '未知用户'}</td>
                <td><span class="code-pill">${token.token_preview || 'N/A'}</span></td>
                <td>${token.auth_type || 'Social'}</td>
                <td style="font-family: var(--font-mono);">${token.remaining_usage || 0}</td>
                <td>${this.formatDate(token.expires_at)}</td>
                <td>${this.formatDate(token.last_used)}</td>
                <td>${this.getStatusBadge(token)}</td>
            </tr>
        `).join('');
    }

    getStatusBadge(token) {
        const now = new Date();
        const expiry = new Date(token.expires_at);
        const remaining = token.remaining_usage || 0;

        let status = '正常';
        let cls = 'badge-active';

        if (expiry < now) { status = '已过期'; cls = 'badge-expired'; }
        else if (remaining === 0) { status = '已耗尽'; cls = 'badge-expired'; }
        else if (remaining <= 5) { status = '余额不足'; cls = 'badge-warning'; }

        return `<span class="badge ${cls}"><span class="badge-dot"></span>${status}</span>`;
    }

    updateStatusBar(data) {
        this.animateValue('totalTokens', data.total_tokens || 0);
        this.animateValue('activeTokens', data.active_tokens || 0);
    }

    animateValue(id, value) {
        const el = document.getElementById(id);
        if (!el) return;
        // 简单的数字跳动效果可以后续增强
        el.textContent = value;
    }

    updateLastUpdate() {
        const el = document.getElementById('lastUpdate');
        if (el) el.textContent = new Date().toLocaleTimeString('zh-CN');
    }

    formatDate(dateStr) {
        if (!dateStr) return '-';
        return new Date(dateStr).toLocaleString('zh-CN', {
            month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
        });
    }

    toggleAutoRefresh() {
        const switchEl = document.getElementById('autoRefreshSwitch');
        this.isAutoRefreshEnabled = !this.isAutoRefreshEnabled;

        switchEl.classList.toggle('active', this.isAutoRefreshEnabled);

        if (this.isAutoRefreshEnabled) {
            this.autoRefreshInterval = setInterval(() => this.refreshTokens(), 30000);
            this.showToast('自动刷新已开启', 'success');
        } else {
            clearInterval(this.autoRefreshInterval);
            this.showToast('自动刷新已关闭', 'warning');
        }
    }

    showToast(msg, type = 'success') {
        const container = document.querySelector('.toast-container');
        const toast = document.createElement('div');
        const icon = type === 'success' ? '✅' : (type === 'error' ? '❌' : '⚠️');

        toast.className = `toast toast-${type}`;
        toast.innerHTML = `<span class="toast-icon">${icon}</span> ${msg}`;

        container.appendChild(toast);

        // 3秒后自动消失
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 400);
        }, 3000);
    }
}

class AuthConfigManager {
    constructor() {
        this.apiBaseUrl = '/api/auth-config';
        this.configs = [];
        this.parsedAccounts = [];
        this.init();
    }

    init() {
        this.bindEvents();
    }

    bindEvents() {
        // 模态框绑定
        this.bindModal('showAddFormBtn', 'addAuthForm', 'closeAddFormBtn', 'cancelAddBtn');
        this.bindModal('showImportFormBtn', 'importAccountsForm', 'closeImportFormBtn', null); // 移除取消按钮绑定，使用关闭按钮

        // 操作按钮
        document.getElementById('reloadConfigBtn')?.addEventListener('click', () => this.reloadConfigs());
        document.getElementById('submitAddBtn')?.addEventListener('click', () => this.addConfig());
        document.getElementById('parseJsonBtn')?.addEventListener('click', () => this.parseSmartJson());

        // 导入逻辑
        document.querySelectorAll('.import-method-tabs .btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchImportTab(e.target));
        });

        document.getElementById('parseAccountsBtn')?.addEventListener('click', () => this.parseImportAccounts());
        document.getElementById('submitImportBtn')?.addEventListener('click', () => this.submitImport());

        // 动态显示 IdC 字段
        document.getElementById('authTypeSelect')?.addEventListener('change', (e) => {
            const idcFields = document.querySelector('.idc-fields');
            if (idcFields) idcFields.style.display = e.target.value === 'IdC' ? 'block' : 'none';
        });

        // 导入界面的全选/反选
        document.getElementById('selectAllBtn')?.addEventListener('click', () => this.toggleAllPreviews(true));
        document.getElementById('invertSelectBtn')?.addEventListener('click', () => this.invertPreviews());
        document.getElementById('selectValidBtn')?.addEventListener('click', () => this.selectValidPreviews());

        // 文件上传交互
        const fileArea = document.getElementById('fileUploadArea');
        const fileInput = document.getElementById('accountFileInput');
        if (fileArea && fileInput) {
            fileArea.addEventListener('click', () => fileInput.click());
            fileInput.addEventListener('change', (e) => this.handleFileSelect(e));

            // 移除文件
            document.getElementById('removeFileBtn')?.addEventListener('click', (e) => {
                e.stopPropagation();
                fileInput.value = '';
                document.getElementById('fileInfo').style.display = 'none';
                this.parsedAccounts = [];
            });
        }
    }

    handleFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            document.getElementById('fileName').textContent = file.name;
            document.getElementById('fileInfo').style.display = 'flex';
        }
    }

    bindModal(openBtnId, modalId, closeBtnId, cancelBtnId) {
        const modal = document.getElementById(modalId);
        const openBtn = document.getElementById(openBtnId);
        const closeBtn = document.getElementById(closeBtnId);
        const cancelBtn = document.getElementById(cancelBtnId);

        if (openBtn && modal) {
            openBtn.addEventListener('click', () => {
                modal.classList.add('open');
            });
        }

        const close = () => {
            if (modal) modal.classList.remove('open');
        };

        if (closeBtn) closeBtn.addEventListener('click', close);
        if (cancelBtn) cancelBtn.addEventListener('click', close);

        // 点击背景关闭
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) close();
            });
        }
    }

    async loadConfigs() {
        const tbody = document.getElementById('authConfigTableBody');
        if (!tbody) return;

        try {
            const response = await authenticatedFetch(this.apiBaseUrl);
            const data = await response.json();

            this.configs = data.configs || [];
            this.renderConfigTable();

            document.getElementById('configPath').textContent = data.configPath || 'auth_config.json';
            document.getElementById('configCount').textContent = data.total || 0;

        } catch (error) {
            console.error('Load config error:', error);
            tokenDashboard.showToast('加载配置失败', 'error');
        }
    }

    renderConfigTable() {
        const tbody = document.getElementById('authConfigTableBody');
        if (this.configs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 40px; color: var(--text-muted);">暂无配置，请添加</td></tr>`;
            return;
        }

        tbody.innerHTML = this.configs.map((config, index) => {
            const statusClass = config.disabled ? 'badge-expired' : (config.exhausted ? 'badge-expired' : 'badge-active');
            const statusText = config.disabled ? '已禁用' : (config.exhausted ? '已耗尽' : '启用中');

            return `
                <tr>
                    <td>${index + 1}</td>
                    <td>${config.auth || 'Social'}</td>
                    <td><span class="code-pill">${config.refreshTokenPreview || '***'}</span></td>
                    <td><span class="code-pill">${config.clientIdPreview || '-'}</span></td>
                    <td><span class="badge ${statusClass}"><span class="badge-dot"></span>${statusText}</span></td>
                    <td>
                        <div style="display: flex; gap: 8px;">
                            <button class="btn btn-glass" style="padding: 4px 12px; font-size: 0.8rem;" onclick="authConfigManager.toggleConfig(${index}, ${!config.disabled})">
                                ${config.disabled ? '启用' : '禁用'}
                            </button>
                            <button class="btn btn-danger" style="padding: 4px 12px; font-size: 0.8rem;" onclick="authConfigManager.deleteConfig(${index})">
                                删除
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    }

    async toggleConfig(index, disabled) {
        try {
            await authenticatedFetch(`${this.apiBaseUrl}/toggle`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ index, disabled })
            });
            tokenDashboard.showToast(`配置已${disabled ? '禁用' : '启用'}`, 'success');
            this.loadConfigs();
        } catch (e) {
            tokenDashboard.showToast('操作失败', 'error');
        }
    }

    async deleteConfig(index) {
        if (!confirm('确定要删除此配置吗？此操作不可恢复。')) return;
        try {
            await authenticatedFetch(`${this.apiBaseUrl}/delete`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ index })
            });
            tokenDashboard.showToast('配置已删除', 'success');
            this.loadConfigs();
        } catch (e) {
            tokenDashboard.showToast('删除失败', 'error');
        }
    }

    async reloadConfigs() {
        try {
            await authenticatedFetch(`${this.apiBaseUrl}/reload`, { method: 'POST' });
            tokenDashboard.showToast('配置已从磁盘重载', 'success');
            this.loadConfigs();
        } catch (e) {
            tokenDashboard.showToast('重载失败', 'error');
        }
    }

    async parseSmartJson() {
        const clientJson = document.getElementById('clientJsonInput').value;
        const tokenJson = document.getElementById('tokenJsonInput').value;

        try {
            const response = await authenticatedFetch(`${this.apiBaseUrl}/parse`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ clientJson, tokenJson })
            });
            const data = await response.json();

            if (data.success) {
                const conf = data.config;
                if (conf.auth) document.getElementById('authTypeSelect').value = conf.auth;
                if (conf.refreshToken) document.getElementById('refreshTokenInput').value = conf.refreshToken;
                if (conf.clientId) document.getElementById('clientIdInput').value = conf.clientId;
                if (conf.clientSecret) document.getElementById('clientSecretInput').value = conf.clientSecret;

                // 触发 change 事件以显示/隐藏字段
                document.getElementById('authTypeSelect').dispatchEvent(new Event('change'));

                tokenDashboard.showToast('JSON 解析成功', 'success');
            } else {
                tokenDashboard.showToast('解析失败: ' + (data.errors?.[0] || '未知错误'), 'error');
            }
        } catch (e) {
            tokenDashboard.showToast('解析请求错误', 'error');
        }
    }

    async addConfig() {
        const auth = document.getElementById('authTypeSelect').value;
        const refreshToken = document.getElementById('refreshTokenInput').value;
        const clientId = document.getElementById('clientIdInput').value;
        const clientSecret = document.getElementById('clientSecretInput').value;

        if (!refreshToken) return tokenDashboard.showToast('Refresh Token 不能为空', 'error');
        if (auth === 'IdC' && (!clientId || !clientSecret)) return tokenDashboard.showToast('IdC 模式需填写 Client ID 和 Secret', 'error');

        try {
            const res = await authenticatedFetch(`${this.apiBaseUrl}/add`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ auth, refreshToken, clientId, clientSecret })
            });
            const data = await res.json();

            if (data.success) {
                tokenDashboard.showToast('配置添加成功', 'success');
                document.getElementById('addAuthForm').classList.remove('open');
                this.loadConfigs();
                // 清空输入
                document.querySelectorAll('#addAuthForm input, #addAuthForm textarea').forEach(i => i.value = '');
            } else {
                tokenDashboard.showToast(data.error || '添加失败', 'error');
            }
        } catch (e) {
            tokenDashboard.showToast('请求失败', 'error');
        }
    }

    // --- 导入逻辑 ---

    switchImportTab(btn) {
        document.querySelectorAll('.import-method-tabs .btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const method = btn.dataset.method;
        document.getElementById('fileUploadMethod').style.display = method === 'file' ? 'block' : 'none';
        document.getElementById('pasteJsonMethod').style.display = method === 'paste' ? 'block' : 'none';
    }

    async parseImportAccounts() {
        let jsonStr = '';
        if (document.querySelector('.import-method-tabs .btn.active').dataset.method === 'paste') {
            jsonStr = document.getElementById('accountJsonInput').value;
        } else {
             const fileInput = document.getElementById('accountFileInput');
             if (fileInput.files.length) {
                 jsonStr = await fileInput.files[0].text();
             }
        }

        try {
            const accounts = JSON.parse(jsonStr);
            if (!Array.isArray(accounts)) throw new Error('格式错误，应为 JSON 数组');

            this.parsedAccounts = accounts.map(a => ({...a, _selected: true, _status: this.validateAccount(a)}));
            this.renderPreviewTable();
            document.getElementById('previewSection').style.display = 'block';
            document.getElementById('submitImportBtn').disabled = false;
        } catch (e) {
            tokenDashboard.showToast('JSON 格式无效', 'error');
        }
    }

    validateAccount(acc) {
        if (!acc.refreshToken) return '缺少 Token';
        return '有效';
    }

    renderPreviewTable() {
        const tbody = document.getElementById('previewTableBody');
        tbody.innerHTML = this.parsedAccounts.map((acc, i) => `
            <tr>
                <td><input type="checkbox" class="preview-cb" data-idx="${i}" ${acc._selected ? 'checked' : ''}></td>
                <td>${acc.email || 'N/A'}</td>
                <td>${acc.clientId ? 'IdC' : 'Social'}</td>
                <td><span class="code-pill">${(acc.refreshToken || '').substring(0, 8)}...</span></td>
                <td>${acc.expiresAt || '-'}</td>
                <td><span class="badge ${acc._status === '有效' ? 'badge-active' : 'badge-expired'}"><span class="badge-dot"></span>${acc._status}</span></td>
            </tr>
        `).join('');

        this.updatePreviewStats();

        tbody.querySelectorAll('.preview-cb').forEach(cb => {
            cb.addEventListener('change', (e) => {
                this.parsedAccounts[e.target.dataset.idx]._selected = e.target.checked;
                this.updatePreviewStats();
            });
        });
    }

    updatePreviewStats() {
        const total = this.parsedAccounts.length;
        const selected = this.parsedAccounts.filter(a => a._selected).length;
        const valid = this.parsedAccounts.filter(a => a._status === '有效').length;

        document.getElementById('previewTotal').textContent = total;
        document.getElementById('previewSelected').textContent = selected;
        document.getElementById('previewValid').textContent = valid;
        document.getElementById('previewInvalid').textContent = total - valid;
        document.getElementById('submitImportBtn').disabled = selected === 0;
    }

    toggleAllPreviews(state) {
        this.parsedAccounts.forEach(a => a._selected = state);
        this.renderPreviewTable();
    }

    invertPreviews() {
        this.parsedAccounts.forEach(a => a._selected = !a._selected);
        this.renderPreviewTable();
    }

    selectValidPreviews() {
        this.parsedAccounts.forEach(a => a._selected = (a._status === '有效'));
        this.renderPreviewTable();
    }

    async submitImport() {
        const selected = this.parsedAccounts.filter(a => a._selected);
        try {
             await authenticatedFetch(`${this.apiBaseUrl}/import`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ accounts: selected, mode: 'skip' })
            });
            tokenDashboard.showToast(`成功导入 ${selected.length} 个账户`, 'success');
            document.getElementById('importAccountsForm').classList.remove('open');
            this.loadConfigs();
        } catch (e) {
            tokenDashboard.showToast('导入失败', 'error');
        }
    }
}

// 全局实例
let tokenDashboard;
let authConfigManager;
// 认证管理器实例（确保全局可用）
const authManager = new AuthManager();

document.addEventListener('DOMContentLoaded', () => {
    // 初始化时检查登录状态
    if (!authManager.getToken()) {
        document.body.classList.add('auth-locked');
        authManager.showLoginModal();
    } else {
        document.body.classList.remove('auth-locked');
    }

    tokenDashboard = new TokenDashboard();
    authConfigManager = new AuthConfigManager();
});
