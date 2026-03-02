// ============================================
// S.O.W.A Security - DNS Protection Dashboard
// Main Application JavaScript v2
// With Authentication Flow
// ============================================

const API_BASE = '';
let statsRefreshInterval = null;
let queriesChart = null;
let queryTypesChart = null;
let authToken = localStorage.getItem('sowa_token') || '';

// ==================== Auth ====================

// Server info cache
let serverInfo = null;

async function checkAuth() {
    try {
        const resp = await apiFetch('/api/auth/status');
        if (!resp.ok) throw new Error('Auth check failed');
        const data = await resp.json();

        if (!data.configured) {
            // First time setup - show wizard
            showLoginScreen('setup');
            return;
        }

        if (!data.authenticated) {
            // Show login form
            showLoginScreen('login');
            return;
        }

        // Authenticated - show app
        showApp();
    } catch (e) {
        // If auth endpoint doesn't exist yet (no auth configured), show app
        console.warn('Auth check:', e.message);
        showApp();
    }
}

function showLoginScreen(mode) {
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('appContainer').style.display = 'none';

    if (mode === 'setup') {
        document.getElementById('setupWizard').style.display = 'block';
        document.getElementById('loginForm').style.display = 'none';
        wizardNext(1);
        loadServerInfo();
    } else {
        document.getElementById('setupWizard').style.display = 'none';
        document.getElementById('loginForm').style.display = 'block';
    }
}

function showApp() {
    document.getElementById('loginScreen').style.display = 'none';
    document.getElementById('appContainer').style.display = 'flex';
    initApp();
}

// ==================== Setup Wizard ====================

let currentWizardStep = 1;

function wizardNext(step) {
    currentWizardStep = step;

    // Update progress indicators
    document.querySelectorAll('.wizard-step').forEach(el => {
        const s = parseInt(el.dataset.step);
        el.classList.remove('active', 'done');
        if (s < step) el.classList.add('done');
        if (s === step) el.classList.add('active');
    });

    // Show active panel
    document.querySelectorAll('.wizard-panel').forEach(p => p.classList.remove('active'));
    const panel = document.getElementById(`wizardStep${step}`);
    if (panel) panel.classList.add('active');
}

async function loadServerInfo() {
    try {
        const resp = await fetch(`${API_BASE}/api/system/info`);
        if (resp.ok) {
            serverInfo = await resp.json();
            const ip = serverInfo.ips?.[0] || '127.0.0.1';
            const dnsPort = serverInfo.dns_port || 53;
            const webPort = serverInfo.web_port || 8080;
            const webURL = `http://${ip}:${webPort}`;

            // Wizard info
            const wizardIP = document.getElementById('wizardServerIP');
            const wizardPort = document.getElementById('wizardDNSPort');
            const wizardWeb = document.getElementById('wizardWebURL');
            if (wizardIP) wizardIP.textContent = ip;
            if (wizardPort) wizardPort.textContent = dnsPort;
            if (wizardWeb) wizardWeb.textContent = webURL;

            // Guide DNS codes in wizard
            ['guideDNS1', 'guideDNS2', 'guideDNS3', 'guideDNS4'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.textContent = ip;
            });
        }
    } catch (e) {
        console.warn('Failed to load server info:', e);
    }
}

// Setup tabs in wizard
document.addEventListener('click', (e) => {
    const tab = e.target.closest('.setup-tab');
    if (!tab) return;
    const target = tab.dataset.target;

    tab.closest('.setup-tabs').querySelectorAll('.setup-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');

    const wizard = tab.closest('.wizard-card') || tab.closest('.wizard-panel');
    if (wizard) {
        wizard.querySelectorAll('.setup-guide').forEach(g => g.classList.remove('active'));
        const guide = document.getElementById(target);
        if (guide) guide.classList.add('active');
    }
});

// Password strength indicator
document.addEventListener('input', (e) => {
    if (e.target.id === 'setupPassword') {
        const val = e.target.value;
        const bar = document.getElementById('passwordStrength');
        if (!bar) return;
        let strength = 0;
        if (val.length >= 4) strength += 25;
        if (val.length >= 8) strength += 25;
        if (/[A-Z]/.test(val) && /[a-z]/.test(val)) strength += 25;
        if (/[0-9!@#$%^&*]/.test(val)) strength += 25;
        const colors = { 25: '#ff4466', 50: '#ffaa00', 75: '#00aaff', 100: '#00ff88' };
        bar.style.setProperty('--strength', strength + '%');
        bar.style.setProperty('--strength-color', colors[strength] || '#ff4466');
    }
});

function initLoginForms() {
    // Setup form (wizard step 2)
    document.getElementById('setupForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = document.getElementById('setupPassword').value;
        const confirm = document.getElementById('setupPasswordConfirm').value;
        const errEl = document.getElementById('setupError');

        if (password.length < 4) {
            if (errEl) { errEl.textContent = 'Password must be at least 4 characters'; errEl.style.display = 'block'; errEl.classList.add('visible'); }
            return;
        }
        if (password !== confirm) {
            if (errEl) { errEl.textContent = 'Passwords do not match'; errEl.style.display = 'block'; errEl.classList.add('visible'); }
            return;
        }

        try {
            const resp = await fetch(`${API_BASE}/api/auth/setup`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: document.getElementById('setupUsername').value || 'admin',
                    password: password
                })
            });

            if (resp.ok) {
                // Now auto-login
                const loginResp = await fetch(`${API_BASE}/api/auth/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: document.getElementById('setupUsername').value || 'admin',
                        password: password
                    })
                });
                if (loginResp.ok) {
                    const data = await loginResp.json();
                    if (data.token) {
                        authToken = data.token;
                        localStorage.setItem('sowa_token', authToken);
                    }
                }
                // Move to DNS setup step
                wizardNext(3);
            } else {
                const err = await resp.json().catch(() => ({}));
                if (errEl) { errEl.textContent = err.error || 'Setup failed'; errEl.style.display = 'block'; errEl.classList.add('visible'); }
            }
        } catch (e) {
            if (errEl) { errEl.textContent = 'Connection error'; errEl.style.display = 'block'; errEl.classList.add('visible'); }
        }
    });

    // Wizard finish → open dashboard
    document.getElementById('wizardFinish')?.addEventListener('click', () => {
        showApp();
    });

    // Login form (returning users)
    document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;

        try {
            const resp = await fetch(`${API_BASE}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (resp.ok) {
                const data = await resp.json();
                if (data.token) {
                    authToken = data.token;
                    localStorage.setItem('sowa_token', authToken);
                }
                hideLoginError();
                showApp();
            } else {
                showLoginError('Invalid username or password');
            }
        } catch (e) {
            showLoginError('Connection error');
        }
    });
}

function showLoginError(msg) {
    const el = document.getElementById('loginError');
    if (el) {
        el.textContent = msg;
        el.classList.add('visible');
        el.style.display = 'block';
    }
}

function hideLoginError() {
    const el = document.getElementById('loginError');
    if (el) {
        el.classList.remove('visible');
        el.style.display = 'none';
    }
}

async function logout() {
    try {
        await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch (e) { /* ignore */ }
    authToken = '';
    localStorage.removeItem('sowa_token');
    showLoginScreen('login');
    if (statsRefreshInterval) {
        clearInterval(statsRefreshInterval);
        statsRefreshInterval = null;
    }
}

// Wrapper for authenticated API calls
async function apiFetch(url, options = {}) {
    if (!options.headers) options.headers = {};
    if (authToken) {
        options.headers['Authorization'] = `Bearer ${authToken}`;
    }
    const resp = await fetch(`${API_BASE}${url}`, options);
    if (resp.status === 401) {
        // Token expired or invalid
        authToken = '';
        localStorage.removeItem('sowa_token');
        showLoginScreen('login');
        throw new Error('Unauthorized');
    }
    return resp;
}

// ==================== Init ====================

document.addEventListener('DOMContentLoaded', () => {
    initLoginForms();
    checkAuth();
});

let appInitialized = false;

function initApp() {
    if (appInitialized) {
        loadDashboard();
        return;
    }
    appInitialized = true;
    initNavigation();
    initForms();
    loadDashboard();
    startAutoRefresh();
    loadConfig();
}

// ==================== Navigation ====================

function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const menuToggle = document.getElementById('menuToggle');
    const sidebar = document.getElementById('sidebar');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            const page = item.dataset.page;

            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            const pageEl = document.getElementById(`page-${page}`);
            if (pageEl) pageEl.classList.add('active');

            document.getElementById('pageTitle').textContent = item.querySelector('span').textContent;
            sidebar.classList.remove('open');
            loadPageData(page);
        });
    });

    menuToggle?.addEventListener('click', () => {
        sidebar.classList.toggle('open');
    });

    // Logout
    document.getElementById('logoutBtn')?.addEventListener('click', (e) => {
        e.preventDefault();
        logout();
    });

    // Quick domain test
    document.getElementById('quickTestBtn')?.addEventListener('click', () => {
        const domain = document.getElementById('quickTestDomain')?.value?.trim();
        if (domain) testDomain(domain);
    });

    document.getElementById('quickTestDomain')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const domain = e.target.value.trim();
            if (domain) testDomain(domain);
        }
    });
}

function loadPageData(page) {
    switch (page) {
        case 'dashboard': loadDashboard(); break;
        case 'blocklists': loadBlocklists(); break;
        case 'querylog': loadQueryLog(); break;
        case 'clients': loadClients(); break;
        case 'dhcp': loadDHCPLeases(); break;
        case 'safesearch': loadSafeSearch(); break;
        case 'dns': loadDNSSettings(); break;
        case 'settings': loadGeneralSettings(); break;
        case 'access': loadAccessSettings(); break;
        case 'encryption': loadEncryptionSettings(); break;
        case 'filters': loadCustomRules(); break;
        case 'guide': loadSetupGuide(); break;
    }
}

// ==================== Setup Guide Page ====================

async function loadSetupGuide() {
    try {
        const resp = await apiFetch('/api/system/info');
        if (!resp.ok) return;
        const data = await resp.json();
        serverInfo = data;

        const ip = data.ips?.[0] || '127.0.0.1';
        const el = document.getElementById('guideIP');
        if (el) el.textContent = ip;

        const portEl = document.getElementById('guideDNSPort');
        if (portEl) portEl.textContent = data.dns_port || 53;

        const webEl = document.getElementById('guideWebPanel');
        if (webEl) webEl.textContent = `http://${ip}:${data.web_port || 8080}`;

        // Fill all .guide-ip-code elements
        document.querySelectorAll('.guide-ip-code').forEach(el => {
            el.textContent = ip;
        });
    } catch (e) {
        console.warn('Failed to load guide info:', e);
    }
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'success');
    }).catch(() => {
        // Fallback
        const input = document.createElement('input');
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
        showToast('Copied!', 'success');
    });
}

// ==================== Dashboard ====================

async function loadDashboard() {
    try {
        const resp = await apiFetch('/api/stats');
        if (!resp.ok) return;
        const data = await resp.json();

        animateNumber('totalQueries', data.total_queries || 0);
        animateNumber('blockedQueries', data.blocked_queries || 0);

        const percentage = data.total_queries > 0
            ? ((data.blocked_queries / data.total_queries) * 100).toFixed(1)
            : 0;
        document.getElementById('blockedPercentage').textContent = percentage + '%';
        document.getElementById('avgResponseTime').textContent = (data.average_time_ms || 0).toFixed(1) + 'ms';

        updateCharts(data);
        updateTopTables(data);
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading dashboard:', e);
    }
}

function animateNumber(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const current = parseInt(el.textContent.replace(/[^0-9]/g, '')) || 0;
    if (current === target) {
        el.textContent = formatNumber(target);
        return;
    }
    const diff = target - current;
    const steps = 20;
    const stepVal = diff / steps;
    let step = 0;

    function tick() {
        step++;
        const val = step >= steps ? target : Math.round(current + stepVal * step);
        el.textContent = formatNumber(val);
        if (step < steps) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}

function updateCharts(data) {
    const ctx1 = document.getElementById('queriesChart')?.getContext('2d');
    if (ctx1) {
        const hours = Array.from({ length: 24 }, (_, i) => `${i}:00`);
        const hourlyQueries = data.hourly_queries || new Array(24).fill(0);
        const hourlyBlocked = data.hourly_blocked || new Array(24).fill(0);

        if (queriesChart) queriesChart.destroy();
        queriesChart = new Chart(ctx1, {
            type: 'line',
            data: {
                labels: hours,
                datasets: [{
                    label: 'Total Queries',
                    data: hourlyQueries,
                    borderColor: '#00d4ff',
                    backgroundColor: 'rgba(0, 212, 255, 0.08)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: '#00d4ff',
                }, {
                    label: 'Blocked',
                    data: hourlyBlocked,
                    borderColor: '#ff4466',
                    backgroundColor: 'rgba(255, 68, 102, 0.08)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: '#ff4466',
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { intersect: false, mode: 'index' },
                plugins: {
                    legend: { labels: { color: '#8888aa', font: { size: 11 }, usePointStyle: true, pointStyle: 'circle' } },
                    tooltip: {
                        backgroundColor: 'rgba(26, 26, 46, 0.95)',
                        titleColor: '#e0e0e8',
                        bodyColor: '#8888aa',
                        borderColor: '#2a2a45',
                        borderWidth: 1,
                        cornerRadius: 8,
                        padding: 12,
                    }
                },
                scales: {
                    x: { ticks: { color: '#555577', font: { size: 10 } }, grid: { color: 'rgba(42,42,69,0.3)' } },
                    y: { ticks: { color: '#555577', font: { size: 10 } }, grid: { color: 'rgba(42,42,69,0.3)' }, beginAtZero: true }
                }
            }
        });
    }

    const ctx2 = document.getElementById('queryTypesChart')?.getContext('2d');
    if (ctx2) {
        const queryTypes = data.query_types || {};
        const labels = Object.keys(queryTypes);
        const values = Object.values(queryTypes);

        if (queryTypesChart) queryTypesChart.destroy();
        queryTypesChart = new Chart(ctx2, {
            type: 'doughnut',
            data: {
                labels: labels.length > 0 ? labels : ['No Data'],
                datasets: [{
                    data: values.length > 0 ? values : [1],
                    backgroundColor: [
                        '#00d4ff', '#7b2fff', '#ff4466', '#00ff88',
                        '#ffaa00', '#ff66aa', '#00aaff', '#88ff00'
                    ],
                    borderWidth: 0,
                    hoverOffset: 8,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#8888aa', font: { size: 11 }, padding: 12, usePointStyle: true, pointStyle: 'circle' }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(26, 26, 46, 0.95)',
                        titleColor: '#e0e0e8',
                        bodyColor: '#8888aa',
                        borderColor: '#2a2a45',
                        borderWidth: 1,
                        cornerRadius: 8,
                        padding: 12,
                    }
                }
            }
        });
    }
}

function updateTopTables(data) {
    fillTopTable('topQueriedTable', data.top_queried_domains || {});
    fillTopTable('topBlockedTable', data.top_blocked_domains || {});
    fillTopTable('topClientsTable', data.top_clients || {});
}

function fillTopTable(tableId, dataMap) {
    const tbody = document.querySelector(`#${tableId} tbody`);
    if (!tbody) return;

    const sorted = Object.entries(dataMap)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    tbody.innerHTML = sorted.length === 0
        ? '<tr><td colspan="2" class="empty-state"><i class="fas fa-inbox"></i> No data yet</td></tr>'
        : sorted.map(([key, val]) => `<tr><td>${escapeHtml(key)}</td><td>${formatNumber(val)}</td></tr>`).join('');
}

// ==================== Domain Test ====================

async function testDomain(domain) {
    try {
        const resp = await apiFetch(`/api/test?domain=${encodeURIComponent(domain)}`);
        if (!resp.ok) {
            showToast('Failed to test domain', 'error');
            return;
        }
        const data = await resp.json();
        const blocked = data.blocked;
        const reason = data.reason || '';

        // Show toast for quick test
        if (blocked) {
            showToast(`${domain} is BLOCKED (${reason})`, 'error');
        } else {
            showToast(`${domain} is ALLOWED`, 'success');
        }

        // Also update the test result panel if visible
        const resultEl = document.getElementById('testDomainResult');
        if (resultEl) {
            resultEl.style.display = 'block';
            resultEl.className = `test-result ${blocked ? 'blocked' : 'allowed'}`;
            resultEl.innerHTML = blocked
                ? `<i class="fas fa-ban"></i> <strong>${escapeHtml(domain)}</strong> is <strong>BLOCKED</strong> — ${escapeHtml(reason)}`
                : `<i class="fas fa-check-circle"></i> <strong>${escapeHtml(domain)}</strong> is <strong>ALLOWED</strong>`;
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error testing domain', 'error');
    }
}

// ==================== Config Loading ====================

async function loadConfig() {
    try {
        const resp = await apiFetch('/api/config');
        if (!resp.ok) return;
        const cfg = await resp.json();
        applyConfigToUI(cfg);
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading config:', e);
    }
}

function applyConfigToUI(cfg) {
    // General settings
    setChecked('filteringEnabled', cfg.filtering?.enabled);
    setChecked('safeBrowsing', cfg.filtering?.safe_browsing);
    setChecked('parentalControl', cfg.filtering?.parental_control);

    // Safe Search
    const ss = cfg.filtering?.safe_search || {};
    setChecked('safeSearchEnabled', ss.enabled);
    setChecked('ssGoogle', ss.google);
    setChecked('ssBing', ss.bing);
    setChecked('ssYahoo', ss.yahoo);
    setChecked('ssYandex', ss.yandex);
    setChecked('ssDuckDuckGo', ss.duckduckgo);
    setChecked('ssYouTube', ss.youtube);
    setChecked('ssEcosia', ss.ecosia);
    setChecked('ssStartPage', ss.startpage);
    setChecked('ssBrave', ss.brave);

    // DNS settings
    setValue('dnsBindHost', cfg.dns?.bind_host);
    setValue('dnsPort', cfg.dns?.port);
    setChecked('enableIPv6', cfg.dns?.enable_ipv6);
    setValue('upstreamServers', (cfg.dns?.upstreams || []).join('\n'));
    setValue('bootstrapDns', (cfg.dns?.bootstrap_dns || []).join('\n'));
    setChecked('cacheEnabled', cfg.dns?.cache_enabled);
    setValue('cacheSize', cfg.dns?.cache_size);
    setValue('cacheTTLMin', cfg.dns?.cache_ttl_min);
    setValue('cacheTTLMax', cfg.dns?.cache_ttl_max);
    setValue('rateLimit', cfg.dns?.rate_limit);

    // Encryption
    setChecked('dohEnabled', cfg.dns?.doh_enabled);
    setValue('dohPort', cfg.dns?.doh_port);
    setChecked('dotEnabled', cfg.dns?.dot_enabled);
    setValue('dotPort', cfg.dns?.dot_port);
    setValue('tlsCert', cfg.dns?.doh_cert || cfg.dns?.dot_cert);
    setValue('tlsKey', cfg.dns?.doh_key || cfg.dns?.dot_key);

    // DHCP
    setChecked('dhcpEnabled', cfg.dhcp?.enabled);
    setValue('dhcpInterface', cfg.dhcp?.interface_name);
    setValue('dhcpGateway', cfg.dhcp?.gateway_ip);
    setValue('dhcpSubnet', cfg.dhcp?.subnet_mask);
    setValue('dhcpRangeStart', cfg.dhcp?.range_start);
    setValue('dhcpRangeEnd', cfg.dhcp?.range_end);
    setValue('dhcpLease', cfg.dhcp?.lease_duration);

    // Access
    setValue('allowedClients', (cfg.access?.allowed_clients || []).join('\n'));
    setValue('disallowedClients', (cfg.access?.disallowed_clients || []).join('\n'));
    setValue('blockedHosts', (cfg.access?.blocked_hosts || []).join('\n'));

    // Custom rules
    setValue('customRules', (cfg.filtering?.custom_rules || []).join('\n'));
}

// ==================== Form Handlers ====================

function initForms() {
    // General Settings
    document.getElementById('generalSettingsForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig({
            filtering: {
                enabled: getChecked('filteringEnabled'),
                safe_browsing: getChecked('safeBrowsing'),
                parental_control: getChecked('parentalControl')
            }
        });
    });

    // Change Password
    document.getElementById('changePasswordForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const current = document.getElementById('currentPassword').value;
        const newPass = document.getElementById('newPassword').value;
        if (!current || !newPass) {
            showToast('Please fill in all fields', 'error');
            return;
        }
        try {
            const resp = await apiFetch('/api/auth/password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ current_password: current, new_password: newPass })
            });
            if (resp.ok) {
                showToast('Password changed successfully. Please login again.', 'success');
                document.getElementById('currentPassword').value = '';
                document.getElementById('newPassword').value = '';
                setTimeout(() => logout(), 2000);
            } else {
                const err = await resp.json().catch(() => ({}));
                showToast(err.error || 'Failed to change password', 'error');
            }
        } catch (e) {
            if (e.message !== 'Unauthorized') showToast('Error changing password', 'error');
        }
    });

    // DNS Settings
    document.getElementById('dnsSettingsForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig({
            dns: {
                bind_host: getValue('dnsBindHost'),
                port: parseInt(getValue('dnsPort')),
                enable_ipv6: getChecked('enableIPv6'),
                upstreams: getLines('upstreamServers'),
                bootstrap_dns: getLines('bootstrapDns'),
                cache_enabled: getChecked('cacheEnabled'),
                cache_size: parseInt(getValue('cacheSize')),
                cache_ttl_min: parseInt(getValue('cacheTTLMin')),
                cache_ttl_max: parseInt(getValue('cacheTTLMax')),
                rate_limit: parseInt(getValue('rateLimit'))
            }
        });
    });

    // DHCP
    document.getElementById('dhcpForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig({
            dhcp: {
                enabled: getChecked('dhcpEnabled'),
                interface_name: getValue('dhcpInterface'),
                gateway_ip: getValue('dhcpGateway'),
                subnet_mask: getValue('dhcpSubnet'),
                range_start: getValue('dhcpRangeStart'),
                range_end: getValue('dhcpRangeEnd'),
                lease_duration: parseInt(getValue('dhcpLease'))
            }
        });
    });

    // Encryption
    document.getElementById('encryptionForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig({
            dns: {
                doh_enabled: getChecked('dohEnabled'),
                doh_port: parseInt(getValue('dohPort')),
                dot_enabled: getChecked('dotEnabled'),
                dot_port: parseInt(getValue('dotPort')),
                doh_cert: getValue('tlsCert'),
                doh_key: getValue('tlsKey'),
                dot_cert: getValue('tlsCert'),
                dot_key: getValue('tlsKey')
            }
        });
    });

    // Access Control
    document.getElementById('accessForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig({
            access: {
                allowed_clients: getLines('allowedClients'),
                disallowed_clients: getLines('disallowedClients'),
                blocked_hosts: getLines('blockedHosts')
            }
        });
    });

    // Safe Search
    document.getElementById('saveSafeSearch')?.addEventListener('click', async () => {
        await saveConfig({
            filtering: {
                safe_search: {
                    enabled: getChecked('safeSearchEnabled'),
                    google: getChecked('ssGoogle'),
                    bing: getChecked('ssBing'),
                    yahoo: getChecked('ssYahoo'),
                    yandex: getChecked('ssYandex'),
                    duckduckgo: getChecked('ssDuckDuckGo'),
                    youtube: getChecked('ssYouTube'),
                    ecosia: getChecked('ssEcosia'),
                    startpage: getChecked('ssStartPage'),
                    brave: getChecked('ssBrave')
                }
            }
        });
    });

    // Custom Rules
    document.getElementById('saveCustomRules')?.addEventListener('click', async () => {
        await saveConfig({
            filtering: {
                custom_rules: getLines('customRules')
            }
        });
    });

    // Test Domain button on filters page
    document.getElementById('testDomainBtn')?.addEventListener('click', () => {
        const domain = document.getElementById('testDomainInput')?.value?.trim();
        if (domain) testDomain(domain);
    });

    document.getElementById('testDomainInput')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const domain = e.target.value.trim();
            if (domain) testDomain(domain);
        }
    });

    // Blocklist actions
    document.getElementById('addBlocklist')?.addEventListener('click', showAddBlocklistModal);
    document.getElementById('addWhitelist')?.addEventListener('click', showAddWhitelistModal);
    document.getElementById('refreshLists')?.addEventListener('click', refreshAllLists);

    // Clear cache
    document.getElementById('clearCache')?.addEventListener('click', async () => {
        try {
            const resp = await apiFetch('/api/cache/clear', { method: 'POST' });
            if (resp.ok) showToast('DNS cache cleared', 'success');
            else showToast('Failed to clear cache', 'error');
        } catch (e) {
            if (e.message !== 'Unauthorized') showToast('Error clearing cache', 'error');
        }
    });

    // Query log filter
    document.getElementById('queryLogFilter')?.addEventListener('change', loadQueryLog);
    document.getElementById('refreshQueryLog')?.addEventListener('click', loadQueryLog);

    // Add client
    document.getElementById('addClient')?.addEventListener('click', showAddClientModal);

    // Toggle protection
    document.getElementById('toggleProtection')?.addEventListener('click', toggleProtection);

    // Modal close
    document.getElementById('modalClose')?.addEventListener('click', closeModal);
    document.getElementById('modal')?.addEventListener('click', (e) => {
        if (e.target.id === 'modal') closeModal();
    });
}

// ==================== API Calls ====================

async function saveConfig(partial) {
    try {
        const resp = await apiFetch('/api/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(partial)
        });
        if (resp.ok) {
            showToast('Settings saved successfully', 'success');
            loadConfig();
        } else {
            showToast('Failed to save settings', 'error');
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error saving settings: ' + e.message, 'error');
    }
}

async function toggleProtection() {
    try {
        const resp = await apiFetch('/api/protection/toggle', { method: 'POST' });
        if (resp.ok) {
            const data = await resp.json();
            const indicator = document.getElementById('serverStatus');
            const dot = indicator?.querySelector('.status-dot');
            const label = indicator?.querySelector('span:last-child');
            if (data.enabled) {
                dot.className = 'status-dot online';
                label.textContent = 'Protection Active';
                indicator.classList.remove('disabled');
                showToast('Protection enabled', 'success');
            } else {
                dot.className = 'status-dot offline';
                label.textContent = 'Protection Disabled';
                indicator.classList.add('disabled');
                showToast('Protection disabled', 'warning');
            }
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error toggling protection', 'error');
    }
}

// ==================== Blocklists ====================

async function loadBlocklists() {
    try {
        const resp = await apiFetch('/api/config');
        if (!resp.ok) return;
        const cfg = await resp.json();

        renderBlocklists(cfg.filtering?.blocklists || [], 'blocklistsList');
        renderBlocklists(cfg.filtering?.whitelists || [], 'whitelistsList');

        const statsResp = await apiFetch('/api/filtering/stats');
        if (statsResp.ok) {
            const stats = await statsResp.json();
            const el = document.getElementById('filterStats');
            if (el) {
                el.innerHTML = `
                    <div class="filter-stat"><strong>${formatNumber(stats.total_rules || 0)}</strong> blocked domains</div>
                    <div class="filter-stat"><strong>${stats.blocklists || 0}</strong> blocklists</div>
                    <div class="filter-stat"><strong>${stats.whitelists || 0}</strong> whitelists</div>
                    <div class="filter-stat">Last update: <strong>${stats.last_update || 'Never'}</strong></div>
                `;
            }
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading blocklists:', e);
    }
}

function renderBlocklists(lists, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (lists.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-list"></i><p>No lists configured</p></div>';
        return;
    }

    container.innerHTML = lists.map((list, index) => `
        <div class="blocklist-item">
            <div class="blocklist-info">
                <div class="name">${escapeHtml(list.name)}${list.default ? ' <span class="badge active" style="font-size:0.7em;margin-left:6px;">Default</span>' : ''}</div>
                <div class="url" title="${escapeHtml(list.url)}">${escapeHtml(list.url)}</div>
            </div>
            <div class="blocklist-actions">
                <label class="switch">
                    <input type="checkbox" ${list.enabled ? 'checked' : ''} 
                        onchange="toggleBlocklist('${containerId}', ${index}, this.checked)">
                    <span class="slider"></span>
                </label>
                ${list.default ? '' : `<button class="btn btn-sm btn-danger" onclick="removeBlocklist('${containerId}', ${index})">
                    <i class="fas fa-trash"></i>
                </button>`}
            </div>
        </div>
    `).join('');
}

async function toggleBlocklist(type, index, enabled) {
    const listType = type === 'blocklistsList' ? 'blocklist' : 'whitelist';
    try {
        const resp = await apiFetch(`/api/filtering/${listType}/${index}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        if (resp.ok) showToast(`List ${enabled ? 'enabled' : 'disabled'}`, 'success');
        else showToast('Failed to toggle list', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error toggling list', 'error');
    }
}

async function removeBlocklist(type, index) {
    if (!confirm('Are you sure you want to remove this list?')) return;
    const listType = type === 'blocklistsList' ? 'blocklist' : 'whitelist';
    try {
        const resp = await apiFetch(`/api/filtering/${listType}/${index}`, { method: 'DELETE' });
        if (resp.ok) {
            showToast('List removed', 'success');
            loadBlocklists();
        } else showToast('Failed to remove list', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error removing list', 'error');
    }
}

async function refreshAllLists() {
    const btn = document.getElementById('refreshLists');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
    }
    showToast('Updating all lists...', 'info');
    try {
        const resp = await apiFetch('/api/filtering/refresh', { method: 'POST' });
        if (resp.ok) {
            showToast('All lists updated successfully', 'success');
            loadBlocklists();
        } else showToast('Failed to update lists', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error updating lists', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-download"></i> Update All Lists Now';
        }
    }
}

// ==================== Query Log ====================

async function loadQueryLog() {
    try {
        const filter = getValue('queryLogFilter') || 'all';
        const resp = await apiFetch(`/api/querylog?limit=100&filter=${filter}`);
        if (!resp.ok) return;
        const data = await resp.json();

        const tbody = document.querySelector('#queryLogTable tbody');
        if (!tbody) return;

        const entries = data.entries || [];
        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state"><i class="fas fa-clipboard-list"></i> No queries logged yet</td></tr>';
            return;
        }

        tbody.innerHTML = entries.map(entry => {
            const rowClass = entry.blocked ? 'blocked-row' : 'allowed-row';
            const status = entry.blocked
                ? `<span style="color:var(--danger)"><i class="fas fa-ban"></i> Blocked (${escapeHtml(entry.reason)})</span>`
                : `<span style="color:var(--success)"><i class="fas fa-check"></i> ${escapeHtml(entry.reason)}</span>`;
            const time = new Date(entry.timestamp).toLocaleTimeString();
            return `<tr class="${rowClass}">
                <td>${time}</td>
                <td>${escapeHtml(entry.domain)}</td>
                <td>${escapeHtml(entry.type)}</td>
                <td>${escapeHtml(entry.client_ip)}</td>
                <td>${status}</td>
                <td>${escapeHtml(entry.duration)}</td>
            </tr>`;
        }).join('');
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading query log:', e);
    }
}

// ==================== Modals ====================

function showAddBlocklistModal() {
    showModal('Add Blocklist', `
        <div class="form-group">
            <label>List Name</label>
            <input type="text" id="newListName" placeholder="My Custom Blocklist">
        </div>
        <div class="form-group">
            <label>URL</label>
            <input type="text" id="newListURL" placeholder="https://example.com/blocklist.txt">
        </div>
        <button class="btn btn-primary" onclick="addList('blocklist')">
            <i class="fas fa-plus"></i> Add Blocklist
        </button>
    `);
}

function showAddWhitelistModal() {
    showModal('Add Whitelist', `
        <div class="form-group">
            <label>List Name</label>
            <input type="text" id="newListName" placeholder="My Whitelist">
        </div>
        <div class="form-group">
            <label>URL</label>
            <input type="text" id="newListURL" placeholder="https://example.com/whitelist.txt">
        </div>
        <button class="btn btn-primary" onclick="addList('whitelist')">
            <i class="fas fa-plus"></i> Add Whitelist
        </button>
    `);
}

async function addList(type) {
    const name = getValue('newListName');
    const url = getValue('newListURL');
    if (!name || !url) {
        showToast('Please fill in all fields', 'error');
        return;
    }

    try {
        const resp = await apiFetch(`/api/filtering/${type}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, url, enabled: true, type: 'url' })
        });
        if (resp.ok) {
            showToast(`${type} added successfully`, 'success');
            closeModal();
            loadBlocklists();
        } else showToast(`Failed to add ${type}`, 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast(`Error adding ${type}`, 'error');
    }
}

function showAddClientModal() {
    showModal('Add Client Device', `
        <div class="form-group">
            <label>Client Name</label>
            <input type="text" id="newClientName" placeholder="Living Room TV">
        </div>
        <div class="form-group">
            <label>IDs (IPs, MACs - one per line)</label>
            <textarea id="newClientIDs" rows="3" placeholder="192.168.1.100&#10;AA:BB:CC:DD:EE:FF"></textarea>
        </div>
        <div class="form-group">
            <label>Filtering Enabled</label>
            <label class="switch"><input type="checkbox" id="newClientFiltering" checked><span class="slider"></span></label>
        </div>
        <div class="form-group">
            <label>Safe Search</label>
            <label class="switch"><input type="checkbox" id="newClientSafeSearch" checked><span class="slider"></span></label>
        </div>
        <div class="form-group">
            <label>Parental Control</label>
            <label class="switch"><input type="checkbox" id="newClientParental"><span class="slider"></span></label>
        </div>
        <button class="btn btn-primary" onclick="addClient()">
            <i class="fas fa-plus"></i> Add Client
        </button>
    `);
}

async function addClient() {
    const name = getValue('newClientName');
    const ids = getLines('newClientIDs');
    if (!name || ids.length === 0) {
        showToast('Please fill in all required fields', 'error');
        return;
    }

    try {
        const resp = await apiFetch('/api/clients', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                ids,
                filtering_enabled: getChecked('newClientFiltering'),
                safe_search: getChecked('newClientSafeSearch'),
                parental_control: getChecked('newClientParental'),
                use_global_config: true
            })
        });
        if (resp.ok) {
            showToast('Client added successfully', 'success');
            closeModal();
            loadClients();
        } else showToast('Failed to add client', 'error');
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error adding client', 'error');
    }
}

// ==================== Load Functions ====================

async function loadClients() {
    try {
        // Load configured clients
        const resp = await apiFetch('/api/clients');
        if (!resp.ok) return;
        const clients = await resp.json();

        // Load active clients from stats
        const statsResp = await apiFetch('/api/stats');
        let activeClients = {};
        if (statsResp.ok) {
            const stats = await statsResp.json();
            activeClients = stats.top_clients || {};
        }

        const container = document.getElementById('clientsList');
        if (!container) return;

        let html = '';

        // Show active (auto-detected) clients from DNS queries
        const activeEntries = Object.entries(activeClients).sort((a, b) => b[1] - a[1]);
        if (activeEntries.length > 0) {
            html += '<div class="section-label" style="padding:12px 0 8px;color:#8888aa;font-size:0.85em;font-weight:600;text-transform:uppercase;letter-spacing:1px;"><i class="fas fa-wifi" style="margin-right:6px;color:#00d4aa;"></i>Active Clients (Auto-detected)</div>';
            html += activeEntries.map(([ip, queries]) => `
                <div class="client-item">
                    <div class="client-info">
                        <div class="name"><i class="fas fa-desktop" style="color:#00d4aa;margin-right:8px;"></i>${escapeHtml(ip)}</div>
                        <div class="ids">${formatNumber(queries)} queries</div>
                    </div>
                    <span class="badge active" style="font-size:0.75em;">Connected</span>
                </div>
            `).join('');
        }

        // Show configured (manual) clients
        if (clients && clients.length > 0) {
            html += '<div class="section-label" style="padding:16px 0 8px;color:#8888aa;font-size:0.85em;font-weight:600;text-transform:uppercase;letter-spacing:1px;"><i class="fas fa-cog" style="margin-right:6px;"></i>Configured Clients</div>';
            html += clients.map((client, i) => `
                <div class="client-item">
                    <div class="client-info">
                        <div class="name"><i class="fas fa-laptop"></i> ${escapeHtml(client.name)}</div>
                        <div class="ids">${(client.ids || []).map(id => escapeHtml(id)).join(', ')}</div>
                        <div class="client-badges">
                            <span class="badge ${client.filtering_enabled ? 'active' : 'inactive'}">Filtering</span>
                            <span class="badge ${client.safe_search ? 'active' : 'inactive'}">Safe Search</span>
                            <span class="badge ${client.parental_control ? 'active' : 'inactive'}">Parental</span>
                        </div>
                    </div>
                    <button class="btn btn-sm btn-danger" onclick="removeClient(${i})">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            `).join('');
        }

        if (!html) {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-laptop"></i><p>No clients detected yet. Connect a device using this DNS server to see it here.</p></div>';
        } else {
            container.innerHTML = html;
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading clients:', e);
    }
}

async function removeClient(index) {
    if (!confirm('Remove this client?')) return;
    try {
        const resp = await apiFetch(`/api/clients/${index}`, { method: 'DELETE' });
        if (resp.ok) {
            showToast('Client removed', 'success');
            loadClients();
        }
    } catch (e) {
        if (e.message !== 'Unauthorized') showToast('Error removing client', 'error');
    }
}

async function loadDHCPLeases() {
    try {
        const resp = await apiFetch('/api/dhcp/leases');
        if (!resp.ok) return;
        const leases = await resp.json();

        const tbody = document.querySelector('#dhcpLeasesTable tbody');
        if (!tbody) return;

        if (!leases || leases.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state"><i class="fas fa-network-wired"></i> No active leases</td></tr>';
            return;
        }

        tbody.innerHTML = leases.map(lease => `
            <tr>
                <td><code>${escapeHtml(lease.mac)}</code></td>
                <td>${escapeHtml(lease.ip)}</td>
                <td>${escapeHtml(lease.hostname || '-')}</td>
                <td>${lease.static ? '<span class="badge static">Static</span>' : '-'}</td>
                <td>${lease.static ? 'Never' : new Date(lease.expires_at).toLocaleString()}</td>
            </tr>
        `).join('');
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading DHCP leases:', e);
    }
}

function loadSafeSearch() { loadConfig(); }
function loadGeneralSettings() { loadConfig(); }
function loadDNSSettings() { loadConfig(); }
function loadAccessSettings() { loadConfig(); }
function loadEncryptionSettings() { loadConfig(); }

async function loadCustomRules() {
    try {
        const resp = await apiFetch('/api/config');
        if (!resp.ok) return;
        const cfg = await resp.json();
        setValue('customRules', (cfg.filtering?.custom_rules || []).join('\n'));
    } catch (e) {
        if (e.message !== 'Unauthorized') console.error('Error loading custom rules:', e);
    }
}

// ==================== Utilities ====================

function showModal(title, body) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = body;
    document.getElementById('modal').classList.add('active');
}

function closeModal() {
    document.getElementById('modal').classList.remove('active');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icons = { success: 'check-circle', error: 'exclamation-circle', info: 'info-circle', warning: 'exclamation-triangle' };
    toast.innerHTML = `<i class="fas fa-${icons[type] || 'info-circle'}"></i> ${escapeHtml(message)}`;

    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 350);
    }, 3500);
}

function startAutoRefresh() {
    if (statsRefreshInterval) clearInterval(statsRefreshInterval);
    statsRefreshInterval = setInterval(loadDashboard, 10000);
}

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function getValue(id) {
    const el = document.getElementById(id);
    return el ? el.value : '';
}

function setValue(id, value) {
    const el = document.getElementById(id);
    if (el && value !== undefined && value !== null) el.value = value;
}

function getChecked(id) {
    const el = document.getElementById(id);
    return el ? el.checked : false;
}

function setChecked(id, value) {
    const el = document.getElementById(id);
    if (el) el.checked = !!value;
}

function getLines(id) {
    return getValue(id).split('\n').map(l => l.trim()).filter(l => l);
}
