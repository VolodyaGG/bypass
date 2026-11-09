// bypass Frontend - JARVIS-style UI
// Backend integration

// State management
const state = {
    protocols: { hysteria2: false, vless_reality: false, openflux: false },
    vps: { ip: '', port: 22, user: 'root', auth: 'key', keyPath: '', password: '', runtime: 'native' },
    dns: { cfToken: '', root: '', sub: '' },
    certs: { source: 'upload', vpsFullchainPath: '', vpsPrivkeyPath: '', info: null },
    openflux: { transport: null, mode: 'l4', codec: 'batched', localIp: '', yandexUrl: '', maxToken: '', maxUid: '', encKey: '' },
    routing: { ruDirect: true, privateDirect: true, customDirectDomains: '' },
    deploy: { jobId: null, running: false, stages: {}, logs: [], mode: 'demo' },
    clients: [],
    services: {},
    theme: 'dark',
    selectedClientId: null
};

const formGroups = ['protocols', 'vps', 'dns', 'certs', 'openflux', 'routing'];
const workspaceForms = { demo: Object.fromEntries(
    formGroups.map(group => [group, { ...state[group] }])
) };
let deployMode = 'demo';
let lastDemo = null;

const iconPaths = {
    shield: '<path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3Z"/><path d="m9 12 2 2 4-4"/>',
    cpu: '<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
    server: '<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01M6 18h.01"/>',
    users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
    'help-circle': '<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 1 1 5.83 1c0 2-3 2-3 4M12 18h.01"/>',
    eye: '<path d="M2.06 12.35a1 1 0 0 1 0-.7C3.73 7.6 7.6 5 12 5s8.27 2.6 9.94 6.65a1 1 0 0 1 0 .7C20.27 16.4 16.4 19 12 19s-8.27-2.6-9.94-6.65"/><circle cx="12" cy="12" r="3"/>',
    'eye-off': '<path d="m2 2 20 20M10.73 5.08A10.43 10.43 0 0 1 12 5c4.4 0 8.27 2.6 9.94 6.65a1 1 0 0 1 0 .7 10.6 10.6 0 0 1-2.11 3.19M6.61 6.61a10.73 10.73 0 0 0-4.55 5.04 1 1 0 0 0 0 .7C3.73 16.4 7.6 19 12 19a10.43 10.43 0 0 0 5.39-1.61M14.12 14.12A3 3 0 0 1 9.88 9.88"/>',
    copy: '<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
    x: '<path d="M18 6 6 18M6 6l12 12"/>',
    'edit-2': '<path d="M17 3a2.85 2.85 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/>',
    'trash-2': '<path d="M3 6h18M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M10 11v6M14 11v6"/>'
};

// Render bundled SVG icons without depending on an external CDN.
function initIcons() {
    document.querySelectorAll('[data-lucide]').forEach(element => {
        const path = iconPaths[element.dataset.lucide];
        if (!path) return;
        const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        icon.setAttribute('viewBox', '0 0 24 24');
        icon.setAttribute('fill', 'none');
        icon.setAttribute('stroke', 'currentColor');
        icon.setAttribute('stroke-width', '2');
        icon.setAttribute('stroke-linecap', 'round');
        icon.setAttribute('stroke-linejoin', 'round');
        icon.setAttribute('aria-hidden', 'true');
        icon.setAttribute('class', element.getAttribute('class') || '');
        if (element.getAttribute('style')) icon.setAttribute('style', element.getAttribute('style'));
        icon.innerHTML = path;
        element.replaceWith(icon);
    });
}

// LocalStorage helpers
function saveState() {
    try {
        if (deployMode === 'demo') {
            localStorage.setItem(demoStorageKey(), JSON.stringify({
                ip: state.vps.ip,
                runtime: state.vps.runtime,
                protocols: state.protocols,
                root: state.dns.root,
                sub: state.dns.sub,
                last: lastDemo
            }));
        } else {
            const toSave = Object.fromEntries(formGroups.map(group => [group, state[group]]));
            toSave.vps = { ...state.vps, password: '' };
            toSave.dns = { ...state.dns, cfToken: '' };
            toSave.openflux = { ...state.openflux, encKey: '' };
            localStorage.setItem('vpnforge-state', JSON.stringify(toSave));
        }
    } catch (error) {
        console.warn('Could not save workspace settings', error);
    }
}

function loadState() {
    try {
        const parsed = JSON.parse(localStorage.getItem('vpnforge-state')) || {};
        formGroups.forEach(group => Object.assign(state[group], parsed[group]));
        if (state.openflux.mode === 'proxy') state.openflux.mode = 'l4';
        if (state.openflux.mode === 'raw') state.openflux.mode = 'l3';
        const saved = JSON.parse(localStorage.getItem(demoStorageKey()));
        if (saved) {
            const { vps, dns, protocols } = workspaceForms.demo;
            vps.ip = saved.ip || '';
            vps.runtime = saved.runtime === 'docker' ? 'docker' : 'native';
            dns.root = saved.root || '';
            dns.sub = saved.sub || '';
            Object.keys(protocols).forEach(name => { protocols[name] = Boolean(saved.protocols?.[name]); });
            lastDemo = saved.last || null;
        }
    } catch (error) {
        console.warn('Could not load workspace settings', error);
    }
    workspaceForms.real = Object.fromEntries(formGroups.map(group => [group, state[group]]));
    Object.assign(state, workspaceForms.demo);
}

function demoStorageKey() {
    return `bypass-demo:${document.getElementById('app').dataset.profile.toLowerCase()}`;
}

function switchMode(mode) {
    if (state.deploy.running || deployMode === mode) return;
    deployMode = mode;
    Object.assign(state, workspaceForms[mode]);
    initFormFromState();
    clearFormError();
    updateDeployControls();
    if (mode === 'real' && state.vps.ip) refreshRealClients(state.vps.ip);
}

function fillDemo() {
    Object.assign(state.vps, { ip: '203.0.113.10', user: 'demo', auth: 'password', password: 'mock', runtime: 'native' });
    Object.assign(state.protocols, { hysteria2: true, vless_reality: false, openflux: false });
    Object.assign(state.dns, { root: 'example.test', sub: 'vpn', cfToken: 'mock' });
    Object.assign(state.certs, {
        source: 'vps',
        vpsFullchainPath: '/demo/fullchain.pem',
        vpsPrivkeyPath: '/demo/privkey.pem'
    });
    initFormFromState();
    clearFormError();
    saveState();
}

function renderLastDemo() {
    const result = document.getElementById('last-demo-result');
    result.classList.toggle('hidden', deployMode !== 'demo' || !lastDemo);
    if (lastDemo) {
        const date = new Date(lastDemo.finishedAt).toLocaleString('ru-RU');
        result.textContent = `Последнее демо · ${lastDemo.ip} · ${deployStatusText(lastDemo.status, 'demo')} · ${date}`;
    }
}

// API helper
async function api(path, { method = 'GET', body, form } = {}) {
    const opts = { method, headers: {} };
    if (body) { 
        opts.headers['Content-Type'] = 'application/json'; 
        opts.body = JSON.stringify(body); 
    }
    if (form) { 
        opts.body = form; 
    }
    const r = await fetch(path, opts);
    if (!r.ok) {
        const error = await r.json();
        if (error.error?.code === 'auth_required') {
            window.location.assign('/login');
        }
        throw new Error(error.error?.message || 'API request failed');
    }
    return r.status === 204 ? null : r.json();
}

// UI Helpers
function showElement(id) {
    document.getElementById(id)?.classList.remove('hidden');
}

function hideElement(id) {
    document.getElementById(id)?.classList.add('hidden');
}

function toggleElement(id) {
    document.getElementById(id)?.classList.toggle('hidden');
}

// Toast notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'fadeOut 180ms ease-out forwards';
        setTimeout(() => toast.remove(), 180);
    }, 4000);
}

function clientToken(client) {
    return client.sub_token || client.subToken;
}

function subscriptionUrl(client) {
    const host = state.protocols.hysteria2 && state.dns.root && state.dns.sub
        ? `${state.dns.sub}.${state.dns.root}`
        : state.vps.ip;
    const scheme = state.protocols.hysteria2 ? 'https' : 'http';
    const port = state.protocols.hysteria2 ? 8444 : 8080;
    return `${scheme}://${host}:${port}/sub/${clientToken(client)}`;
}

function decodeSubscription(payload) {
    const binary = atob(payload.trim());
    const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
}

// Section visibility based on protocols
function updateSectionVisibility() {
    const { hysteria2, vless_reality: vlessReality, openflux } = state.protocols;
    
    // DNS & CERTS section - only if Hysteria 2 is enabled
    if (hysteria2) {
        showElement('section-dns');
    } else {
        hideElement('section-dns');
    }
    
    // OPENFLUX section - only if OpenFlux is enabled
    if (openflux) {
        showElement('section-openflux');
    } else {
        hideElement('section-openflux');
    }

    if (vlessReality) {
        showElement('section-routing');
    } else {
        hideElement('section-routing');
    }
    
    // CLIENTS and SERVICES sections - only after successful deploy
    // For mock, we'll show them when there are clients/services
    if (state.clients.length > 0) {
        showElement('section-clients');
    } else {
        hideElement('section-clients');
    }
    
    if (Object.keys(state.services).length > 0) {
        showElement('section-services');
    } else {
        hideElement('section-services');
    }
}

// Auth type toggle
function updateAuthFields() {
    const auth = state.vps.auth;
    if (auth === 'key') {
        showElement('key-path-group');
        hideElement('password-group');
    } else {
        hideElement('key-path-group');
        showElement('password-group');
    }
}

function updateCertificateFields() {
    if (state.certs.source === 'vps') {
        hideElement('certificate-upload-fields');
        showElement('certificate-vps-fields');
    } else {
        showElement('certificate-upload-fields');
        hideElement('certificate-vps-fields');
    }
}

// OpenFlux transport fields
function updateOpenFluxFields() {
    const transport = state.openflux.transport;
    const mode = state.openflux.mode || 'l4';
    hideElement('document-url-group');
    hideElement('oneme-group');
    hideElement('openflux-localip-group');
    
    if (mode === 'l3') {
        showElement('openflux-localip-group');
    }

    if (['yandex', 'vyandex', 'mailru'].includes(transport)) {
        showElement('document-url-group');
    } else if (transport === 'oneme') {
        showElement('oneme-group');
    }
}

// Render clients
function renderClients() {
    const container = document.getElementById('clients-list');
    container.innerHTML = '';
    
    // Update client count in header
    const clientCount = document.getElementById('client-count');
    if (clientCount) {
        clientCount.textContent = state.clients.length;
    }
    
    state.clients.forEach(client => {
        const row = document.createElement('div');
        row.className = 'client-row';
        row.dataset.clientId = client.id;
        
        const info = document.createElement('div');
        info.className = 'client-info';
        
        const label = document.createElement('span');
        label.className = 'client-label';
        label.textContent = client.label;
        
        const protocols = document.createElement('span');
        protocols.className = 'client-protocols';
        protocols.textContent = [
            state.protocols.vless_reality ? 'VLESS' : null,
            state.protocols.hysteria2 ? 'Hy2' : null,
        ].filter(Boolean).join('+');
        
        const sub = document.createElement('span');
        sub.className = 'client-sub';
        const token = clientToken(client);
        sub.textContent = `/sub/${token.substring(0, 8)}…`;
        
        info.appendChild(label);
        info.appendChild(protocols);
        info.appendChild(sub);
        
        const actions = document.createElement('div');
        actions.className = 'client-actions';
        
        const copyBtn = document.createElement('button');
        copyBtn.className = 'icon-btn';
        copyBtn.innerHTML = '<i data-lucide="copy" class="w-4 h-4"></i>';
        copyBtn.title = 'Copy subscription URL';
        copyBtn.onclick = (e) => {
            e.stopPropagation();
            copyToClipboard(subscriptionUrl(client));
            showToast('Ссылка подписки скопирована.', 'success');
        };
        
        const renameBtn = document.createElement('button');
        renameBtn.className = 'icon-btn';
        renameBtn.innerHTML = '<i data-lucide="edit-2" class="w-4 h-4"></i>';
        renameBtn.title = 'Rename';
        renameBtn.onclick = (e) => {
            e.stopPropagation();
            openRenameClientModal(client.id);
        };
        
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'icon-btn';
        deleteBtn.innerHTML = '<i data-lucide="trash-2" class="w-4 h-4"></i>';
        deleteBtn.title = 'Delete';
        deleteBtn.onclick = (e) => {
            e.stopPropagation();
            openDeleteClientModal(client.id);
        };
        
        actions.appendChild(copyBtn);
        actions.appendChild(renameBtn);
        actions.appendChild(deleteBtn);
        
        row.appendChild(info);
        row.appendChild(actions);
        
        row.onclick = () => openViewConfigModal(client.id);
        
        container.appendChild(row);
    });
    
    initIcons();
}

// Render services
function renderServices() {
    const container = document.getElementById('services-list');
    container.innerHTML = '';
    
    // Update node count in header
    const nodeCount = document.getElementById('node-count');
    if (nodeCount) {
        nodeCount.textContent = state.vps.ip ? '1' : '0';
    }
    
    // For now, we don't have a services status endpoint, so we'll show placeholder
    if (state.vps.ip) {
        const services = [
            { name: 'xray.service', status: 'unknown' },
            { name: 'hysteria.service', status: 'unknown' },
            { name: 'vpnforge-sub.service', status: 'unknown' }
        ];
        
        if (state.protocols.openflux) {
            services.push({ name: 'openflux.service', status: 'unknown' });
        }
        
        services.forEach(service => {
            const row = document.createElement('div');
            row.className = 'service-row';
            
            const status = document.createElement('span');
            status.className = 'service-status';
            status.textContent = '●';
            status.style.color = 'var(--text-dim)';
            
            const serviceName = document.createElement('span');
            serviceName.className = 'service-name';
            serviceName.textContent = service.name;
            
            const stateText = document.createElement('span');
            stateText.className = 'service-state';
            stateText.textContent = service.status;
            
            row.appendChild(status);
            row.appendChild(serviceName);
            row.appendChild(stateText);
            
            container.appendChild(row);
        });
    }
}

const deploymentStages = {
    demo: [
        ['converge', 'Описание'],
        ['idempotence', 'Повторный прогон'],
        ['verify', 'Проверка']
    ],
    real: [
        ['prepare', 'Подготовка'],
        ['ansible', 'Деплой и проверка']
    ]
};

function focusJournal() {
    document.getElementById('journal-title').focus({ preventScroll: true });
    document.getElementById('deploy-journal').scrollIntoView({ block: 'nearest' });
}

function renderStages() {
    const stages = document.getElementById('stages-bar');
    const mode = state.deploy.jobId || state.deploy.running ? state.deploy.mode : deployMode;
    stages.replaceChildren(...deploymentStages[mode].map(([key, label]) => {
        const status = state.deploy.stages[key];
        const item = document.createElement('span');
        item.className = `stage ${status || ''}`;
        const icon = { running: '◐', done: '✓', failed: '✗' }[status] || '○';
        const description = { running: 'выполняется', done: 'завершено', failed: 'ошибка' }[status] || 'ожидание';
        item.textContent = `${icon} ${label}`;
        item.setAttribute('aria-label', `${label}: ${description}`);
        return item;
    }));
}

function trackDeploymentStage(line) {
    if (state.deploy.mode === 'demo') {
        const match = line.match(/\[default > (converge|idempotence|verify)\] (Executing|Executed: (?:Successful|Failed))/);
        if (match) {
            const status = { Executing: 'running', 'Executed: Successful': 'done', 'Executed: Failed': 'failed' };
            state.deploy.stages[match[1]] = status[match[2]];
        }
    } else if (line === 'deploy started') {
        state.deploy.stages.prepare = 'running';
    } else if (line === 'running ansible-playbook') {
        state.deploy.stages.prepare = 'done';
        state.deploy.stages.ansible = 'running';
    }
    renderStages();
}

function deployStatusText(status, mode) {
    return {
        idle: 'Ожидание запуска',
        running: 'Выполняется',
        success: mode === 'demo' ? 'Симуляция завершена' : 'Сервер настроен',
        failed: 'Ошибка запуска',
        cancelled: 'Запуск отменён'
    }[status] || 'Статус неизвестен';
}

function setDeployStatus(status, error = '') {
    const element = document.getElementById('deploy-status');
    element.dataset.status = status;
    element.textContent = deployStatusText(status, state.deploy.mode) + (error ? ` · ${error}` : '');
}

function updateDeployControls() {
    const running = state.deploy.running;
    const demo = deployMode === 'demo';
    document.getElementById('app').dataset.mode = deployMode;
    const button = document.getElementById('forge-btn');
    document.getElementById('deploy-button-label').textContent = demo ? 'Запустить демо' : 'Развернуть на VPS';
    button.disabled = running;
    document.querySelectorAll('[data-deploy-mode]').forEach(control => {
        control.disabled = running;
        control.setAttribute('aria-pressed', String(control.dataset.deployMode === deployMode));
    });
    document.getElementById('mode-description').textContent = demo
        ? 'Molecule проверит конфигурацию на этом компьютере.'
        : 'Ansible подключится по SSH и развернёт VPN на VPS.';
    document.getElementById('demo-fill-btn').classList.toggle('hidden', !demo);
    document.getElementById('demo-fill-btn').disabled = running;
    const cancel = document.getElementById('cancel-deploy-btn');
    cancel.classList.toggle('hidden', !demo);
    cancel.disabled = !running || !state.deploy.jobId;
    const hasLogs = state.deploy.logs.length > 0;
    document.getElementById('copy-log-btn').disabled = !hasLogs;
    document.getElementById('download-log-btn').disabled = !hasLogs;
    const journalMode = state.deploy.jobId || running || hasLogs ? state.deploy.mode : deployMode;
    document.getElementById('deploy-mode-badge').textContent = journalMode === 'demo' ? 'Демо' : 'На VPS';
    updateStatusDot(running);
    renderStages();
    renderLastDemo();
}

function clearFormError() {
    hideElement('deploy-form-error');
    document.querySelectorAll('[aria-invalid="true"]').forEach(field => field.removeAttribute('aria-invalid'));
}

function showFormError(message, fieldId) {
    const field = document.getElementById(fieldId);
    const details = field.closest('details');
    if (details) details.open = true;
    field.setAttribute('aria-invalid', 'true');
    document.getElementById('deploy-form-error').textContent = message;
    showElement('deploy-form-error');
    field.focus();
}

// Add log line to terminal
function addLogLine(line, type = 'default') {
    const container = document.getElementById('log-container');
    const logLine = document.createElement('div');
    logLine.className = `log-line ${type}`;
    logLine.textContent = line;
    container.appendChild(logLine);
    
    // Auto-scroll to bottom
    const terminal = document.getElementById('terminal');
    terminal.scrollTop = terminal.scrollHeight;
}

// Clear terminal
function clearTerminal() {
    document.getElementById('log-container').innerHTML = '';
}

// Both modes use the same controls and event stream.
async function startDeployment() {
    if (state.deploy.running) return;
    clearFormError();
    const mode = deployMode;
    const demo = mode === 'demo';
    const ip = state.vps.ip.trim();
    if (!ip) {
        showFormError('Введите адрес сервера.', 'vps-ip');
        return;
    }
    if (!Object.values(state.protocols).some(Boolean)) {
        showFormError('Выберите хотя бы один протокол.', 'proto-hysteria2');
        return;
    }
    const domain = state.dns.root.trim() && state.dns.sub.trim()
        ? `${state.dns.sub.trim()}.${state.dns.root.trim()}` : null;
    if (!demo && state.protocols.hysteria2 && !domain) {
        showFormError('Для Hysteria 2 укажите корневой домен и поддомен.', state.dns.root.trim() ? 'dns-sub' : 'dns-root');
        return;
    }
    if (!demo && state.protocols.hysteria2 && state.certs.source === 'vps' &&
        (!state.certs.vpsFullchainPath || !state.certs.vpsPrivkeyPath)) {
        showFormError('Укажите оба пути к сертификату на VPS.', state.certs.vpsFullchainPath ? 'cert-vps-privkey' : 'cert-vps-fullchain');
        return;
    }

    try {
        // Prepare deploy request
        const deployRequest = demo ? {
            ip,
            domain,
            protocols: state.protocols,
            runtime: state.vps.runtime
        } : {
            ip,
            ssh_user: state.vps.user,
            ssh_port: state.vps.port,
            ssh_private_key_path: state.vps.auth === 'key' ? state.vps.keyPath : null,
            ssh_password: state.vps.auth === 'password' ? state.vps.password : null,
            domain: state.protocols.hysteria2 ? domain : null,
            root_domain: state.dns.root || null,
            protocols: state.protocols,
            runtime: state.vps.runtime,
            certificate_source: state.certs.source,
            vps_fullchain_path: state.certs.source === 'vps' ? state.certs.vpsFullchainPath : null,
            vps_privkey_path: state.certs.source === 'vps' ? state.certs.vpsPrivkeyPath : null,
            openflux: state.protocols.openflux ? {
                transport: state.openflux.transport,
                mode: state.openflux.mode || 'l4',
                codec: state.openflux.codec || 'batched',
                local_ip: state.openflux.localIp || null,
                yandex_url: state.openflux.yandexUrl || null,
                max_token: state.openflux.maxToken || null,
                max_uid: state.openflux.maxUid || null,
                encryption_key: state.openflux.encKey || null,
                debug: false,
            } : null,
            routing: {
                ru_direct: state.routing.ruDirect,
                private_direct: state.routing.privateDirect,
                custom_direct_domains: state.routing.customDirectDomains
                    .split(/[\n,]+/)
                    .map(domain => domain.trim())
                    .filter(Boolean),
            },
            cf_api_token: state.dns.cfToken || null
        };
        
        // Prepare form data
        const formData = new FormData();
        formData.append('payload', JSON.stringify(deployRequest));
        
        // Add certificate files if Hysteria 2 is enabled
        if (!demo && state.protocols.hysteria2 && state.certs.source === 'upload') {
            const certInput = document.getElementById('cert-file');
            const keyInput = document.getElementById('key-file');
            
            if (certInput.files.length > 0) {
                formData.append('fullchain', certInput.files[0]);
            }
            if (keyInput.files.length > 0) {
                formData.append('privkey', keyInput.files[0]);
            }
        }
        
        state.deploy = { jobId: null, running: true, stages: {}, logs: [], mode, ip };
        clearTerminal();
        setDeployStatus('running');
        updateDeployControls();
        focusJournal();

        const path = demo ? '/api/deploy/demo' : '/api/deploy';
        const response = await api(path, { method: 'POST', form: formData });
        state.deploy.jobId = response.job_id;
        updateDeployControls();
        connectToStream(response.job_id);
    } catch (error) {
        completeDeployment('failed', error.message);
    }
}

function connectToStream(jobId) {
    const eventSource = new EventSource(`/api/deploy/stream/${jobId}`);

    eventSource.addEventListener('log', event => {
        const line = JSON.parse(event.data).line;
        state.deploy.logs.push(line);
        addLogLine(line);
        trackDeploymentStage(line);
        document.getElementById('copy-log-btn').disabled = false;
        document.getElementById('download-log-btn').disabled = false;
    });

    eventSource.addEventListener('done', event => {
        const { status, error } = JSON.parse(event.data);
        eventSource.close();
        completeDeployment(status, status === 'cancelled' ? '' : error);
    });

    eventSource.addEventListener('error', () => {
        eventSource.close();
        completeDeployment('failed', 'Связь с журналом прервалась.');
    });
}

function completeDeployment(status, error = '') {
    const { mode, ip, stages } = state.deploy;
    state.deploy.running = false;
    if (mode === 'real' && status === 'success') {
        stages.ansible = 'done';
        refreshRealClients(ip);
    }
    if (status === 'failed' || status === 'cancelled') {
        Object.keys(stages).forEach(stage => {
            if (stages[stage] === 'running') stages[stage] = 'failed';
        });
    }
    if (mode === 'demo') {
        lastDemo = { ip, status, finishedAt: new Date().toISOString() };
        saveState();
    }
    const message = deployStatusText(status, mode);
    const summary = error ? `${message} · ${error}` : message;
    state.deploy.logs.push(summary);
    addLogLine(summary, { success: 'success', failed: 'error', cancelled: 'warning' }[status]);
    setDeployStatus(status, error);
    updateDeployControls();
}

async function refreshRealClients(ip) {
    try {
        const clients = await api(`/api/clients?ip=${encodeURIComponent(ip)}`);
        if (deployMode === 'real' && state.vps.ip.trim() === ip) {
            state.clients = clients;
            renderClients();
            updateSectionVisibility();
        }
    } catch (error) {
        showToast(error.message, 'error');
    }
}

async function cancelDeployment() {
    if (!state.deploy.running || !state.deploy.jobId) return;
    const button = document.getElementById('cancel-deploy-btn');
    button.disabled = true;
    try {
        await api(`/api/deploy/cancel/${state.deploy.jobId}`, { method: 'POST' });
    } catch (error) {
        button.disabled = !state.deploy.running;
        showToast(error.message, 'error');
    }
}

// Status dot in header
function updateStatusDot(running) {
    const dot = document.getElementById('status-dot');
    if (running) {
        dot.style.color = 'var(--accent)';
        dot.classList.add('status-dot-pulse');
    } else {
        dot.style.color = 'var(--text-dim)';
        dot.classList.remove('status-dot-pulse');
    }
}

// Modal functions
function openModal(id) {
    showElement(id);
    document.body.style.overflow = 'hidden';
}

function closeModal(id) {
    hideElement(id);
    document.body.style.overflow = '';
}

function openAddClientModal() {
    document.getElementById('new-client-label').value = '';
    openModal('add-client-modal');
}

function openRenameClientModal(clientId) {
    state.selectedClientId = clientId;
    const client = state.clients.find(c => c.id === clientId);
    if (client) {
        document.getElementById('rename-client-label').value = client.label;
        openModal('rename-client-modal');
    }
}

function openDeleteClientModal(clientId) {
    state.selectedClientId = clientId;
    const client = state.clients.find(c => c.id === clientId);
    if (client) {
        document.getElementById('delete-client-name').textContent = client.label;
        openModal('delete-client-modal');
    }
}

async function openViewConfigModal(clientId) {
    state.selectedClientId = clientId;
    const client = state.clients.find(c => c.id === clientId);
    if (client) {
        const container = document.getElementById('config-urls');
        container.innerHTML = '';
        const token = clientToken(client);
        document.getElementById('subscription-url').textContent = subscriptionUrl(client);
        document.getElementById('routing-summary').textContent = state.routing.ruDirect
            ? 'Xray JSON включает: private → direct, category-ru/geoip:ru → direct, остальное → VPN.'
            : 'Xray JSON включает локальную сеть и пользовательские direct-домены.';
        
        try {
            // Get subscription URLs from backend
            const response = await fetch(`/api/sub/${token}`);
            if (!response.ok) throw new Error('Failed to fetch subscription');
            const subscription = decodeSubscription(await response.text());
            const urls = subscription.split('\n').filter(url => url.trim());
            
            urls.forEach(url => {
                const urlDiv = document.createElement('div');
                urlDiv.className = 'text-xs break-all p-2 rounded';
                urlDiv.style.backgroundColor = 'var(--bg-terminal)';
                urlDiv.textContent = url;
                container.appendChild(urlDiv);
            });
            
            openModal('view-config-modal');
        } catch (error) {
            console.error('Failed to load client config:', error);
            showToast('Failed to load client configuration', 'error');
        }
    }
}

// Client operations
async function addClient() {
    const label = document.getElementById('new-client-label').value.trim();
    if (!label) {
        showToast('Label is required', 'error');
        return;
    }
    
    try {
        const newClient = await api('/api/clients', {
            method: 'POST',
            body: { ip: state.vps.ip, label }
        });
        
        state.clients.push(newClient);
        renderClients();
        updateSectionVisibility();
        saveState();
        closeModal('add-client-modal');
        showToast('Клиент добавлен локально. Нажмите DEPLOY, чтобы отправить его на VPS.', 'success');
    } catch (error) {
        console.error('Failed to add client:', error);
        showToast(error.message, 'error');
    }
}

async function renameClient() {
    const label = document.getElementById('rename-client-label').value.trim();
    if (!label) {
        showToast('Label is required', 'error');
        return;
    }
    
    try {
        const updatedClient = await api(`/api/clients/${state.selectedClientId}`, {
            method: 'PATCH',
            body: { ip: state.vps.ip, label }
        });
        
        const client = state.clients.find(c => c.id === state.selectedClientId);
        if (client) {
            Object.assign(client, updatedClient);
            renderClients();
            saveState();
        }
        closeModal('rename-client-modal');
        showToast('Клиент переименован. Нажмите DEPLOY, чтобы обновить VPS.', 'success');
    } catch (error) {
        console.error('Failed to rename client:', error);
        showToast(error.message, 'error');
    }
}

async function deleteClient() {
    try {
        await api(`/api/clients/${state.selectedClientId}?ip=${encodeURIComponent(state.vps.ip)}`, {
            method: 'DELETE'
        });
        
        state.clients = state.clients.filter(c => c.id !== state.selectedClientId);
        renderClients();
        updateSectionVisibility();
        saveState();
        closeModal('delete-client-modal');
        showToast('Клиент удалён локально. Нажмите DEPLOY, чтобы обновить VPS.', 'success');
    } catch (error) {
        console.error('Failed to delete client:', error);
        showToast(error.message, 'error');
    }
}

// Utility functions
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).catch(err => {
        console.error('Failed to copy:', err);
    });
}

// File input handling
function handleFileSelect(inputId, statusId) {
    const input = document.getElementById(inputId);
    const status = document.getElementById(statusId);
    
    input.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            status.textContent = `✓ ${file.name}`;
            status.style.color = 'var(--success)';
        } else {
            status.textContent = '';
        }
    });
}

// Password toggle
function setupPasswordToggles() {
    document.querySelectorAll('.password-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.target;
            const input = document.getElementById(targetId);
            if (input.type === 'password') {
                input.type = 'text';
                btn.innerHTML = '<i data-lucide="eye-off" class="w-4 h-4"></i>';
            } else {
                input.type = 'password';
                btn.innerHTML = '<i data-lucide="eye" class="w-4 h-4"></i>';
            }
            initIcons();
        });
    });
}

// Form input handling
function setupFormInputs() {
    // Text inputs
    document.querySelectorAll('.input-field').forEach(input => {
        input.addEventListener('input', (e) => {
            const field = e.target.dataset.field;
            if (field) {
                const parts = field.split('.');
                if (parts.length === 2) {
                    state[parts[0]][parts[1]] = e.target.value;
                }
                if (e.target.hasAttribute('aria-invalid')) clearFormError();
                saveState();
            }
        });
    });
    
    // Checkboxes (protocols)
    document.querySelectorAll('#proto-hysteria2, #proto-vless, #proto-openflux').forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            const field = e.target.dataset.field;
            if (field) {
                const parts = field.split('.');
                if (parts.length === 2) {
                    state[parts[0]][parts[1]] = e.target.checked;
                }
                if (e.target.hasAttribute('aria-invalid')) clearFormError();
                updateSectionVisibility();
                saveState();
            }
        });
    });

    document.querySelectorAll('#routing-ru-direct, #routing-private-direct').forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            const parts = e.target.dataset.field.split('.');
            state[parts[0]][parts[1]] = e.target.checked;
            saveState();
        });
    });
    
    // Radio buttons
    document.querySelectorAll('input[type="radio"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            const field = e.target.dataset.field;
            if (field) {
                const parts = field.split('.');
                if (parts.length === 2) {
                    state[parts[0]][parts[1]] = e.target.value;
                }
                
                // Handle special cases
                if (field === 'vps.auth') {
                    updateAuthFields();
                }
                if (field === 'openflux.transport') {
                    updateOpenFluxFields();
                }
                if (field === 'openflux.mode') {
                    updateOpenFluxFields();
                }
                if (field === 'certs.source') {
                    updateCertificateFields();
                }
                
                saveState();
            }
        });
    });
}

// Event listeners
function setupEventListeners() {
    // Deploy button
    document.getElementById('forge-btn').addEventListener('click', () => {
        startDeployment();
    });
    
    document.getElementById('status-btn').addEventListener('click', focusJournal);
    document.querySelectorAll('[data-deploy-mode]').forEach(button => {
        button.addEventListener('click', () => switchMode(button.dataset.deployMode));
    });
    document.getElementById('demo-fill-btn').addEventListener('click', fillDemo);
    document.getElementById('help-btn').addEventListener('click', () => openModal('help-modal'));
    document.getElementById('openflux-client-btn').addEventListener('click', async () => {
        if (!state.vps.ip) {
            showToast('Сначала укажите VPS и нажмите DEPLOY.', 'error');
            return;
        }
        try {
            const setup = await api(`/api/openflux/client?ip=${encodeURIComponent(state.vps.ip)}`);
            document.getElementById('openflux-client-command').textContent = setup.command;
            document.getElementById('openflux-client-key').textContent = setup.encryption_key || 'шифрование выключено';
            showElement('openflux-client-output');
        } catch (error) {
            showToast(error.message, 'error');
        }
    });
    
    document.getElementById('cancel-deploy-btn').addEventListener('click', cancelDeployment);
    
    document.getElementById('copy-log-btn').addEventListener('click', () => {
        const logs = state.deploy.logs.join('\n');
        copyToClipboard(logs);
        showToast('Log copied to clipboard', 'success');
    });
    
    document.getElementById('download-log-btn').addEventListener('click', () => {
        const logs = state.deploy.logs.join('\n');
        const blob = new Blob([logs], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `deploy-${state.deploy.jobId}.log`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('Log downloaded', 'success');
    });
    
    // Client buttons
    document.getElementById('add-client-btn').addEventListener('click', openAddClientModal);
    document.getElementById('confirm-add-client-btn').addEventListener('click', addClient);
    document.getElementById('confirm-rename-client-btn').addEventListener('click', renameClient);
    document.getElementById('confirm-delete-client-btn').addEventListener('click', deleteClient);
    
    // Modal close buttons
    document.querySelectorAll('.modal-close-btn, .modal-cancel-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const modalId = btn.dataset.modal;
            closeModal(modalId);
        });
    });
    
    // Copy config button
    document.getElementById('copy-config-btn').addEventListener('click', () => {
        const client = state.clients.find(c => c.id === state.selectedClientId);
        if (!client) return;
        copyToClipboard(subscriptionUrl(client));
        showToast('Ссылка подписки скопирована.', 'success');
    });

    document.getElementById('download-xray-btn').addEventListener('click', () => {
        const client = state.clients.find(c => c.id === state.selectedClientId);
        if (!client) return;
        if (!state.protocols.vless_reality) {
            showToast('Xray JSON доступен только при включённом VLESS Reality.', 'error');
            return;
        }
        const link = document.createElement('a');
        link.href = `/api/config/${clientToken(client)}/xray.json`;
        link.download = `bypass-${client.label}-xray.json`;
        link.click();
    });
    
    // Validate cert button
    document.getElementById('validate-cert-btn').addEventListener('click', async () => {
        const certInput = document.getElementById('cert-file');
        const keyInput = document.getElementById('key-file');
        
        if (certInput.files.length === 0 || keyInput.files.length === 0) {
            showToast('Please select both certificate and key files', 'error');
            return;
        }
        
        try {
            const formData = new FormData();
            formData.append('fullchain', certInput.files[0]);
            formData.append('privkey', keyInput.files[0]);
            formData.append('domain', state.dns.sub && state.dns.root ? `${state.dns.sub}.${state.dns.root}` : null);
            
            const certInfo = await api('/api/cert/validate', { method: 'POST', form: formData });
            state.certs.info = certInfo;
            showToast('Certificate validated successfully', 'success');
        } catch (error) {
            console.error('Certificate validation failed:', error);
            showToast(error.message, 'error');
        }
    });
    
    // File inputs
    handleFileSelect('cert-file', 'cert-status');
    handleFileSelect('key-file', 'key-status');
    
    // File select buttons
    document.querySelectorAll('.file-select-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.target;
            document.getElementById(targetId).click();
        });
    });
    
    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal:not(.hidden)').forEach(modal => {
                closeModal(modal.id);
            });
        }
    });
}

// Initialize form from state
function initFormFromState() {
    // Protocols
    document.getElementById('proto-hysteria2').checked = state.protocols.hysteria2;
    document.getElementById('proto-vless').checked = state.protocols.vless_reality;
    document.getElementById('proto-openflux').checked = state.protocols.openflux;
    
    // VPS
    document.getElementById('vps-ip').value = state.vps.ip;
    document.getElementById('vps-port').value = state.vps.port;
    document.getElementById('vps-user').value = state.vps.user;
    document.getElementById('vps-keypath').value = state.vps.keyPath;
    document.getElementById('vps-password').value = state.vps.password;
    
    // Auth radio
    document.querySelector(`input[name="auth"][value="${state.vps.auth}"]`).checked = true;
    
    // Runtime radio
    document.querySelector(`input[name="runtime"][value="${state.vps.runtime}"]`).checked = true;
    
    // DNS
    document.getElementById('dns-cftoken').value = state.dns.cfToken;
    document.getElementById('dns-root').value = state.dns.root;
    document.getElementById('dns-sub').value = state.dns.sub;
    document.querySelector(`input[name="certificate-source"][value="${state.certs.source}"]`).checked = true;
    document.getElementById('cert-vps-fullchain').value = state.certs.vpsFullchainPath;
    document.getElementById('cert-vps-privkey').value = state.certs.vpsPrivkeyPath;
    
    // OpenFlux
    document.querySelectorAll('input[name="transport"]').forEach(input => {
        input.checked = input.value === state.openflux.transport;
    });
    document.getElementById('openflux-enckey').value = state.openflux.encKey || '';
    document.getElementById('openflux-yandex').value = state.openflux.yandexUrl || '';
    document.getElementById('openflux-maxtoken').value = state.openflux.maxToken || '';
    document.getElementById('openflux-maxuid').value = state.openflux.maxUid || '';
    if (state.openflux.mode) {
        document.querySelector(`input[name="openflux-mode"][value="${state.openflux.mode}"]`).checked = true;
    }
    document.getElementById('openflux-localip').value = state.openflux.localIp || '';
    document.querySelector(`input[name="openflux-codec"][value="${state.openflux.codec || 'batched'}"]`).checked = true;

    document.getElementById('routing-ru-direct').checked = state.routing.ruDirect;
    document.getElementById('routing-private-direct').checked = state.routing.privateDirect;
    document.getElementById('routing-custom-domains').value = state.routing.customDirectDomains;
    
    updateAuthFields();
    updateCertificateFields();
    updateOpenFluxFields();
    updateSectionVisibility();
}

// Initialize app
function init() {
    loadState();
    initIcons();
    initFormFromState();
    setupFormInputs();
    setupPasswordToggles();
    setupEventListeners();
    
    updateDeployControls();

    renderClients();
    renderServices();
    
    // Initialize header stats
    const clientCount = document.getElementById('client-count');
    const nodeCount = document.getElementById('node-count');
    if (clientCount) clientCount.textContent = state.clients.length;
    if (nodeCount) nodeCount.textContent = state.vps.ip ? '1' : '0';
    
    console.log('bypass UI initialized (backend integration mode)');
}

// Start app when DOM is ready
document.addEventListener('DOMContentLoaded', init);
