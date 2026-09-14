// VPN-Forge Frontend - JARVIS-style UI
// Mock implementation without backend integration

// State management
const state = {
    protocols: { hysteria2: false, vless_reality: false, openflux: false },
    vps: { ip: '', port: 22, user: 'root', auth: 'key', keyPath: '', password: '', runtime: 'native' },
    dns: { cfToken: '', root: '', sub: '' },
    certs: { fullchainPath: '', privkeyPath: '', info: null },
    openflux: { transport: null, yandexUrl: '', maxToken: '', maxUid: '', encKey: '' },
    deploy: { jobId: null, running: false, stages: {}, logs: [] },
    clients: [],
    services: {},
    theme: 'dark',
    selectedClientId: null
};

// Mock data for testing
const mockClients = [
    { id: '1', label: 'Vasya', protocols: 'VLESS+Hy2', subToken: '7f3a9b2c', disabled: false },
    { id: '2', label: 'Petya', protocols: 'VLESS+Hy2', subToken: '9d4e8f1a', disabled: false }
];

const mockServices = {
    'xray.service': { status: 'active' },
    'hysteria.service': { status: 'active' },
    'vpnforge-sub.service': { status: 'active' },
    'openflux.service': { status: 'inactive' }
};

// Initialize Lucide icons
function initIcons() {
    lucide.createIcons();
}

// LocalStorage helpers
function saveState() {
    const toSave = { ...state };
    delete toSave.deploy; // Don't save deploy state
    delete toSave.services; // Don't save services (fetched from server)
    localStorage.setItem('vpnforge-state', JSON.stringify(toSave));
}

function loadState() {
    const saved = localStorage.getItem('vpnforge-state');
    if (saved) {
        try {
            const parsed = JSON.parse(saved);
            Object.assign(state, parsed);
        } catch (e) {
            console.error('Failed to load state:', e);
        }
    }
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

// Section visibility based on protocols
function updateSectionVisibility() {
    const { hysteria2, openflux } = state.protocols;
    
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

// OpenFlux transport fields
function updateOpenFluxFields() {
    const transport = state.openflux.transport;
    hideElement('yandex-url-group');
    hideElement('oneme-group');
    
    if (transport === 'yandex') {
        showElement('yandex-url-group');
    } else if (transport === 'oneme') {
        showElement('oneme-group');
    }
}

// Render clients
function renderClients() {
    const container = document.getElementById('clients-list');
    container.innerHTML = '';
    
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
        protocols.textContent = client.protocols;
        
        const sub = document.createElement('span');
        sub.className = 'client-sub';
        sub.textContent = `/sub/${client.subToken.substring(0, 8)}…`;
        
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
            copyToClipboard(`http://127.0.0.1:8000/api/sub/${client.subToken}`);
            showToast('Copied.', 'success');
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
    
    Object.entries(state.services).forEach(([name, service]) => {
        const row = document.createElement('div');
        row.className = 'service-row';
        
        const status = document.createElement('span');
        status.className = 'service-status';
        status.textContent = '●';
        
        if (service.status === 'active') {
            status.style.color = 'var(--success)';
            status.classList.add('status-dot-pulse');
        } else if (service.status === 'failed') {
            status.style.color = 'var(--error)';
        } else {
            status.style.color = 'var(--text-dim)';
        }
        
        const serviceName = document.createElement('span');
        serviceName.className = 'service-name';
        serviceName.textContent = name;
        
        const stateText = document.createElement('span');
        stateText.className = 'service-state';
        stateText.textContent = service.status;
        
        row.appendChild(status);
        row.appendChild(serviceName);
        row.appendChild(stateText);
        
        container.appendChild(row);
    });
}

// Deployment overlay
function openDeployOverlay() {
    showElement('deploy-overlay');
    document.body.style.overflow = 'hidden';
}

function closeDeployOverlay() {
    hideElement('deploy-overlay');
    document.body.style.overflow = '';
}

// Update stages in overlay
function updateStages() {
    const stages = ['apt', 'runtime', 'xray', 'hysteria', 'sub', 'verify'];
    stages.forEach(stage => {
        const element = document.querySelector(`.stage[data-stage="${stage}"]`);
        if (!element) return;
        
        const icon = element.querySelector('.stage-icon');
        const status = state.deploy.stages[stage];
        
        element.classList.remove('running', 'done', 'failed');
        
        if (status === 'running') {
            element.classList.add('running');
            icon.textContent = '◐';
        } else if (status === 'done') {
            element.classList.add('done');
            icon.textContent = '✓';
        } else if (status === 'failed') {
            element.classList.add('failed');
            icon.textContent = '✗';
        } else {
            icon.textContent = '○';
        }
    });
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

// Mock deployment process
function startMockDeployment() {
    state.deploy.running = true;
    state.deploy.jobId = 'mock-' + Date.now();
    state.deploy.stages = {};
    state.deploy.logs = [];
    
    clearTerminal();
    openDeployOverlay();
    updateStatusDot(true);
    
    const stages = [
        { name: 'apt', duration: 1000 },
        { name: 'runtime', duration: 1500 },
        { name: 'xray', duration: 2000 },
        { name: 'hysteria', duration: 1500 },
        { name: 'sub', duration: 1000 },
        { name: 'verify', duration: 800 }
    ];
    
    let currentIndex = 0;
    
    function runNextStage() {
        if (currentIndex >= stages.length) {
            completeDeployment(true);
            return;
        }
        
        const stage = stages[currentIndex];
        state.deploy.stages[stage.name] = 'running';
        updateStages();
        addLogLine(`▸ ${stage.name} - starting...`);
        
        // Simulate log output
        const mockLogs = [
            `TASK [${stage.name} : setup] ***`,
            `ok: [${state.vps.ip || '1.2.3.4'}]`,
            `changed: [${state.vps.ip || '1.2.3.4'}]`
        ];
        
        let logIndex = 0;
        const logInterval = setInterval(() => {
            if (logIndex < mockLogs.length) {
                addLogLine(mockLogs[logIndex]);
                logIndex++;
            } else {
                clearInterval(logInterval);
            }
        }, 300);
        
        setTimeout(() => {
            clearInterval(logInterval);
            state.deploy.stages[stage.name] = 'done';
            updateStages();
            addLogLine(`▸ ${stage.name} - done`, 'success');
            currentIndex++;
            runNextStage();
        }, stage.duration);
    }
    
    runNextStage();
}

function completeDeployment(success) {
    state.deploy.running = false;
    updateStatusDot(false);
    
    if (success) {
        addLogLine('✓ Node forged.', 'success');
        document.getElementById('app').classList.add('flash-success');
        setTimeout(() => {
            document.getElementById('app').classList.remove('flash-success');
        }, 1000);
        
        // Add mock clients and services
        state.clients = [...mockClients];
        state.services = { ...mockServices };
        renderClients();
        renderServices();
        updateSectionVisibility();
        saveState();
        
        showToast('Node forged successfully!', 'success');
    } else {
        addLogLine('✗ Deploy failed.', 'error');
        document.getElementById('app').classList.add('flash-error');
        setTimeout(() => {
            document.getElementById('app').classList.remove('flash-error');
        }, 1000);
        
        showToast('Deploy failed.', 'error');
    }
}

function cancelDeployment() {
    if (!state.deploy.running) return;
    
    state.deploy.running = false;
    addLogLine('▸ Deployment cancelled.', 'warning');
    updateStatusDot(false);
    
    // Reset stages
    Object.keys(state.deploy.stages).forEach(stage => {
        state.deploy.stages[stage] = 'failed';
    });
    updateStages();
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

function openViewConfigModal(clientId) {
    state.selectedClientId = clientId;
    const client = state.clients.find(c => c.id === clientId);
    if (client) {
        const container = document.getElementById('config-urls');
        container.innerHTML = '';
        
        // Mock URLs
        const urls = [
            `vless://uuid-v4@${state.vps.ip || '1.2.3.4'}:443?type=xhttp&security=reality&pbk=test&fp=chrome&sni=www.microsoft.com&sid=deadbeef&path=/&mode=packet-up#${client.label}`,
            `hysteria2://user:pass@${state.dns.sub ? state.dns.sub + '.' + state.dns.root : 'node1.example.com'}:443?sni=${state.dns.sub ? state.dns.sub + '.' + state.dns.root : 'node1.example.com'}&insecure=0&obfs=salamander&obfs-password=test#${client.label}`
        ];
        
        urls.forEach(url => {
            const urlDiv = document.createElement('div');
            urlDiv.className = 'text-xs break-all p-2 bg-terminal rounded';
            urlDiv.textContent = url;
            container.appendChild(urlDiv);
        });
        
        openModal('view-config-modal');
    }
}

// Client operations
function addClient() {
    const label = document.getElementById('new-client-label').value.trim();
    if (!label) {
        showToast('Label is required', 'error');
        return;
    }
    
    const newClient = {
        id: Date.now().toString(),
        label: label,
        protocols: 'VLESS+Hy2',
        subToken: Math.random().toString(16).substring(2, 10),
        disabled: false
    };
    
    state.clients.push(newClient);
    renderClients();
    updateSectionVisibility();
    saveState();
    closeModal('add-client-modal');
    showToast('Client added.', 'success');
}

function renameClient() {
    const label = document.getElementById('rename-client-label').value.trim();
    if (!label) {
        showToast('Label is required', 'error');
        return;
    }
    
    const client = state.clients.find(c => c.id === state.selectedClientId);
    if (client) {
        client.label = label;
        renderClients();
        saveState();
        closeModal('rename-client-modal');
        showToast('Client renamed.', 'success');
    }
}

function deleteClient() {
    state.clients = state.clients.filter(c => c.id !== state.selectedClientId);
    renderClients();
    updateSectionVisibility();
    saveState();
    closeModal('delete-client-modal');
    showToast('Client deleted.', 'success');
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
                updateSectionVisibility();
                saveState();
            }
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
                
                saveState();
            }
        });
    });
}

// Event listeners
function setupEventListeners() {
    // Forge button
    document.getElementById('forge-btn').addEventListener('click', () => {
        // Validate at least one protocol
        if (!state.protocols.hysteria2 && !state.protocols.vless_reality && !state.protocols.openflux) {
            showToast('At least one protocol must be enabled', 'error');
            return;
        }
        
        // Validate VPS IP
        if (!state.vps.ip) {
            showToast('VPS IP is required', 'error');
            return;
        }
        
        startMockDeployment();
    });
    
    // Status button
    document.getElementById('status-btn').addEventListener('click', () => {
        if (state.deploy.running || state.deploy.logs.length > 0) {
            openDeployOverlay();
        } else {
            showToast('No deployment in progress', 'info');
        }
    });
    
    // Overlay controls
    document.getElementById('close-overlay-btn').addEventListener('click', closeDeployOverlay);
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
        const urls = document.getElementById('config-urls').innerText;
        copyToClipboard(urls);
        showToast('Config copied to clipboard', 'success');
    });
    
    // Validate cert button (mock)
    document.getElementById('validate-cert-btn').addEventListener('click', () => {
        showToast('Certificate validated successfully', 'success');
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
            closeDeployOverlay();
            document.querySelectorAll('.modal:not(.hidden)').forEach(modal => {
                closeModal(modal.id);
            });
        }
        
        if (e.key === 'Enter' && !e.target.matches('input, textarea')) {
            document.getElementById('forge-btn').click();
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
    
    // OpenFlux
    if (state.openflux.transport) {
        document.querySelector(`input[name="transport"][value="${state.openflux.transport}"]`).checked = true;
        document.getElementById('openflux-yandex').value = state.openflux.yandexUrl;
        document.getElementById('openflux-maxtoken').value = state.openflux.maxToken;
        document.getElementById('openflux-maxuid').value = state.openflux.maxUid;
    }
    
    updateAuthFields();
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
    renderClients();
    renderServices();
    
    console.log('VPN-Forge UI initialized (mock mode)');
}

// Start app when DOM is ready
document.addEventListener('DOMContentLoaded', init);