// VPN-Forge Frontend - JARVIS-style UI
// Backend integration

// State management
const state = {
    protocols: { hysteria2: false, vless_reality: false, openflux: false },
    vps: { ip: '', port: 22, user: 'root', auth: 'key', keyPath: '', password: '', runtime: 'native' },
    dns: { cfToken: '', root: '', sub: '' },
    certs: { fullchainPath: '', privkeyPath: '', info: null },
    openflux: { transport: null, mode: 'proxy', localIp: '', yandexUrl: '', maxToken: '', maxUid: '', encKey: '' },
    deploy: { jobId: null, running: false, stages: {}, logs: [] },
    clients: [],
    services: {},
    theme: 'dark',
    selectedClientId: null
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
    const mode = state.openflux.mode || 'proxy';
    hideElement('yandex-url-group');
    hideElement('oneme-group');
    hideElement('openflux-localip-group');
    
    if (mode === 'raw') {
        showElement('openflux-localip-group');
    }

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
        copyBtn.onclick = async (e) => {
            e.stopPropagation();
            try {
                const response = await fetch(`/api/sub/${client.subToken}`);
                if (!response.ok) throw new Error('Failed to fetch subscription');
                const subscription = await response.text();
                copyToClipboard(subscription);
                showToast('Copied.', 'success');
            } catch (error) {
                console.error('Failed to copy subscription:', error);
                showToast('Failed to copy subscription', 'error');
            }
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

// Real deployment process
async function startDeployment() {
    try {
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
        
        // Prepare deploy request
        const deployRequest = {
            ip: state.vps.ip,
            ssh_user: state.vps.user,
            ssh_port: state.vps.port,
            ssh_private_key_path: state.vps.auth === 'key' ? state.vps.keyPath : null,
            ssh_password: state.vps.auth === 'password' ? state.vps.password : null,
            domain: state.protocols.hysteria2 ? (state.dns.sub && state.dns.root ? `${state.dns.sub}.${state.dns.root}` : null) : null,
            root_domain: state.dns.root || null,
            protocols: state.protocols,
            runtime: state.vps.runtime,
            openflux: state.protocols.openflux ? {
                transport: state.openflux.transport,
                mode: state.openflux.mode || 'proxy',
                local_ip: state.openflux.localIp || null,
                yandex_url: state.openflux.yandexUrl || null,
                max_token: state.openflux.maxToken || null,
                max_uid: state.openflux.maxUid || null,
                encryption_key: state.openflux.encKey || null,
                debug: false,
            } : null,
            cf_api_token: state.dns.cfToken || null
        };
        
        // Prepare form data
        const formData = new FormData();
        formData.append('payload', JSON.stringify(deployRequest));
        
        // Add certificate files if Hysteria 2 is enabled
        if (state.protocols.hysteria2) {
            const certInput = document.getElementById('cert-file');
            const keyInput = document.getElementById('key-file');
            
            if (certInput.files.length > 0) {
                formData.append('fullchain', certInput.files[0]);
            }
            if (keyInput.files.length > 0) {
                formData.append('privkey', keyInput.files[0]);
            }
        }
        
        state.deploy.running = true;
        state.deploy.logs = [];
        clearTerminal();
        openDeployOverlay();
        updateStatusDot(true);
        
        // Start deployment
        const response = await api('/api/deploy', { method: 'POST', form: formData });
        state.deploy.jobId = response.job_id;
        
        // Connect to SSE stream
        connectToStream(response.job_id);
        
    } catch (error) {
        console.error('Deployment failed:', error);
        showToast(error.message, 'error');
        state.deploy.running = false;
        updateStatusDot(false);
    }
}

// SSE stream connection
function connectToStream(jobId) {
    const eventSource = new EventSource(`/api/deploy/stream/${jobId}`);
    
    eventSource.addEventListener('log', (e) => {
        const data = JSON.parse(e.data);
        addLogLine(data.line);
        state.deploy.logs.push(data.line);
    });
    
    eventSource.addEventListener('stage', (e) => {
        const data = JSON.parse(e.data);
        if (data.stage) {
            state.deploy.stages[data.stage] = data.status;
            updateStages();
        }
    });
    
    eventSource.addEventListener('done', (e) => {
        const data = JSON.parse(e.data);
        eventSource.close();
        completeDeployment(data.status === 'success');
    });
    
    eventSource.addEventListener('error', (e) => {
        eventSource.close();
        completeDeployment(false);
    });
    
    // Store for cleanup
    state.deploy.eventSource = eventSource;
}

async function completeDeployment(success) {
    state.deploy.running = false;
    updateStatusDot(false);
    
    if (success) {
        addLogLine('✓ Node forged.', 'success');
        document.getElementById('app').classList.add('flash-success');
        setTimeout(() => {
            document.getElementById('app').classList.remove('flash-success');
        }, 1000);
        
        // Load real clients from backend
        try {
            state.clients = await api(`/api/clients?ip=${state.vps.ip}`);
            renderClients();
            updateSectionVisibility();
            saveState();
        } catch (error) {
            console.error('Failed to load clients:', error);
        }
        
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

async function cancelDeployment() {
    if (!state.deploy.running || !state.deploy.jobId) return;
    
    try {
        await api(`/api/deploy/cancel/${state.deploy.jobId}`, { method: 'POST' });
        if (state.deploy.eventSource) {
            state.deploy.eventSource.close();
        }
        state.deploy.running = false;
        addLogLine('▸ Deployment cancelled.', 'warning');
        updateStatusDot(false);
        
        // Reset stages
        Object.keys(state.deploy.stages).forEach(stage => {
            state.deploy.stages[stage] = 'failed';
        });
        updateStages();
    } catch (error) {
        console.error('Failed to cancel deployment:', error);
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
        
        try {
            // Get subscription URLs from backend
            const response = await fetch(`/api/sub/${client.subToken}`);
            if (!response.ok) throw new Error('Failed to fetch subscription');
            const subscription = await response.text();
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
        showToast('Client added.', 'success');
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
        showToast('Client renamed.', 'success');
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
        showToast('Client deleted.', 'success');
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
        startDeployment();
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
    document.getElementById('copy-config-btn').addEventListener('click', async () => {
        try {
            const client = state.clients.find(c => c.id === state.selectedClientId);
            if (client) {
                const response = await fetch(`/api/sub/${client.subToken}`);
                if (!response.ok) throw new Error('Failed to fetch subscription');
                const subscription = await response.text();
                copyToClipboard(subscription);
                showToast('Config copied to clipboard', 'success');
            }
        } catch (error) {
            console.error('Failed to copy config:', error);
            showToast('Failed to copy config', 'error');
        }
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
        document.getElementById('openflux-enckey').value = state.openflux.encKey;
    }
    if (state.openflux.mode) {
        document.querySelector(`input[name="openflux-mode"][value="${state.openflux.mode}"]`).checked = true;
    }
    document.getElementById('openflux-localip').value = state.openflux.localIp || '';
    
    updateAuthFields();
    updateOpenFluxFields();
    updateSectionVisibility();
}

// Initialize app
async function init() {
    loadState();
    initIcons();
    initFormFromState();
    setupFormInputs();
    setupPasswordToggles();
    setupEventListeners();
    
    // Load clients from backend if VPS IP is set
    if (state.vps.ip) {
        try {
            state.clients = await api(`/api/clients?ip=${state.vps.ip}`);
        } catch (error) {
            console.error('Failed to load clients:', error);
            // Keep existing clients from localStorage if API fails
        }
    }
    
    renderClients();
    renderServices();
    
    // Initialize header stats
    const clientCount = document.getElementById('client-count');
    const nodeCount = document.getElementById('node-count');
    if (clientCount) clientCount.textContent = state.clients.length;
    if (nodeCount) nodeCount.textContent = state.vps.ip ? '1' : '0';
    
    console.log('VPN-Forge UI initialized (backend integration mode)');
}

// Start app when DOM is ready
document.addEventListener('DOMContentLoaded', init);