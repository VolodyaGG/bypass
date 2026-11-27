"""Exercise the real browser script with a small DOM and storage substitute."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

BOOTSTRAP = r"""
const elements = new Map(), stored = new Map();
let focused = null;
class Element {
    constructor(id = '') {
        this.id = id; this.dataset = {}; this.style = {}; this.children = [];
        this.files = []; this.attributes = {}; this.textContent = '';
        const classes = new Set();
        this.classList = {
            add: x => classes.add(x), remove: x => classes.delete(x),
            contains: x => classes.has(x),
            toggle: (x, force) => {
                const active = force ?? !classes.has(x);
                if (active) classes.add(x); else classes.delete(x);
            }
        };
    }
    addEventListener() {}
    setAttribute(k, v) { this.attributes[k] = v; }
    getAttribute(k) { return this.attributes[k]; }
    removeAttribute(k) { delete this.attributes[k]; }
    hasAttribute(k) { return k in this.attributes; }
    appendChild(child) { this.children.push(child); }
    replaceChildren(...children) { this.children = children; }
    closest() { return null; }
    focus() { focused = this.id; }
    scrollIntoView() {}
}
const document = {
    getElementById(id) {
        if (!elements.has(id)) elements.set(id, new Element(id));
        return elements.get(id);
    },
    querySelector(selector) {
        if (selector === '[data-target="cert-file"]')
            return this.getElementById('select-cert-file');
        if (selector === '[data-target="key-file"]') return this.getElementById('select-key-file');
        return this.getElementById(selector);
    },
    querySelectorAll() { return []; },
    createElement() { return new Element(); },
    addEventListener() {}, body: new Element()
};
document.getElementById('app').dataset.profile = 'Demo';
const localStorage = {
    getItem: key => stored.get(key) ?? null,
    setItem: (key, value) => stored.set(key, value)
};
const console = {warn() {}, error() {}, log() {}};
class EventSource {
    static CLOSED = 2;
    static instances = [];
    constructor(url) {
        this.url = url; this.readyState = 1; this.handlers = {};
        EventSource.instances.push(this);
    }
    addEventListener(name, callback) { this.handlers[name] = callback; }
    close() { this.closed = true; }
    send(name, value) { this.handlers[name]({data: JSON.stringify(value)}); }
}
"""

CHECKS = r"""
function assert(value, message) { if (!value) throw new Error(message); }
function reset() {
    stored.clear(); focused = null; lastDemo = null; deployMode = 'demo';
    formGroups.forEach(group => { state[group] = {...formDefaults[group]}; });
    workspaceForms.demo = Object.fromEntries(formGroups.map(g => [g, {...formDefaults[g]}]));
    state.deploy = {jobId: null, running: false, stages: {}, logs: [], mode: 'demo'};
    state.clients = []; state.services = {};
}
reset();
stored.set('vpnforge-state', '{broken');
stored.set(demoStorageKey(), JSON.stringify({
    ip: '203.0.113.10', runtime: 'docker', domain: 'vpn.example.test',
    protocols: {hysteria2: true},
    last: {ip: '203.0.113.10', status: 'success', finishedAt: '2026-11-21T10:00:00Z'}
}));
loadState();
assert(state.vps.ip === '203.0.113.10', 'bad real JSON must not hide demo');
assert(lastDemo.status === 'success', 'last result must survive reload');
assert(state.vps.runtime === 'docker', 'runtime must survive reload');

reset();
stored.set('vpnforge-state', JSON.stringify({
    vps: {ip: '192.0.2.1', port: '2222', password: 'old-secret', auth: 'invalid'},
    dns: {root: 'example.co.uk', sub: 'deep.vpn', cfToken: 'old-token'},
    certs: {source: 'invalid'},
    protocols: {hysteria2: true, vless_reality: 'false', extra: true},
    openflux: {transport: 'yandex', mode: 'raw', encKey: 'old-key'}
}));
stored.set(demoStorageKey(), JSON.stringify({root: 'example.test', sub: 'demo'}));
loadState();
assert(state.dns.domain === 'demo.example.test', 'migrate demo domain');
deployMode = 'real'; Object.assign(state, workspaceForms.real);
assert(state.dns.domain === 'deep.vpn.example.co.uk', 'migrate real domain');
assert(state.vps.port === 2222 && state.vps.auth === 'key', 'restore valid port and safe auth');
assert(state.certs.source === 'letsencrypt', 'invalid certificate source must use default');
assert(state.openflux.transport === 'yandex' && state.openflux.mode === 'l3',
    'restore transport and legacy mode');
assert(!state.vps.password && !state.dns.cfToken && !state.openflux.encKey,
    'never restore old credentials');
assert(state.protocols.vless_reality === false && !('extra' in state.protocols),
    'only known typed fields');
state.vps.password = 'password'; state.dns.cfToken = 'token'; state.openflux.encKey = 'key';
saveState();
const safe = JSON.parse(stored.get('vpnforge-state'));
assert(!safe.vps.password && !safe.dns.cfToken && !safe.openflux.encKey,
    'never persist credentials');

reset(); loadState();
startDeployment();
assert(focused === 'vps-ip' && !state.deploy.running, 'focus empty target');
state.vps.ip = '203.0.113.10';
startDeployment();
assert(focused === 'proto-hysteria2' && !state.deploy.running, 'focus missing protocol');
deployMode = 'real'; state.protocols.hysteria2 = true;
state.dns.domain = 'vpn.example.test'; state.vps.port = 0;
startDeployment();
assert(focused === 'vps-port', 'focus invalid port');
state.vps.port = 22; state.certs.source = 'upload';
startDeployment();
assert(focused === 'select-cert-file', 'focus certificate selection button');
state.protocols.hysteria2 = false; state.protocols.openflux = true;
startDeployment();
assert(focused === 'transport-cups', 'focus missing transport');

reset();
state.deploy = {jobId: 'demo-job', running: true,
    stages: {}, logs: [], mode: 'demo', ip: '203.0.113.10'};
connectToStream('demo-job');
const stream = EventSource.instances.at(-1);
stream.readyState = 0; stream.send('error');
assert(state.deploy.running && !stream.closed,
    'network error must reconnect without marking task failed');
assert(document.getElementById('deploy-status').textContent.includes('Восстанавливаем'),
    'explain reconnect');
stream.readyState = 1; stream.send('open');
stream.send('log', {line: 'demo stage'});
stream.send('done', {status: 'success', error: null});
assert(stream.closed && !state.deploy.running && lastDemo.status === 'success',
    'actual completion must persist');
const count = state.deploy.logs.length;
completeDeployment('failed', 'late callback');
assert(state.deploy.logs.length === count && lastDemo.status === 'success',
    'ignore duplicate completion');

reset();
state.deploy = {jobId: 'lost-job', running: true,
    stages: {}, logs: [], mode: 'demo', ip: '203.0.113.10'};
connectToStream('lost-job');
const lost = EventSource.instances.at(-1);
lost.readyState = EventSource.CLOSED; lost.send('error');
assert(!state.deploy.running && lastDemo.status === 'interrupted',
    'closed journal means unknown outcome');
"""


def test_frontend_storage_validation_and_stream_recovery(tmp_path: Path) -> None:
    source = (Path(__file__).parents[1] / "vpnforge/web/static/app.js").read_text()
    script = BOOTSTRAP + source + CHECKS
    node = shutil.which("node")
    if node:
        command = [node]
    elif sys.platform == "darwin" and shutil.which("swift"):
        runner = tmp_path / "evaluate.swift"
        runner.write_text('''
import Foundation
import JavaScriptCore
let context = JSContext()!
var failed = false
context.exceptionHandler = { _, exception in
    failed = true
    fputs("\\(exception!.toString()!)\\n", stderr)
}
let input = FileHandle.standardInput.readDataToEndOfFile()
context.evaluateScript(String(data: input, encoding: .utf8)!)
if failed { exit(1) }
''')
        command = ["swift", "-module-cache-path", str(tmp_path / "cache"), str(runner)]
    else:
        pytest.skip("Frontend checks require Node.js or macOS JavaScriptCore with Swift")
    result = subprocess.run(command, input=script, text=True, capture_output=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
