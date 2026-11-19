#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { PIDFILE, LOG, QUAR, notify } = require('../src/util');

const DAEMON = path.join(__dirname, '..', 'src', 'daemon.js');
const RUN_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
const cmd = process.argv[2];

function running() {
  try { process.kill(Number(fs.readFileSync(PIDFILE, 'utf8')), 0); return true; } catch { return false; }
}
function start() {
  if (running()) return console.log('already running');
  spawn(process.execPath, [DAEMON], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
  console.log('started (hidden background process)');
}
function stop() {
  try { process.kill(Number(fs.readFileSync(PIDFILE, 'utf8'))); console.log('stopped'); } catch { console.log('not running'); }
}
function manifest() {
  try { return fs.readFileSync(path.join(QUAR, 'manifest.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse); } catch { return []; }
}

switch (cmd) {
  case 'start': start(); break;
  case 'stop': stop(); break;
  case 'status': console.log(running() ? 'running' : 'stopped'); break;
  case 'install': // explicit opt-in autostart, no admin needed
    spawnSync('reg', ['add', RUN_KEY, '/v', 'SecurityGuardian', '/t', 'REG_SZ', '/f', '/d', `"${process.execPath}" "${DAEMON}"`], { stdio: 'inherit' });
    start(); console.log('autostart registered at every login'); break;
  case 'uninstall':
    spawnSync('reg', ['delete', RUN_KEY, '/v', 'SecurityGuardian', '/f'], { stdio: 'inherit' });
    stop(); break;
  case 'log': console.log(fs.existsSync(LOG) ? fs.readFileSync(LOG, 'utf8') : '(no alerts yet)'); break;
  case 'quarantine': manifest().forEach((m) => console.log(`${m.id}\n   from ${m.from}`)); break;
  case 'restore': {
    const m = manifest().find((x) => x.id === process.argv[3]);
    if (!m) { console.log('unknown id (see: guardian quarantine)'); process.exit(1); }
    fs.renameSync(path.join(QUAR, m.id), m.from); console.log('restored to ' + m.from); break;
  }
  case 'test-alert': notify('Test', 'If you see this, alerts work.'); break;
  default:
    console.log('guardian <start|stop|status|install|uninstall|log|quarantine|restore <id>|test-alert>');
}
