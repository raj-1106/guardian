const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { HOME, PIDFILE, DIR, rules, log, alert, quarantine } = require('./util');

fs.mkdirSync(DIR, { recursive: true });
fs.writeFileSync(PIDFILE, String(process.pid));
const cfg = rules();
const fileRes = cfg.suspiciousFilePatterns.map((p) => new RegExp(p, 'i'));
const folderRes = cfg.suspiciousFolderPatterns.map((p) => new RegExp(p, 'i'));
const allowed = new Set(cfg.allowedDotFolders.map((s) => s.toLowerCase()));
const ignored = cfg.ignoredPathParts.map((s) => s.toLowerCase());
const seen = new Set();

function act(level, title, target, detail) {
  if (seen.has(target)) return;
  seen.add(target);
  let result = 'not removed';
  try { result = 'quarantined as ' + quarantine(target); } catch (e) { result = 'quarantine failed: ' + e.code; }
  alert(level, title, `${target}\n${detail}\n${result}`);
}

// ── File watcher: non-recursive on high-risk folders (a recursive watch on the whole
// profile overflows its buffer and drops events), plus a sweep every cycle as backstop ──
const APPDATA = process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming');
const watchDirs = [
  HOME, path.join(HOME, 'Downloads'), path.join(HOME, 'Desktop'), path.join(HOME, 'Documents'),
  APPDATA, path.join(HOME, 'AppData', 'Local', 'Temp'),
  path.join(APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
].filter((d) => fs.existsSync(d));

function onFile(full) {
  const low = full.toLowerCase();
  if (ignored.some((p) => low.includes(p))) return;
  if (!fileRes.some((r) => r.test(path.basename(full)))) return;
  setTimeout(() => { if (fs.existsSync(full)) act('CRITICAL', 'Suspicious file removed', full, 'Matched malware file pattern.'); }, 500);
}
for (const dir of watchDirs) {
  try { fs.watch(dir, (_e, f) => f && onFile(path.join(dir, f))).on('error', () => {}); }
  catch (e) { log('ERROR', `watch failed for ${dir}: ${e.message}`); }
}
function sweepFiles() {
  for (const dir of watchDirs) {
    let names = [];
    try { names = fs.readdirSync(dir); } catch { continue; }
    for (const n of names) onFile(path.join(dir, n));
  }
}

// ── Hidden dot-folder scan (top level of profile) ──
function scanFolders() {
  let entries = [];
  try { entries = fs.readdirSync(HOME, { withFileTypes: true }); } catch { return; }
  for (const d of entries) {
    if (!d.isDirectory() || !d.name.startsWith('.') || allowed.has(d.name.toLowerCase())) continue;
    const full = path.join(HOME, d.name);
    let reason = '';
    if (folderRes.some((r) => r.test(d.name))) reason = 'name matches known malware folder pattern';
    else {
      let files = [];
      try { files = fs.readdirSync(full); } catch { continue; }
      if (files.includes('node_modules') && files.some((f) => /\.vbs$/i.test(f))) reason = 'hidden folder with node_modules and a .vbs launcher';
    }
    if (reason) { killInFolder(full); act('CRITICAL', 'Hidden malware folder removed', full, reason); }
  }
}

// ── Process scan ──
const PS_LIST = "Get-CimInstance Win32_Process -Filter \"Name='node.exe' OR Name='wscript.exe' OR Name='cscript.exe'\" | Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress";
let procCache = [];
function listProcs(cb) {
  execFile('powershell.exe', ['-NoProfile', '-Command', PS_LIST], { windowsHide: true, maxBuffer: 8e6 }, (err, out) => {
    if (err || !out.trim()) return cb([]);
    try { const j = JSON.parse(out); cb(Array.isArray(j) ? j : [j]); } catch { cb([]); }
  });
}
function suspiciousProc(p) {
  const cmd = (p.CommandLine || '').toLowerCase();
  const home = HOME.toLowerCase();
  if (!cmd.includes(home)) return null;
  if (/wscript|cscript/.test(p.Name.toLowerCase()) && /\.vbs/.test(cmd)) return 'VBScript running from user profile';
  const m = cmd.replace(/\//g, '\\').match(new RegExp(home.replace(/\\/g, '\\\\') + '\\\\(\\.[^\\\\]+)\\\\'));
  if (m && !allowed.has(m[1]) && folderRes.some((r) => r.test(m[1]))) return 'node running from malware-style hidden folder';
  return null;
}
function killInFolder(folder) {
  for (const p of procCache) if ((p.CommandLine || '').toLowerCase().includes(folder.toLowerCase())) { try { process.kill(p.ProcessId); } catch {} }
}
function scanProcs() {
  listProcs((procs) => {
    procCache = procs;
    for (const p of procs) {
      const why = suspiciousProc(p);
      if (!why || seen.has('pid' + p.ProcessId)) continue;
      seen.add('pid' + p.ProcessId);
      let killed = false;
      try { process.kill(p.ProcessId); killed = true; } catch {}
      alert('CRITICAL', killed ? 'Malicious process killed' : 'Malicious process detected', `PID ${p.ProcessId} ${p.Name}\n${why}\n${p.CommandLine}`);
    }
  });
}

log('INFO', `Guardian started (PID ${process.pid})`);
scanFolders();
sweepFiles();
setInterval(() => { scanProcs(); scanFolders(); sweepFiles(); }, cfg.checkIntervalSeconds * 1000);
process.on('uncaughtException', (e) => log('ERROR', 'uncaught: ' + e.message));
