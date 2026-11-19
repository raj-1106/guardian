const { rules } = require('./util');

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function analyzeScript(script, cfg = rules()) {
  const hits = cfg.suspiciousScriptKeywords.filter((k) => new RegExp(`(^|[^\\w])${esc(k)}([^\\w]|$)`, 'i').test(script));
  const runs = /child_process|powershell|Start-Process|WScript\.Shell|\bexec\b|\bspawn\b/i.test(script);
  const fetches = /curl|wget|DownloadString|https?:\/\//i.test(script);
  return { hits, critical: runs && fetches };
}

// pkg = registry manifest for one version. Returns { critical: [], warnings: [] }.
function analyzePackage(pkg, cfg = rules()) {
  const critical = [], warnings = [];
  for (const s of cfg.installScripts) {
    const script = pkg.scripts && pkg.scripts[s];
    if (!script) continue;
    const r = analyzeScript(script, cfg);
    warnings.push(`has ${s} script: ${script}`);
    if (r.hits.length) warnings.push(`${s} uses: ${r.hits.join(', ')}`);
    if (r.critical) critical.push(`${s} script downloads AND executes code`);
  }
  const deps = Object.keys(pkg.dependencies || {});
  const has = (key) => deps.some((d) => new RegExp(cfg.riskyDependencyPatterns[key]).test(d));
  if (has('dpapi')) warnings.push('depends on a DPAPI package (Windows credential decryption)');
  if (has('koffi')) warnings.push('depends on koffi (native DLL calls)');
  if (has('dpapi') && (has('sqlite') || has('socketio')))
    critical.push('DPAPI + SQLite/socket.io dependencies: password-stealer pattern');
  for (const d of deps) if (cfg.knownMaliciousPackages.includes(d)) critical.push(`known malicious dependency: ${d}`);
  return { critical, warnings };
}

module.exports = { analyzeScript, analyzePackage };
