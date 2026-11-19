#!/usr/bin/env node
const { spawnSync } = require('child_process');
const readline = require('readline');
const { rules } = require('../src/util');
const { analyzePackage } = require('../src/scan');
const { typosquatOf } = require('../src/typosquat');

const args = process.argv.slice(2);
const cfg = rules();
const run = () => process.exit(spawnSync('npm', args, { stdio: 'inherit', shell: true }).status ?? 1);

function parseSpec(spec) {
  const at = spec.lastIndexOf('@');
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) };
  return { name: spec, version: '' };
}

async function fetchManifest({ name, version }) {
  const v = /^\d+\.\d+\.\d+$/.test(version) ? version : 'latest';
  const res = await fetch(`https://registry.npmjs.org/${name.replace('/', '%2F')}/${v}`, { signal: AbortSignal.timeout(8000) });
  return res.ok ? res.json() : null;
}

const ask = (q) => new Promise((r) => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question(q, (a) => { rl.close(); r(a); });
});

(async () => {
  const isInstall = ['install', 'i', 'add'].includes(args[0]);
  const specs = args.slice(1).filter((a) => !a.startsWith('-'));
  if (!isInstall || !specs.length) return run(); // plain npm / npm ci / bare install pass through

  let blocked = false, needsConfirm = false;
  for (const spec of specs) {
    const p = parseSpec(spec);
    console.log(`\n  checking ${spec}`);
    const bad = [], warn = [];
    if (cfg.knownMaliciousPackages.includes(p.name)) bad.push('known malicious package');
    const squat = typosquatOf(p.name);
    if (squat) warn.push(`name is one typo away from popular package '${squat}'`);
    let manifest = null;
    try { manifest = await fetchManifest(p); } catch {}
    if (manifest) {
      const r = analyzePackage(manifest, cfg);
      bad.push(...r.critical);
      warn.push(...r.warnings);
    } else warn.push('could not fetch registry info (offline or package does not exist)');
    bad.forEach((m) => console.log(`    [BLOCK] ${m}`));
    warn.forEach((m) => console.log(`    [warn]  ${m}`));
    if (!bad.length && !warn.length) console.log('    ok');
    if (bad.length) blocked = true;
    if (warn.some((w) => !w.startsWith('has '))) needsConfirm = true;
  }

  // exitCode (not process.exit) so Node on Windows can close the fetch handle cleanly
  if (blocked) { console.log('\n  INSTALL BLOCKED. npm was not run.'); process.exitCode = 1; return; }
  if (needsConfirm && !/^y/i.test(await ask('\n  Warnings above. Proceed anyway? (y/N) '))) { process.exitCode = 1; return; }
  run();
})();
