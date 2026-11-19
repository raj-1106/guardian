const POPULAR = ['socket.io', 'axios', 'express', 'lodash', 'react', 'vue', 'typescript', 'webpack',
  'eslint', 'prettier', 'better-sqlite3', 'node-fetch', 'discord.js', 'ethers', 'chalk', 'commander',
  'moment', 'dotenv', 'request', 'jquery', 'next', 'viem', 'web3', 'koffi'];

function levenshtein(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}

function isTransposition(a, b) {
  if (a.length !== b.length) return false;
  const diff = [...a].map((c, i) => (c !== b[i] ? i : -1)).filter((i) => i >= 0);
  return diff.length === 2 && diff[1] === diff[0] + 1 && a[diff[0]] === b[diff[1]] && a[diff[1]] === b[diff[0]];
}

// Returns the popular package this name is suspiciously close to, or null.
function typosquatOf(name) {
  const bare = name.replace(/^@[^/]+\//, '');
  if (POPULAR.includes(name)) return null;
  for (const pop of POPULAR) {
    if (pop.length < 5) continue;
    if (levenshtein(bare, pop) <= 1 || isTransposition(bare, pop)) return pop;
  }
  return null;
}

module.exports = { levenshtein, typosquatOf };
