# security-guardian

Personal Windows tripwire for malware-style activity. Experimental R&D, not antivirus.
Built after a `Trojan:Win32/Wacatac.B!ml` infection; the rules are tuned to that incident.

## What it does

**Background daemon** (`guardian`), checks every 10 seconds plus real-time watchers:
- Watches Desktop, Documents, Downloads, AppData, Temp, the Startup folder and the top level of your profile.
- Files matching malware patterns (`abe_payload*`, `*_inj_*.dll`, `loader.log`, `.vbs`/`.vbe`) are **quarantined**, not deleted.
- Hidden dot-folders in your profile that match malware-style names, or hold `node_modules` plus a `.vbs` launcher, are quarantined and their processes killed.
- `node`/`wscript`/`cscript` processes running from those locations are killed.
- Every action writes to `~\.guardian\alerts.log` and raises a Windows toast.

**`npm-safe install <pkg>`** scans a package before npm runs:
- known-malicious names and typosquats (Levenshtein distance 1 or a transposition)
- `preinstall` / `install` / `postinstall` / `prepare` scripts that download and execute
- dependency combos like DPAPI + SQLite / socket.io

Critical findings block the install (exit 1). Other warnings ask `Proceed anyway? (y/N)`.

## Limits

- It cannot see links you click. It only catches a resulting file if the name matches a rule.
- Bare `npm install` is not intercepted; use `npm-safe install`. For wrapping npm itself, see `@aikidosec/safe-chain` or `npq`.
- Signature-based on one incident; trivially evaded. Keep Windows Defender on.
- Windows only. Needs Node 18+.

## Setup

```
cd R:\security-guardian
npm link            # adds `guardian` and `npm-safe` to every shell
guardian install    # autostart at every login (HKCU Run key, no admin)
```

Run as a normal user, not admin. If PowerShell blocks the `guardian` shim, use cmd or `node bin\guardian.js <command>`.

## Commands

| Command | Effect |
|---|---|
| `guardian start` / `stop` / `status` | control the background process |
| `guardian install` / `uninstall` | add/remove login autostart |
| `guardian log` | show alerts |
| `guardian quarantine` | list quarantined items |
| `guardian restore <id>` | move an item back to where it came from |
| `guardian test-alert` | fire a test toast |

Quarantine lives in `~\.guardian\quarantine`.

## Config

Edit `rules.json`, then `guardian stop` and `guardian start` (config loads once at startup).
If something legitimate gets quarantined, add its folder to `allowedDotFolders` or loosen a pattern.

## Test

```
npm test
```

## Known gaps

- `guardian.pid` is not removed on exit; PID reuse could make `status` report a false "running".
- No auto-restart if the daemon crashes.
- Toast delivery and the process-kill path are untested against real malware.
