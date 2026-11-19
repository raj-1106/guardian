const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const HOME = os.homedir();
const DIR = path.join(HOME, '.guardian');
const LOG = path.join(DIR, 'alerts.log');
const QUAR = path.join(DIR, 'quarantine');
const PIDFILE = path.join(DIR, 'guardian.pid');
const rules = () => JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'rules.json'), 'utf8'));

function log(level, msg) {
  fs.mkdirSync(DIR, { recursive: true });
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  fs.appendFileSync(LOG, `[${ts}] [${level}] ${msg}\n`);
}

// Toast via PowerShell; text goes through env vars so it can't be injected into the script.
const TOAST_PS = `
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] | Out-Null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$t = [System.Security.SecurityElement]::Escape($env:G_TITLE); $b = [System.Security.SecurityElement]::Escape($env:G_BODY)
$x.LoadXml("<toast duration='long'><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>")
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($x))`;

function notify(title, body) {
  try {
    spawn('powershell.exe', ['-NoProfile', '-WindowStyle', 'Hidden', '-Command', TOAST_PS], {
      env: { ...process.env, G_TITLE: 'Security Guardian: ' + title, G_BODY: body },
      stdio: 'ignore', windowsHide: true, detached: true,
    }).unref();
  } catch {}
}

function alert(level, title, body) {
  log(level, `${title} | ${body}`);
  notify(title, body);
}

// Move (never delete) into quarantine, with a manifest entry so it can be restored.
function quarantine(target) {
  fs.mkdirSync(QUAR, { recursive: true });
  const id = Date.now() + '_' + path.basename(target).replace(/[^\w.-]/g, '_');
  fs.renameSync(target, path.join(QUAR, id));
  fs.appendFileSync(path.join(QUAR, 'manifest.jsonl'), JSON.stringify({ id, from: target, at: new Date().toISOString() }) + '\n');
  return id;
}

module.exports = { HOME, DIR, LOG, QUAR, PIDFILE, rules, log, notify, alert, quarantine };
