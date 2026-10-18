// Reproduces agent-browser commands aborting while another CDP client creates,
// closes or navigates its own tabs in the same Chrome.
//
// usage: node foreign-cdp-client-repro.mjs AGENT_BROWSER_BINARY [rounds]
// env:   PLAYWRIGHT_CORE (path to playwright-core), CHROME (executable path)
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const binary = process.argv[2];
const rounds = Number(process.argv[3] ?? 8);
if (!binary) throw Error('usage: node foreign-cdp-client-repro.mjs AGENT_BROWSER_BINARY [rounds]');
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_CORE ?? 'playwright-core');

const churn = other => `<!doctype html><title>churn</title><h1>foreign</h1><div id=f></div><script>
let n=0;setInterval(()=>{const f=document.getElementById('f');if(f.children.length>3)f.firstChild.remove();
const i=document.createElement('iframe');i.src='http://localhost:${other}/frame?'+(n++);f.appendChild(i);},150);</script>`;
const own = other => `<!doctype html><title>own</title><h1>agent page</h1><button>Go</button>
<iframe src="http://localhost:${other}/frame?own"></iframe>`;
const server = createServer((req, res) => {
  const other = server.address().port;
  res.setHeader('content-type', 'text/html');
  if (req.url.startsWith('/churn')) res.end(churn(other));
  else if (req.url.startsWith('/frame')) res.end('<!doctype html><p>frame</p><input placeholder=card>');
  else res.end(own(other));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
const base = `http://127.0.0.1:${port}`;
const profile = mkdtempSync(join(tmpdir(), 'ab-foreign-'));
const session = `foreign-repro-${process.pid}`;
const ab = args => new Promise(resolve => {
  const cli = ['--session', session, '--profile', profile];
  if (process.env.CHROME) cli.push('--executable-path', process.env.CHROME);
  execFile(binary, [...cli, ...args], { timeout: 60000 }, (error, stdout, stderr) =>
    resolve({ ok: !error, out: (stdout + stderr).trim() }));
});

const first = await ab(['open', `${base}/own?start`]);
if (!first.ok) throw Error('initial open failed: ' + first.out);
const cdpPort = readFileSync(join(profile, 'DevToolsActivePort'), 'utf8').split('\n')[0];
const browser = await chromium.connectOverCDP(`http://127.0.0.1:${cdpPort}`, { timeout: 15000 });
const context = browser.contexts()[0];
let stop = false;
const newTabChurn = async () => {
  while (!stop) {
    const page = await context.newPage();
    await page.goto(`${base}/churn?new`, { waitUntil: 'domcontentloaded' }).catch(() => {});
    await page.waitForTimeout(700);
    await page.close().catch(() => {});
  }
};
const backgroundTabNav = async () => {
  const cdp = await browser.newBrowserCDPSession();
  const waiting = context.waitForEvent('page');
  await cdp.send('Target.createTarget', { url: 'about:blank#foreign', background: true });
  const page = await waiting;
  for (let i = 0; !stop; i++) {
    await page.goto(`${base}/churn?bg=${i}`, { waitUntil: 'domcontentloaded' }).catch(() => {});
    await page.waitForTimeout(400);
  }
};
const probes = [newTabChurn(), backgroundTabNav()];
const failures = [];
for (let i = 0; i < rounds; i++) {
  for (const args of [['open', `${base}/own?round=${i}`], ['snapshot'], ['get', 'url']]) {
    const result = await ab(args);
    const wrongTab = args[0] === 'get' && result.ok && !result.out.includes('/own?round=');
    if (!result.ok || wrongTab) failures.push(`${args.join(' ')}: ${result.out.split('\n').slice(-2).join(' | ')}`);
  }
}
stop = true;
await Promise.allSettled(probes);
await browser.close().catch(() => {});
await ab(['close']);
server.close();
rmSync(profile, { recursive: true, force: true });
console.log(JSON.stringify({ rounds, commands: rounds * 3, failures }, null, 2));
process.exit(failures.length ? 1 : 0);
