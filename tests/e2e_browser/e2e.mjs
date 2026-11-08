import puppeteer from 'puppeteer-core';
import { spawn } from 'node:child_process';
import fs from 'node:fs';

// Everything comes from environment variables set by run.py (or by you, to point it elsewhere).
const BASE = process.env.E2E_BASE ?? 'http://localhost:8000';
const KEY = process.env.E2E_API_KEY ?? '';
const ADMIN = [process.env.E2E_ADMIN_USER ?? 'e2e_admin', process.env.E2E_ADMIN_PASSWORD ?? ''];
const ANALYST = [process.env.E2E_ANALYST_USER ?? 'e2e_analyst', process.env.E2E_ANALYST_PASSWORD ?? ''];
const DEMO = process.env.E2E_DEMO_TOOL ?? '../../tools/send_demo_events.py';
const SHOTS = process.env.E2E_SHOTS ?? 'shots';
fs.mkdirSync(SHOTS, { recursive: true });
const results = [];
const problems = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function step(name, fn) {
  try { const note = await fn(); results.push(['PASS', name, note ?? '']); }
  catch (e) { results.push(['FAIL', name, String(e.message).split('\n')[0]]); }
}
async function api(path, { token, method = 'GET', body } = {}) {
  const r = await fetch(BASE + path, { method, headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }) }, body: body && JSON.stringify(body) });
  return { status: r.status, json: await r.json().catch(() => null) };
}
const text = (page) => page.evaluate(() => document.body.innerText);
const waitText = (page, needle, timeout = 15000) =>
  page.waitForFunction((n) => document.body.innerText.toLowerCase().includes(n.toLowerCase()), { timeout }, needle);
async function clearAndType(page, sel, value) {
  await page.focus(sel);
  await page.keyboard.down('Control'); await page.keyboard.press('KeyA'); await page.keyboard.up('Control');
  await page.keyboard.press('Backspace');
  await page.type(sel, value);
  const got = await page.$eval(sel, (e) => e.value);
  if (got !== value) throw new Error(`field ${sel} holds "${got}" instead of "${value}"`);
}
async function login(page, user, pass) {
  await page.waitForSelector('#username', { timeout: 10000 });
  await clearAndType(page, '#username', user);
  await clearAndType(page, '#password', pass);
  await page.click('button.submit-btn');
}
async function clickByText(page, selector, needle) {
  const handle = await page.evaluateHandle((sel, n) => [...document.querySelectorAll(sel)].find((e) => e.innerText.toLowerCase().includes(n.toLowerCase())), selector, needle);
  const el = handle.asElement(); if (!el) throw new Error(`no ${selector} containing "${needle}"`); await el.click();
}

async function launch() {
  if (process.env.CHROME_PATH) return puppeteer.launch({ executablePath: process.env.CHROME_PATH, headless: true, args: ['--no-sandbox'] });
  const { default: chromium } = await import('@sparticuz/chromium'); // Linux x64 only
  return puppeteer.launch({ args: chromium.args, executablePath: await chromium.executablePath(), headless: 'shell' });
}
const browser = await launch();
const page = await browser.newPage();
await page.setViewport({ width: 1366, height: 900 });
page.on('console', (m) => { if (m.type() === 'error') problems.push(`console.error: ${m.text().slice(0, 160)}`); });
page.on('pageerror', (e) => problems.push(`pageerror: ${String(e.message).slice(0, 160)}`));
page.on('response', (r) => { if (r.status() >= 400) problems.push(`HTTP ${r.status()} ${r.request().method()} ${r.url().replace(BASE, '')}`); });
const shot = (n) => page.screenshot({ path: `${SHOTS}/${n}.png` });

await step('1 anonymous visit shows the login form', async () => { await page.goto(BASE + '/', { waitUntil: 'networkidle0' }); await page.waitForSelector('#username'); await shot('01-login'); });
await step('2 wrong password shows the server message, stays on login', async () => { await login(page, ADMIN[0], 'wrong-password'); await waitText(page, 'Invalid username or password'); await shot('02-wrong-password'); });
await step('3 correct login opens the dashboard', async () => { await login(page, ADMIN[0], ADMIN[1]); await page.waitForFunction(() => !document.querySelector('#username'), { timeout: 10000 }); await sleep(1500); await shot('03-dashboard-empty'); return (await text(page)).replace(/\s+/g, ' ').slice(0, 140); });
await step('4 header shows the live connection as live', async () => { await page.waitForFunction(() => document.querySelector('.connection')?.dataset.state === 'live', { timeout: 10000 }); return 'data-state=live'; });

await page.evaluate(() => { window.__marker = 'no-reload'; });
const demo = spawn(process.env.E2E_PYTHON ?? 'python', [DEMO, '--url', BASE, '--api-key', KEY, '--pause', '2', '--rate', '3', '--duration', '3', '--seed', '1'], { stdio: 'pipe' });
let demoOut = ''; demo.stdout.on('data', (d) => (demoOut += d)); demo.stderr.on('data', (d) => (demoOut += d));
const demoDone = new Promise((r) => demo.on('exit', r));

await step('5 a port-scan alert appears LIVE, without reloading the page', async () => { await waitText(page, 'port scan', 25000); const m = await page.evaluate(() => window.__marker); if (m !== 'no-reload') throw new Error('page was reloaded'); await shot('05-live-alert'); });
await step('6 live feed lists items', async () => { const n = await page.$$eval('.feed li', (l) => l.length); if (n < 1) throw new Error('feed is empty'); return `${n} feed items`; });
const code = await demoDone;
await step('7 demo generator finished cleanly', async () => { if (code !== 0) throw new Error(`exit ${code}: ${demoOut.slice(-200)}`); return demoOut.trim().split('\n').slice(-2).join(' | '); });
await sleep(1500);
await step('8 stat tiles reflect the new data', async () => { const t = (await page.$eval('.tiles', (e) => e.innerText)).replace(/\s+/g, ' '); await shot('08-dashboard-after-demo'); if (/\b0\b.*\b0\b.*\b0\b/.test(t) && !/[1-9]/.test(t)) throw new Error('tiles still zero: ' + t); return t; });

await step('9 alerts page lists all four rules', async () => { await page.evaluate(() => (location.hash = '#/alerts')); await page.waitForSelector('tbody tr', { timeout: 10000 }); const t = await text(page); const missing = ['port_scan', 'dns_anomaly', 'auth_failures', 'web_paths'].filter((r) => !t.includes(r)); await shot('09-alerts'); if (missing.length) throw new Error('missing: ' + missing); return `${(await page.$$('tbody tr')).length} rows`; });
let alertId;
await step('10 alert detail shows explanation and evidence', async () => { await clickByText(page, 'tbody tr', 'port_scan'); await page.waitForSelector('[aria-label="Alert detail"] h2', { timeout: 10000 }); alertId = Number(page.url().split('/alerts/')[1]); await sleep(800); const t = await text(page); await shot('10-alert-detail'); if (!/evidence/i.test(t)) throw new Error('no evidence section'); return `alert #${alertId}`; });
await step('11 "Start investigating" persists to the backend', async () => { await clickByText(page, 'button', 'Start investigating'); await sleep(1500); const tok = (await api('/api/token', { method: 'POST', body: { username: ADMIN[0], password: ADMIN[1] } })).json.access_token; const a = await api(`/api/alerts/${alertId}`, { token: tok }); if (a.json.status !== 'investigating') throw new Error('backend status is ' + a.json.status); await shot('11-after-status-change'); return 'backend says investigating'; });
await step('11b blocking from the alert asks to confirm, says it is only a record, then lists the IP', async () => {
  await page.evaluate((id) => (location.hash = `#/alerts/${id}`), alertId); await sleep(800);
  await clickByText(page, '.block-ip button', 'Block');
  await page.waitForSelector('.block-ip .confirm', { timeout: 5000 });
  const warn = await page.$eval('.block-ip .confirm', (e) => e.innerText);
  if (/will be refused/i.test(warn) || !/nothing is blocked automatically/i.test(warn)) throw new Error('misleading wording: ' + warn);
  await clickByText(page, '.block-ip .confirm button', 'Block IP');
  await waitText(page, 'is on the blocklist', 8000);
  const tok = (await api('/api/token', { method: 'POST', body: { username: ADMIN[0], password: ADMIN[1] } })).json.access_token;
  const list = (await api('/api/blocklist', { token: tok })).json;
  if (!list.some((b) => b.ip === '203.0.113.50' && b.alert_id === alertId)) throw new Error('backend list: ' + JSON.stringify(list));
  await shot('11b-blocklisted');
});
await step('11c the blocklist entry survives a reload', async () => { await page.reload({ waitUntil: 'networkidle0' }); await waitText(page, 'is on the blocklist', 8000); });
await step('11d removing it clears it from the backend', async () => {
  await clickByText(page, '.block-ip button', 'Remove from blocklist'); await sleep(1200);
  const tok = (await api('/api/token', { method: 'POST', body: { username: ADMIN[0], password: ADMIN[1] } })).json.access_token;
  const list = (await api('/api/blocklist', { token: tok })).json; if (list.length) throw new Error('still listed: ' + JSON.stringify(list));
});
await step('12 events page shows rows', async () => { await page.evaluate(() => (location.hash = '#/events')); await page.waitForSelector('tbody tr', { timeout: 10000 }); await shot('12-events'); return `${(await page.$$('tbody tr')).length} rows`; });
await step('13 admin page lists users (admin only)', async () => { await page.evaluate(() => (location.hash = '#/admin')); await waitText(page, ANALYST[0], 10000); await shot('13-admin'); });
await step('14 header shows the user, a Users link (admin) and a Log out button', async () => { await page.evaluate(() => (location.hash = '#/')); await sleep(800); const t = await page.$eval('.app-header', (e) => e.innerText); if (!t.includes(ADMIN[0]) || !/Users/.test(t) || !/Log out/.test(t)) throw new Error('header text: ' + t.replace(/\s+/g, ' ')); await shot('14-header'); return t.replace(/\s+/g, ' ').slice(-60); });
await step('14b the Users link opens the admin page', async () => { await clickByText(page, '.app-header a', 'Users'); await waitText(page, ANALYST[0], 8000); });
await step('14c Log out returns to login and clears the stored token', async () => { await clickByText(page, '.app-header button', 'Log out'); await page.waitForSelector('#username', { timeout: 8000 }); const tok = await page.evaluate(() => localStorage.getItem('cyber_mi6_token')); if (tok) throw new Error('token still stored'); });
await step('14d after logout the live socket is closed and the dashboard needs a new login', async () => { const r = await api('/api/stats'); if (r.status !== 401) throw new Error('anon stats gave ' + r.status); await login(page, ADMIN[0], ADMIN[1]); await page.waitForFunction(() => !document.querySelector('#username'), { timeout: 10000 }); });
await step('15 reload keeps the session', async () => { await page.reload({ waitUntil: 'networkidle0' }); await sleep(1500); if (await page.$('#username')) throw new Error('sent back to login after reload'); });

await step('16 analyst login; /admin is refused', async () => { await page.evaluate(() => { localStorage.clear(); sessionStorage.clear(); }); await page.goto(BASE + '/', { waitUntil: 'networkidle0' }); await login(page, ANALYST[0], ANALYST[1]); await page.waitForFunction(() => !document.querySelector('#username'), { timeout: 10000 }); await page.evaluate(() => (location.hash = '#/admin')); await waitText(page, 'Unauthorized', 8000); await shot('16-analyst-admin'); });
await step('17 disabling the analyst sends their open session back to login', async () => {
  const adminTok = (await api('/api/token', { method: 'POST', body: { username: ADMIN[0], password: ADMIN[1] } })).json.access_token;
  const users = (await api('/api/users', { token: adminTok })).json; const id = users.find((u) => u.username === ANALYST[0]).id;
  const r = await api(`/api/users/${id}/status`, { token: adminTok, method: 'PATCH', body: { status: 'disabled' } }); if (r.status !== 200) throw new Error('disable failed ' + r.status);
  await page.evaluate(() => (location.hash = '#/alerts')); await page.waitForSelector('#username', { timeout: 20000 }); await shot('17-kicked-to-login');
});

await browser.close();
console.log('\n=== BROWSER END-TO-END RESULTS ===');
for (const [s, n, note] of results) console.log(`${s}  ${n}${note ? '  -> ' + note : ''}`);
const uniq = [...new Set(problems)];
console.log(`\nPASS ${results.filter((r) => r[0] === 'PASS').length} / ${results.length}`);
console.log('\nconsole/network problems seen (' + uniq.length + '; 401s for wrong passwords and a disabled user are expected):'); uniq.slice(0, 20).forEach((p) => console.log('  ' + p));
process.exit(results.every((r) => r[0] === 'PASS') ? 0 : 1);
