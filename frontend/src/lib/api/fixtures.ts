/**
 * Development fixtures. The first rows reproduce the sample data in the Figma
 * "Dashboard — Desktop" frame so the built views can be compared with the
 * design side by side. Remaining alerts are generated so totals match the
 * frame's stat tiles: 41 alerts (5 critical, 9 high, 18 medium, 9 low) and
 * 23 open (14 new, 9 investigating).
 *
 * Every object follows backend/models.py: e.g. auth_failure events carry only
 * `username`, never HTTP fields (the model rejects them).
 */
import type { Alert, AlertStatus, Event, Severity } from '../types';

/** Today's date (UTC) so "events today" behaves like real data. */
const DAY = new Date().toISOString().slice(0, 10);
const at = (time: string) => `${DAY}T${time}Z`;

const base = {
  dst_ip: null,
  dst_port: null,
  protocol: null,
  dns_name: null,
  username: null,
  http_method: null,
  http_path: null,
  http_status: null,
  user_agent: null,
  details: null,
} satisfies Partial<Event>;

function event(e: Pick<Event, 'id' | 'type' | 'source' | 'src_ip'> & Partial<Event> & { time: string }): Event {
  const { time, ...rest } = e;
  return { ...base, timestamp: at(time), received_at: at(time), ...rest };
}

// --- Events --------------------------------------------------------------

/** "Recent events" table in the Figma desktop frame. */
const recentEvents: Event[] = [
  event({ id: 4890, type: 'auth_failure', time: '09:21:47', source: 'test-webapp', src_ip: '10.0.0.14', username: 'admin' }),
  event({ id: 4889, type: 'dns_query', time: '09:21:40', source: 'laptop-sensor-1', src_ip: '192.168.1.25', dns_name: 'api.github.com' }),
  event({ id: 4888, type: 'network_connection', time: '09:21:38', source: 'laptop-sensor-1', src_ip: '192.168.1.25', dst_ip: '192.168.1.1', dst_port: 443, protocol: 'tcp' }),
  event({ id: 4887, type: 'http_request', time: '09:21:31', source: 'test-webapp', src_ip: '172.16.4.9', http_method: 'GET', http_path: '/.env', http_status: 404 }),
  event({ id: 4886, type: 'dns_query', time: '09:21:22', source: 'laptop-sensor-1', src_ip: '192.168.1.40', dns_name: 'x9f3k2q8z7.example.net' }),
  event({ id: 4885, type: 'network_connection', time: '09:21:15', source: 'laptop-sensor-1', src_ip: '192.168.1.25', dst_ip: '192.168.1.1', dst_port: 22, protocol: 'tcp' }),
];

/**
 * Evidence for the port-scan alert: 41 SYNs from 192.168.1.25 between 09:14:50
 * and 09:15:02. The five rows visible in the Figma evidence list are the five
 * newest, with their exact ids, times and ports; the other 36 ("+ 36 more")
 * are older.
 */
const PORT_SCAN_PORTS = [
  21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 631, 993, 995,
  1080, 1433, 1521, 1723, 2049, 2375, 3000, 3306, 3389, 4444, 5000, 5432, 5900, 6379, 7001, 8000,
  8080, 8443, 9000, 9200,
];
const PINNED: Record<number, { port: number; time: string }> = {
  4812: { port: 21, time: '09:14:50' },
  4839: { port: 22, time: '09:14:58' },
  4847: { port: 445, time: '09:15:00' },
  4850: { port: 3389, time: '09:15:01' },
  4851: { port: 8080, time: '09:15:02' },
};

const portScanEvidence: Event[] = (() => {
  const pinnedPorts = new Set(Object.values(PINNED).map((p) => p.port));
  const free = PORT_SCAN_PORTS.filter((p) => !pinnedPorts.has(p));
  const scan = (id: number, time: string, port: number) =>
    event({
      id, type: 'network_connection', time, source: 'laptop-sensor-1',
      src_ip: '192.168.1.25', dst_ip: '192.168.1.1', dst_port: port, protocol: 'tcp',
    });
  const pinned = Object.entries(PINNED).map(([id, p]) => scan(Number(id), p.time, p.port));
  // Older ids at the first-seen time sort after #4812 (newest first, then id desc).
  const older = free.map((port, i) => scan(4776 + i, '09:14:50', port));
  return [...pinned, ...older]; // 5 + 36 = 41
})();

export const events: Event[] = [...recentEvents, ...portScanEvidence];

// --- Alerts --------------------------------------------------------------

function alert(a: Omit<Alert, 'created_at' | 'updated_at'> & { created: string; updated?: string }): Alert {
  const { created, updated, ...rest } = a;
  return { ...rest, created_at: at(created), updated_at: at(updated ?? created) };
}

/** "Alert history" table and alert detail panel in the Figma desktop frame. */
const designAlerts: Alert[] = [
  alert({
    id: 41, rule: 'auth_failures', severity: 'critical', title: '5 failed logins for admin in 2 min',
    src_ip: '10.0.0.14', status: 'new', count: 1, created: '09:21:47', evidence_event_ids: [4890],
    explanation: { threshold: 5, window_seconds: 300, observed: 5, observed_window_seconds: 120, username: 'admin' },
  }),
  alert({
    id: 40, rule: 'dns_anomaly', severity: 'medium', title: 'High-entropy DNS label: x9f3k2q8z7.example.net',
    src_ip: '192.168.1.40', status: 'new', count: 1, created: '09:18:10', evidence_event_ids: [4886],
    explanation: { max_label_length: 40, min_entropy: 3.0, label: 'x9f3k2q8z7', entropy: 3.32 },
  }),
  alert({
    id: 17, rule: 'port_scan', severity: 'high', title: 'Possible port scan from 192.168.1.25',
    src_ip: '192.168.1.25', status: 'investigating', count: 3, created: '09:14:50', updated: '09:15:02',
    evidence_event_ids: portScanEvidence.map((e) => e.id),
    explanation: { threshold: 20, window_seconds: 30, observed: 41, observed_window_seconds: 12 },
  }),
  alert({
    id: 39, rule: 'web_paths', severity: 'medium', title: 'Suspicious path request: /phpmyadmin',
    src_ip: '172.16.4.9', status: 'investigating', count: 1, created: '09:07:55', evidence_event_ids: [],
    explanation: { category: 'admin_panel_probe', path: '/phpmyadmin' },
  }),
  alert({
    id: 38, rule: 'web_paths', severity: 'low', title: 'Suspicious path request: /.env',
    src_ip: '172.16.4.9', status: 'false_positive', count: 1, created: '09:02:33', evidence_event_ids: [4887],
    explanation: { category: 'sensitive_file', path: '/.env' },
  }),
  alert({
    id: 37, rule: 'auth_failures', severity: 'high', title: '7 failed logins from 172.16.4.9 in 4 min',
    src_ip: '172.16.4.9', status: 'resolved', count: 2, created: '08:51:12', evidence_event_ids: [],
    explanation: { threshold: 5, window_seconds: 300, observed: 7, observed_window_seconds: 240 },
  }),
];

/** Older alerts so the totals match the Figma stat tiles. */
const fillerAlerts: Alert[] = (() => {
  // Remaining after designAlerts: 4 critical, 7 high, 16 medium, 8 low (35).
  const severities: Severity[] = [
    ...Array<Severity>(4).fill('critical'), ...Array<Severity>(7).fill('high'),
    ...Array<Severity>(16).fill('medium'), ...Array<Severity>(8).fill('low'),
  ];
  // Remaining: 12 new, 7 investigating, 12 resolved, 4 false_positive (35).
  const statuses: AlertStatus[] = [
    ...Array<AlertStatus>(12).fill('new'), ...Array<AlertStatus>(7).fill('investigating'),
    ...Array<AlertStatus>(12).fill('resolved'), ...Array<AlertStatus>(4).fill('false_positive'),
  ];
  const templates = [
    { rule: 'port_scan', title: (ip: string) => `Possible port scan from ${ip}` },
    { rule: 'dns_anomaly', title: () => 'Long DNS label: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0.cdn.example.com' },
    { rule: 'auth_failures', title: (ip: string) => `6 failed logins from ${ip} in 3 min` },
    { rule: 'web_paths', title: () => 'Suspicious path request: /etc/passwd' },
  ];
  const ips = ['192.168.1.25', '192.168.1.40', '172.16.4.9', '10.0.0.14', '192.168.1.77'];
  const ids = Array.from({ length: 41 }, (_, i) => i + 1).filter((id) => !designAlerts.some((a) => a.id === id));

  return ids.map((id, i) => {
    const t = templates[i % templates.length];
    const ip = ips[i % ips.length];
    const minutes = 8 * 60 + 45 - i * 7; // spaced back from 08:45
    const time = `${String(Math.floor(minutes / 60)).padStart(2, '0')}:${String(minutes % 60).padStart(2, '0')}:00`;
    // Interleave so filters return a mix rather than one block per value.
    const severity = severities[(i * 11) % severities.length];
    const status = statuses[(i * 13) % statuses.length];
    return alert({
      id, rule: t.rule, severity, title: t.title(ip), src_ip: ip, status, count: 1,
      created: time, evidence_event_ids: [], explanation: {},
    });
  });
})();

export const alerts: Alert[] = [...designAlerts, ...fillerAlerts];
