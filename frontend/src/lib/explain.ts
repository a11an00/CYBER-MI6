/**
 * Turns an alert's `explanation` into the Figma "Why this fired" box:
 * a plain sentence, the threshold with its .env setting names, and the
 * rule's known limitation (handbook §8).
 *
 * The explanation keys are not fixed by the backend yet (detection/engine.py
 * is empty). The ones read here match the mock fixtures; anything else falls
 * back to listing the raw key/value pairs, so a new key never breaks the panel.
 */
import type { Alert } from './types';

export interface Explanation {
  summary: string | null;
  threshold: string | null;
  caveat: string | null;
  /** Raw pairs shown when the summary can't be built from known keys. */
  raw: [string, string][];
}

const CAVEATS: Record<string, string> = {
  port_scan: 'A heuristic, not proof of intent. Packet loss or interface visibility can affect results.',
  dns_anomaly: 'CDNs and legitimate encoded names can trigger false positives.',
  auth_failures: 'Requires events sent by our own instrumented application.',
  web_paths: 'Requires application events. HTTPS capture alone cannot reveal encrypted paths.',
};

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const str = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null);

function rawPairs(e: Record<string, unknown>): [string, string][] {
  return Object.entries(e).map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)]);
}

export function explain(alert: Alert): Explanation {
  const e = alert.explanation ?? {};
  const ip = alert.src_ip ?? 'this source';
  let summary: string | null = null;
  let threshold: string | null = null;

  switch (alert.rule) {
    case 'port_scan': {
      const observed = num(e.observed), within = num(e.observed_window_seconds);
      const limit = num(e.threshold), window = num(e.window_seconds);
      if (observed !== null)
        summary = `${observed} distinct destination ports from ${ip}${within !== null ? ` within ${within} seconds` : ''}.`;
      if (limit !== null && window !== null)
        threshold = `Threshold: ${limit} ports in ${window} s (PORT_SCAN_PORTS, PORT_SCAN_WINDOW_SECONDS)`;
      break;
    }
    case 'auth_failures': {
      const observed = num(e.observed), within = num(e.observed_window_seconds);
      const limit = num(e.threshold), window = num(e.window_seconds);
      const who = str(e.username) ? `for ${str(e.username)}` : `from ${ip}`;
      if (observed !== null)
        summary = `${observed} failed logins ${who}${within !== null ? ` within ${Math.round(within / 60)} min` : ''}.`;
      if (limit !== null && window !== null)
        threshold = `Threshold: ${limit} failures in ${window / 60} min (AUTH_FAIL_COUNT, AUTH_FAIL_WINDOW_SECONDS)`;
      break;
    }
    case 'dns_anomaly': {
      const label = str(e.label), entropy = num(e.entropy);
      const maxLen = num(e.max_label_length), minEntropy = num(e.min_entropy);
      if (label !== null)
        summary = `DNS label "${label}" (${label.length} characters${entropy !== null ? `, entropy ${entropy}` : ''}).`;
      if (maxLen !== null && minEntropy !== null)
        threshold = `Threshold: labels ≥ ${maxLen} characters or entropy ≥ ${minEntropy} (DNS_MAX_LABEL_LENGTH, DNS_MIN_ENTROPY)`;
      break;
    }
    case 'web_paths': {
      const path = str(e.path), category = str(e.category);
      if (path !== null) summary = `Request for ${path}${category ? ` matched the ${category.replaceAll('_', ' ')} pattern` : ''}.`;
      if (category !== null) threshold = `Pattern category: ${category} (WEB_PATH_PATTERNS_FILE)`;
      break;
    }
  }

  return {
    summary,
    threshold,
    caveat: CAVEATS[alert.rule] ?? null,
    raw: summary === null ? rawPairs(e) : [],
  };
}
