/*
 * FIGURE 6 — Disclosure timeline.
 *
 * Gantt-style horizontal bars per finding:
 *   [observed ─── reported ─── patched ─── disclosed]
 *
 * Rendered against a single shared time axis spanning min to max of
 * any date in the dataset.  Diamonds mark milestones; the bar spans
 * from first_observed to the latest known milestone.
 */

import type { Disclosure } from '../security';

const ACCENT = 'var(--accent)';
const INK = 'var(--ink)';
const MUTE = 'var(--ink-mute)';
const RULE = 'var(--rule-soft)';

export function timelineSvg(discs: Disclosure[]): string {
  if (!discs.length) {
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 60" width="100%"><text x="300" y="34" font-size="13" fill="${MUTE}" text-anchor="middle" font-family="Source Serif 4, Georgia, serif" font-style="italic">No public disclosures yet — entries appear here as embargoes lift.</text></svg>`;
  }

  const dates: number[] = [];
  for (const d of discs) {
    if (d.first_observed) dates.push(parseDate(d.first_observed));
    if (d.reported_at)    dates.push(parseDate(d.reported_at));
    if (d.patched_at)     dates.push(parseDate(d.patched_at));
  }
  const minT = Math.min(...dates);
  const maxT = Math.max(...dates);
  const span = Math.max(86_400_000, maxT - minT); // at least one day

  const W = 720;
  const labelW = 132;
  const padR = 60;
  const padTop = 28;
  const padBot = 32;
  const rowH = 24;
  const barAreaX = labelW;
  const barAreaW = W - labelW - padR;
  const H = padTop + discs.length * rowH + padBot;
  const t2x = (t: number) => barAreaX + ((t - minT) / span) * barAreaW;

  const out: string[] = [];
  out.push(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Disclosure timeline" font-family="Source Serif 4, Georgia, serif">`);

  // Year/month tick guides.
  const tickTimes = niceTicks(minT, maxT);
  for (const tt of tickTimes) {
    const x = t2x(tt);
    out.push(`<line x1="${x}" y1="${padTop}" x2="${x}" y2="${H - padBot + 2}" stroke="${RULE}" stroke-width="0.5"/>`);
    out.push(`<text x="${x}" y="${H - padBot + 14}" font-size="10" fill="${MUTE}" text-anchor="middle">${fmtTick(tt)}</text>`);
  }

  // Legend.
  let lx = barAreaX;
  const legend: Array<[string, string]> = [
    ['observed', 'circle'],
    ['reported', 'square'],
    ['patched',  'diamond'],
  ];
  for (const [label, shape] of legend) {
    out.push(marker(lx + 6, padTop - 12, shape, INK));
    out.push(`<text x="${lx + 16}" y="${padTop - 9}" font-size="10.5" fill="${INK}">${label}</text>`);
    lx += 92;
  }

  discs.forEach((d, i) => {
    const y = padTop + i * rowH;
    const cy = y + rowH / 2;
    const obs = d.first_observed ? parseDate(d.first_observed) : null;
    const rep = d.reported_at    ? parseDate(d.reported_at)    : null;
    const pat = d.patched_at     ? parseDate(d.patched_at)     : null;
    const last = pat ?? rep ?? obs;
    if (obs == null || last == null) return;
    const x1 = t2x(obs);
    const x2 = t2x(last);

    // Row label: id + tool.
    out.push(`<text x="${labelW - 8}" y="${cy + 3.5}" font-size="11" fill="${INK}" text-anchor="end" font-family="JetBrains Mono, monospace">${escapeXml(d.id)}</text>`);

    // Bar from observed to last known milestone.
    out.push(`<line x1="${x1}" y1="${cy}" x2="${x2}" y2="${cy}" stroke="${ACCENT}" stroke-width="2.5" stroke-linecap="round"/>`);

    // Markers.
    out.push(marker(x1, cy, 'circle', ACCENT));
    if (rep != null) out.push(marker(t2x(rep), cy, 'square', ACCENT));
    if (pat != null) out.push(marker(t2x(pat), cy, 'diamond', ACCENT));

    // Trailing tool name.
    out.push(`<text x="${barAreaX + barAreaW + 6}" y="${cy + 3.5}" font-size="11" fill="${INK}" text-anchor="start">${escapeXml(d.tool || '')}</text>`);
  });

  out.push('</svg>');
  return out.join('\n');
}

function parseDate(s: string): number {
  // ISO yyyy-mm-dd is reliably parsed as UTC by Date.parse.
  return Date.parse(s);
}

function fmtTick(t: number): string {
  const d = new Date(t);
  const m = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getUTCMonth()];
  return `${m} ${d.getUTCFullYear()}`;
}

function niceTicks(minT: number, maxT: number): number[] {
  const span = maxT - minT;
  // For short spans (< ~3 months) emit monthly ticks; otherwise quarterly.
  const stepMs = span < 90 * 86_400_000 ? 30 * 86_400_000 : 90 * 86_400_000;
  const out: number[] = [];
  for (let t = roundUpToMonth(minT); t <= maxT + stepMs / 2; t += stepMs) out.push(t);
  if (!out.length) out.push((minT + maxT) / 2);
  return out;
}

function roundUpToMonth(t: number): number {
  const d = new Date(t);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
}

function marker(x: number, y: number, kind: string, fill: string): string {
  if (kind === 'square') {
    return `<rect x="${x - 4}" y="${y - 4}" width="8" height="8" fill="${fill}"/>`;
  }
  if (kind === 'diamond') {
    return `<polygon points="${x},${y - 5} ${x + 5},${y} ${x},${y + 5} ${x - 5},${y}" fill="${fill}"/>`;
  }
  return `<circle cx="${x}" cy="${y}" r="4.5" fill="${fill}"/>`;
}

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
