/*
 * FIGURE 4 — Cost vs. completeness.
 *
 * One point per (tool, scenario), x = HTTP requests (log), y = recovery
 * ratio.  GitHacker dots in accent; this is the chart that visualizes
 * the Pareto frontier — high recovery for low cost.
 */

import type { ScenarioResult, ToolMeta } from '../benchmark';

interface Args {
  scenarios: string[];
  scenarioLabels: Record<string, string>;
  tools: Array<{ id: string; meta: ToolMeta }>;
  results: Record<string, Record<string, ScenarioResult>>;
}

const ACCENT = 'var(--accent)';
const INK = 'var(--ink)';
const MUTE = 'var(--ink-mute)';
const RULE = 'var(--rule-soft)';

export function scatterSvg({ scenarios, tools, results }: Args): string {
  const W = 720;
  const H = 320;
  const padL = 56;
  const padR = 130;
  const padT = 14;
  const padB = 36;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  type P = { x: number; y: number; isHero: boolean; toolId: string };
  const pts: P[] = [];
  for (const t of tools) {
    for (const sc of scenarios) {
      const r = results[t.id]?.[sc];
      if (!r) continue;
      const reqs = r.http_requests ?? 0;
      if (reqs <= 0) continue;
      pts.push({ x: reqs, y: r.ratio, isHero: t.id === 'githacker', toolId: t.id });
    }
  }
  if (!pts.length) return '';

  const xs = pts.map((p) => p.x);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const lminX = Math.log10(Math.max(1, minX));
  const lmaxX = Math.log10(maxX);
  const lspan = Math.max(0.1, lmaxX - lminX);
  const xScale = (v: number) => padL + ((Math.log10(Math.max(1, v)) - lminX) / lspan) * plotW;
  const yScale = (v: number) => padT + (1 - v / 100) * plotH;

  const out: string[] = [];
  out.push(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="HTTP requests versus recovery rate" font-family="Source Serif 4, Georgia, serif">`);

  // y gridlines + labels (0/25/50/75/100).
  for (const y of [0, 25, 50, 75, 100]) {
    const py = yScale(y);
    out.push(`<line x1="${padL}" y1="${py}" x2="${padL + plotW}" y2="${py}" stroke="${RULE}" stroke-width="0.5"/>`);
    out.push(`<text x="${padL - 6}" y="${py + 3.5}" font-size="10" fill="${MUTE}" text-anchor="end" font-variant-numeric="tabular-nums">${y}</text>`);
  }
  out.push(`<text x="${padL - 38}" y="${padT + plotH / 2}" font-size="10" fill="${MUTE}" transform="rotate(-90 ${padL - 38} ${padT + plotH / 2})" text-anchor="middle">recovery (%)</text>`);

  // x gridlines at powers of 10 within range.
  const lo = Math.floor(lminX);
  const hi = Math.ceil(lmaxX);
  for (let d = lo; d <= hi; d++) {
    const v = Math.pow(10, d);
    if (v < minX * 0.5 || v > maxX * 2) continue;
    const px = xScale(v);
    if (px < padL - 0.5 || px > padL + plotW + 0.5) continue;
    out.push(`<line x1="${px}" y1="${padT}" x2="${px}" y2="${padT + plotH}" stroke="${RULE}" stroke-width="0.5"/>`);
    out.push(`<text x="${px}" y="${padT + plotH + 14}" font-size="10" fill="${MUTE}" text-anchor="middle" font-variant-numeric="tabular-nums">${v >= 1000 ? `${v / 1000}k` : v}</text>`);
  }
  out.push(`<text x="${padL + plotW / 2}" y="${H - 6}" font-size="10" fill="${MUTE}" text-anchor="middle">HTTP requests (log)</text>`);

  // Points.
  for (const p of pts) {
    const cx = xScale(p.x);
    const cy = yScale(p.y);
    if (p.isHero) {
      out.push(`<circle cx="${cx}" cy="${cy}" r="4.5" fill="${ACCENT}" stroke="${ACCENT}" stroke-width="0.5"/>`);
    } else {
      out.push(`<circle cx="${cx}" cy="${cy}" r="3.5" fill="none" stroke="${INK}" stroke-width="0.9" opacity="0.7"/>`);
    }
  }

  // Legend.
  const lx = padL + plotW + 14;
  const ly = padT + 4;
  out.push(`<circle cx="${lx + 6}" cy="${ly + 5}" r="4.5" fill="${ACCENT}"/>`);
  out.push(`<text x="${lx + 18}" y="${ly + 8}" font-size="11" fill="${INK}">GitHacker</text>`);
  out.push(`<circle cx="${lx + 6}" cy="${ly + 24}" r="3.5" fill="none" stroke="${INK}" stroke-width="0.9"/>`);
  out.push(`<text x="${lx + 18}" y="${ly + 27}" font-size="11" fill="${INK}">other tools</text>`);

  out.push('</svg>');
  return out.join('\n');
}
