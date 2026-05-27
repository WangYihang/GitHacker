/*
 * FIGURE 2 — Completeness with dispersion.
 *
 * Bars + min/max whiskers per tool, sorted descending.  Same value
 * domain as FIG. 1 but adds the spread across scenarios so the reader
 * can see "GitHacker is consistently 99-100%" vs. "Tool X swings from
 * 40% to 80% depending on server".
 */

import type { ToolMeta } from '../benchmark';

interface Row {
  id: string;
  meta: ToolMeta;
  mean: number;
  minR: number;
  maxR: number;
}

const ACCENT = 'var(--accent)';
const INK = 'var(--ink)';
const MUTE = 'var(--ink-mute)';
const RULE = 'var(--rule-soft)';

export function dispersionSvg(rows: Row[]): string {
  const W = 720;
  const labelW = 200;
  const valueW = 96;
  const barAreaX = labelW;
  const barAreaW = W - labelW - valueW - 12;
  const rowH = 24;
  const padTop = 8;
  const padBot = 18;
  const H = padTop + rows.length * rowH + padBot;
  const max = 100;

  const out: string[] = [];
  out.push(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Completeness with dispersion" font-family="Source Serif 4, Georgia, serif">`,
  );
  for (const t of [0, 25, 50, 75, 100]) {
    const x = barAreaX + (t / max) * barAreaW;
    out.push(`<line x1="${x}" y1="${padTop}" x2="${x}" y2="${H - padBot + 2}" stroke="${RULE}" stroke-width="0.5"/>`);
    out.push(`<text x="${x}" y="${H - 4}" font-size="9.5" fill="${MUTE}" text-anchor="middle">${t}</text>`);
  }

  rows.forEach((r, i) => {
    const y = padTop + i * rowH;
    const cy = y + rowH / 2;
    const isHero = r.id === 'githacker';
    const fill = isHero ? ACCENT : INK;
    const barW = (r.mean / max) * barAreaW;
    const minX = barAreaX + (r.minR / max) * barAreaW;
    const maxX = barAreaX + (r.maxR / max) * barAreaW;

    out.push(`<text x="${labelW - 8}" y="${cy + 3.5}" font-size="12" fill="${INK}" text-anchor="end" font-weight="${isHero ? 600 : 400}">${escapeXml(r.meta.name)}</text>`);
    // Whisker line.
    out.push(`<line x1="${minX}" y1="${cy}" x2="${maxX}" y2="${cy}" stroke="${MUTE}" stroke-width="0.75"/>`);
    out.push(`<line x1="${minX}" y1="${cy - 4}" x2="${minX}" y2="${cy + 4}" stroke="${MUTE}" stroke-width="0.75"/>`);
    out.push(`<line x1="${maxX}" y1="${cy - 4}" x2="${maxX}" y2="${cy + 4}" stroke="${MUTE}" stroke-width="0.75"/>`);
    // Mean bar (on top of whisker).
    out.push(`<rect x="${barAreaX}" y="${cy - 5}" width="${barW.toFixed(2)}" height="10" fill="${fill}" opacity="${isHero ? 1 : 0.85}"/>`);
    // Value text — "mean (min–max)".
    out.push(`<text x="${barAreaX + barAreaW + 6}" y="${cy + 3.5}" font-size="11" fill="${INK}" text-anchor="start" font-weight="${isHero ? 600 : 400}" font-variant-numeric="tabular-nums">${r.mean.toFixed(1)} <tspan fill="${MUTE}" font-size="10">(${r.minR.toFixed(0)}–${r.maxR.toFixed(0)})</tspan></text>`);
  });
  out.push('</svg>');
  return out.join('\n');
}

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
