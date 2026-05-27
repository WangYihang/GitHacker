/*
 * FIGURE 1 — Tool completeness leaderboard.
 *
 * Hand-rolled SVG: horizontal bars, sorted descending, GitHacker in
 * accent.  Pure function: rankedTools() result in, SVG string out.
 * Build-time only — no runtime JS shipped.
 */

import type { ToolMeta } from '../benchmark';

interface Row {
  id: string;
  meta: ToolMeta;
  mean: number;
}

const ACCENT = 'var(--accent)';
const INK = 'var(--ink)';
const RULE = 'var(--rule-soft)';
const MUTE = 'var(--ink-mute)';

export function leaderboardSvg(rows: Row[]): string {
  const W = 600;
  const labelW = 168;
  const valueW = 56;
  const barAreaX = labelW;
  const barAreaW = W - labelW - valueW - 12;
  const rowH = 22;
  const padTop = 6;
  const padBot = 16;
  const H = padTop + rows.length * rowH + padBot;

  const max = 100; // recovery ratio is a percentage

  const lines: string[] = [];
  lines.push(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Mean completeness per tool" font-family="Source Serif 4, Georgia, serif">`,
  );
  // Axis ticks: 0 / 50 / 100 at top, faint vertical guides.
  for (const t of [0, 25, 50, 75, 100]) {
    const x = barAreaX + (t / max) * barAreaW;
    lines.push(
      `<line x1="${x}" y1="${padTop}" x2="${x}" y2="${H - padBot + 2}" stroke="${RULE}" stroke-width="0.5"/>`,
    );
    lines.push(
      `<text x="${x}" y="${H - 4}" font-size="9.5" fill="${MUTE}" text-anchor="middle">${t}</text>`,
    );
  }

  rows.forEach((r, i) => {
    const y = padTop + i * rowH;
    const cy = y + rowH / 2;
    const isHero = r.id === 'githacker';
    const fill = isHero ? ACCENT : INK;
    const barW = (r.mean / max) * barAreaW;

    // Tool label, right-aligned.
    lines.push(
      `<text x="${labelW - 8}" y="${cy + 3.5}" font-size="12" fill="${INK}" text-anchor="end" font-weight="${isHero ? 600 : 400}">${escapeXml(r.meta.name)}</text>`,
    );
    // Bar.
    lines.push(
      `<rect x="${barAreaX}" y="${cy - 5}" width="${barW.toFixed(2)}" height="10" fill="${fill}" ${isHero ? '' : 'opacity="0.85"'}/>`,
    );
    // Value (right of bar).
    lines.push(
      `<text x="${barAreaX + barW + 6}" y="${cy + 3.5}" font-size="11" fill="${INK}" text-anchor="start" font-weight="${isHero ? 600 : 400}" font-variant-numeric="tabular-nums">${r.mean.toFixed(1)}%</text>`,
    );
  });
  lines.push('</svg>');
  return lines.join('\n');
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
