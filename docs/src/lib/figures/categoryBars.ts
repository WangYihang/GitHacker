/*
 * FIGURE 5 — Resistance by attack category.
 *
 * Horizontal stacked bars per tool: each bar segment is "PASS count
 * within category X / total tests in X".  Categories typically:
 * RCE, AFW (arbitrary file write), Info (disclosure), CVE (git CVEs).
 * GitHacker uses the accent fill for its PASS segments to keep visual
 * continuity with the other figures.
 */

import type { SecurityToolMeta } from '../security';

interface Row {
  id: string;
  meta: SecurityToolMeta;
  perCategory: Record<string, { pass: number; total: number }>;
}

const ACCENT = 'var(--accent)';
const INK = 'var(--ink)';
const MUTE = 'var(--ink-mute)';
const RULE = 'var(--rule-soft)';
const PAPER = 'var(--paper)';

export function categoryBarsSvg(rows: Row[], categoryOrder: string[]): string {
  const W = 720;
  const labelW = 180;
  const padR = 56;
  const padTop = 28;
  const padBot = 38;
  const rowH = 26;
  const barAreaX = labelW;
  const barAreaW = W - labelW - padR;
  const H = padTop + rows.length * rowH + padBot;

  // Total tests across all categories (assume the same for every tool;
  // use max from first non-empty row).
  let totalTests = 0;
  for (const r of rows) {
    let n = 0;
    for (const c of categoryOrder) n += r.perCategory[c]?.total || 0;
    if (n > totalTests) totalTests = n;
  }
  if (!totalTests) totalTests = 1;

  const out: string[] = [];
  out.push(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Resistance by attack category" font-family="Source Serif 4, Georgia, serif">`);

  // Header / legend.
  let lx = barAreaX;
  for (const cat of categoryOrder) {
    out.push(`<rect x="${lx}" y="${padTop - 18}" width="10" height="10" fill="${INK}" opacity="${categoryOpacity(cat)}"/>`);
    out.push(`<text x="${lx + 14}" y="${padTop - 8}" font-size="11" fill="${INK}">${escapeXml(cat)}</text>`);
    lx += 78;
  }

  // Axis ticks (0 / 50% / 100% of test count).
  for (const t of [0, 0.5, 1]) {
    const x = barAreaX + t * barAreaW;
    out.push(`<line x1="${x}" y1="${padTop}" x2="${x}" y2="${H - padBot + 2}" stroke="${RULE}" stroke-width="0.5"/>`);
    out.push(`<text x="${x}" y="${H - padBot + 16}" font-size="10" fill="${MUTE}" text-anchor="middle" font-variant-numeric="tabular-nums">${Math.round(t * totalTests)}</text>`);
  }
  out.push(`<text x="${barAreaX + barAreaW / 2}" y="${H - 8}" font-size="10" fill="${MUTE}" text-anchor="middle">PASS count (out of ${totalTests} tests)</text>`);

  rows.forEach((r, i) => {
    const y = padTop + i * rowH;
    const cy = y + rowH / 2;
    const isHero = r.id === 'githacker';
    out.push(`<text x="${labelW - 8}" y="${cy + 3.5}" font-size="12" fill="${INK}" text-anchor="end" font-weight="${isHero ? 600 : 400}">${escapeXml(r.meta.name)}</text>`);

    let x = barAreaX;
    let totalPass = 0;
    for (const cat of categoryOrder) {
      const cell = r.perCategory[cat];
      const pass = cell?.pass ?? 0;
      totalPass += pass;
      if (!pass) continue;
      const w = (pass / totalTests) * barAreaW;
      const fill = isHero ? ACCENT : INK;
      out.push(`<rect x="${x}" y="${cy - 7}" width="${w.toFixed(2)}" height="14" fill="${fill}" opacity="${categoryOpacity(cat)}"/>`);
      // Inline count if there's room.
      if (w > 16) {
        const tx = x + w / 2;
        const textFill = isHero || categoryOpacity(cat) > 0.55 ? PAPER : INK;
        out.push(`<text x="${tx}" y="${cy + 3.5}" font-size="10" fill="${textFill}" text-anchor="middle" font-variant-numeric="tabular-nums">${pass}</text>`);
      }
      x += w;
    }
    // Trailing total at the right.
    out.push(`<text x="${barAreaX + barAreaW + 6}" y="${cy + 3.5}" font-size="11" fill="${INK}" text-anchor="start" font-weight="${isHero ? 600 : 400}" font-variant-numeric="tabular-nums">${totalPass}/${totalTests}</text>`);
  });

  out.push('</svg>');
  return out.join('\n');
}

// Encode category as a fixed opacity step on the ink ramp so the
// figure prints cleanly to grayscale.  Order: RCE (darkest) > CVE > AFW > Info.
function categoryOpacity(cat: string): number {
  switch (cat) {
    case 'RCE':  return 1.0;
    case 'CVE':  return 0.75;
    case 'AFW':  return 0.5;
    case 'Info': return 0.3;
    default:     return 0.6;
  }
}

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
