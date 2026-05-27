/*
 * FIGURE 3 — Scenario × tool heatmap.
 *
 * Monochrome ramp (0 = paper, 100 = ink).  No color: stays useful
 * after grayscale print and avoids the visual gimmick of a chroma
 * heatmap when the data is one-dimensional (percent recovered).
 */

import type { ScenarioResult, ToolMeta } from '../benchmark';

interface Args {
  scenarios: string[];
  scenarioLabels: Record<string, string>;
  tools: Array<{ id: string; meta: ToolMeta }>;
  results: Record<string, Record<string, ScenarioResult>>;
}

const INK = 'var(--ink)';
const PAPER = 'var(--paper)';
const MUTE = 'var(--ink-mute)';
const RULE = 'var(--rule-soft)';

export function heatmapSvg({ scenarios, scenarioLabels, tools, results }: Args): string {
  const cellW = 78;
  const cellH = 28;
  const labelW = 180;
  const headerH = 56;
  const padL = 8;
  const padR = 12;
  const padB = 14;
  const W = labelW + scenarios.length * cellW + padL + padR;
  const H = headerH + tools.length * cellH + padB;

  const out: string[] = [];
  out.push(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Scenario by tool recovery heatmap" font-family="Source Serif 4, Georgia, serif">`);

  // Column headers (rotated slightly for compactness).
  scenarios.forEach((sc, ci) => {
    const x = labelW + ci * cellW + cellW / 2;
    const label = scenarioLabels[sc] || sc;
    out.push(`<text x="${x}" y="${headerH - 8}" font-size="11" fill="${INK}" text-anchor="middle" transform="rotate(-22 ${x} ${headerH - 8})">${escapeXml(label)}</text>`);
  });

  // Cells.
  tools.forEach((t, ri) => {
    const y = headerH + ri * cellH;
    const isHero = t.id === 'githacker';
    out.push(`<text x="${labelW - 8}" y="${y + cellH / 2 + 3.5}" font-size="12" fill="${INK}" text-anchor="end" font-weight="${isHero ? 600 : 400}">${escapeXml(t.meta.name)}</text>`);
    scenarios.forEach((sc, ci) => {
      const r = results[t.id]?.[sc];
      const x = labelW + ci * cellW;
      const v = r?.ratio ?? -1;
      if (v < 0) {
        out.push(`<rect x="${x + 1}" y="${y + 1}" width="${cellW - 2}" height="${cellH - 2}" fill="none" stroke="${RULE}" stroke-dasharray="2 2"/>`);
        out.push(`<text x="${x + cellW / 2}" y="${y + cellH / 2 + 3.5}" font-size="10" fill="${MUTE}" text-anchor="middle">—</text>`);
        return;
      }
      // Opacity ramp 0..1 over 0..100%.
      const op = (v / 100).toFixed(3);
      // Background paper-soft for low values so empty isn't pure white.
      out.push(`<rect x="${x + 1}" y="${y + 1}" width="${cellW - 2}" height="${cellH - 2}" fill="${INK}" fill-opacity="${op}"/>`);
      // Text color flips when fill gets dark.
      const textFill = v > 55 ? PAPER : INK;
      out.push(`<text x="${x + cellW / 2}" y="${y + cellH / 2 + 3.5}" font-size="11" fill="${textFill}" text-anchor="middle" font-variant-numeric="tabular-nums">${v.toFixed(0)}</text>`);
    });
  });

  out.push('</svg>');
  return out.join('\n');
}

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
