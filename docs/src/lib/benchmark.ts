/*
 * Typed loader and aggregators for benchmark data.
 *
 * The raw JSON lives at /public/data/benchmark.json and is regenerated
 * by `python -m benchmark run`.  At build time, Astro pages import the
 * JSON via Vite's JSON loader, then narrow it through the shapes below.
 */

import raw from '../../public/data/benchmark.json';

export interface ToolMeta {
  name: string;
  url: string;
  version: string;
}

export interface FeatureStat {
  correct: number;
  total: number;
  ratio: number;
  supported?: boolean;
}

export interface ScenarioResult {
  correct: number;
  total: number;
  ratio: number;
  duration?: number;
  http_requests?: number;
  features?: Record<string, FeatureStat>;
  absent_files?: string[];
  different_files?: string[];
}

export interface BenchmarkData {
  metadata: { generated_at: string; git_commit: string; test_repo_seed: number; note?: string };
  tools: Record<string, ToolMeta>;
  scenarios: string[];
  features: string[];
  results: Record<string, Record<string, ScenarioResult>>;
}

export const benchmark = raw as BenchmarkData;

/** Tools sorted by mean recovery rate, descending; GitHacker first on ties. */
export function rankedTools(): Array<{ id: string; meta: ToolMeta; mean: number; minR: number; maxR: number; meanRequests: number; meanDuration: number }> {
  const out: Array<{ id: string; meta: ToolMeta; mean: number; minR: number; maxR: number; meanRequests: number; meanDuration: number }> = [];
  for (const [id, meta] of Object.entries(benchmark.tools)) {
    const ratios: number[] = [];
    let sumReq = 0;
    let sumDur = 0;
    let n = 0;
    for (const sc of benchmark.scenarios) {
      const r = benchmark.results[id]?.[sc];
      if (!r) continue;
      ratios.push(r.ratio);
      sumReq += r.http_requests ?? 0;
      sumDur += r.duration ?? 0;
      n++;
    }
    if (!ratios.length) continue;
    const mean = ratios.reduce((a, b) => a + b, 0) / ratios.length;
    out.push({
      id,
      meta,
      mean,
      minR: Math.min(...ratios),
      maxR: Math.max(...ratios),
      meanRequests: n ? sumReq / n : 0,
      meanDuration: n ? sumDur / n : 0,
    });
  }
  out.sort((a, b) => {
    if (a.mean !== b.mean) return b.mean - a.mean;
    if (a.id === 'githacker') return -1;
    if (b.id === 'githacker') return 1;
    return a.meta.name.localeCompare(b.meta.name);
  });
  return out;
}
