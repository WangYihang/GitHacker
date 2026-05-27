/*
 * Typed loader for the security suite results.
 *
 * Same pattern as lib/benchmark.ts: Vite imports the JSON at build
 * time, we narrow it through these shapes, downstream figures and
 * page components consume the typed view.
 */

import raw from '../../public/data/security.json';

export type Verdict = 'PASS' | 'FAIL' | 'TIMEOUT' | 'ERROR';
export type Severity = 'H' | 'M' | 'L';

export interface SecurityToolMeta {
  name: string;
  url: string;
  version: string;
}

export interface ToolRun {
  verdict: Verdict;
  evidence?: string;
  duration?: number;
  exit_code?: number;
  stderr_tail?: string;
}

export interface TestData {
  id: string;
  category: 'RCE' | 'AFW' | 'Info' | 'CVE' | string;
  severity: Severity;
  description: string;
  cve?: string | null;
  results: Record<string, ToolRun>;
}

export interface Disclosure {
  id: string;
  test: string;
  tool: string;
  severity: Severity;
  status: string;
  first_observed: string;
  reported_at?: string;
  patched_at?: string;
  cve?: string;
  notes?: string;
}

export interface SecurityReport {
  schema_version: number;
  generated_at: string;
  git_commit: string;
  tools: Record<string, SecurityToolMeta>;
  tests: TestData[];
  disclosures?: Disclosure[];
  embargo_count?: number;
}

export const security = raw as SecurityReport;

/** Tools ordered: GitHacker first, then alphabetical by display name. */
export function orderedToolIds(): string[] {
  return Object.keys(security.tools).sort((a, b) => {
    if (a === 'githacker') return -1;
    if (b === 'githacker') return 1;
    return security.tools[a].name.localeCompare(security.tools[b].name);
  });
}

/** PASS / total counts per tool over public (non-embargoed) tests. */
export function passCount(toolId: string): { pass: number; total: number } {
  let pass = 0;
  let total = 0;
  for (const t of security.tests) {
    const r = t.results[toolId];
    if (!r) continue;
    total++;
    if (r.verdict === 'PASS') pass++;
  }
  return { pass, total };
}

/** PASS counts grouped by category, per tool. */
export function passByCategory(toolId: string): Record<string, { pass: number; total: number }> {
  const out: Record<string, { pass: number; total: number }> = {};
  for (const t of security.tests) {
    const r = t.results[toolId];
    if (!r) continue;
    out[t.category] = out[t.category] || { pass: 0, total: 0 };
    out[t.category].total++;
    if (r.verdict === 'PASS') out[t.category].pass++;
  }
  return out;
}
