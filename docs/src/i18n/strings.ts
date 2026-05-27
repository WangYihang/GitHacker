/*
 * Centralized bilingual strings for the docs site.
 *
 * Render at SSR with `t(strings.en.home.abstract)` for the default
 * (English) HTML, and tag the same node with `data-i18n="home.abstract"`
 * so the runtime swap script can replace it from the `zh` slice when
 * the user toggles language.  Captions for figures and tables stay in
 * English regardless — that's academic convention.
 */

export type Lang = 'en' | 'zh';

export interface Strings {
  common: {
    generated: string;
    randomSeed: string;
    commit: string;
    home: string;
    benchmark: string;
    security: string;
    github: string;
    pypi: string;
    pageOf: string;
  };
  home: {
    titleLine1: string;
    titleLine2: string;
    abstractHeading: string;
    abstract: string;
    introHeading: string;
    intro: string;
    findingsHeading: string;
    findingsLead: string;
    finding1: string;
    finding2: string;
    finding3: string;
    figure1Caption: string;
    reproduceHeading: string;
    reproduce: string;
    reproduceCta: string;
    relatedHeading: string;
    relatedLead: string;
    citationHeading: string;
  };
}

export const strings: Record<Lang, Strings> = {
  en: {
    common: {
      generated: 'Generated',
      randomSeed: 'random seed',
      commit: 'commit',
      home: 'Home',
      benchmark: 'Benchmark',
      security: 'Security',
      github: 'GitHub',
      pypi: 'PyPI',
      pageOf: 'page of',
    },
    home: {
      titleLine1: 'GitHacker',
      titleLine2: 'An Empirical Study of <code>.git</code> Leakage Exploitation',
      abstractHeading: 'Abstract',
      abstract:
        'When a web server inadvertently exposes its <code>.git</code> directory, the entire repository — including its source code, commit history, branches, and stashes — becomes reconstructible by anyone with HTTP access. We benchmark seven open-source pillagers across five server configurations and fifteen adversarial scenarios, and find that completeness varies by more than 60 percentage points across tools, that the most aggressive tool issues ten times more HTTP requests than the most efficient one, and that every pillager except <em>GitHacker</em> currently fails at least one published code-execution test against a malicious <code>.git</code>. We publish a reproducible benchmark, full per-scenario data, and a coordinated-disclosure tracker for unresolved findings.',
      introHeading: 'Introduction',
      intro:
        'A leaked <code>.git</code> directory is the most concentrated form of source-code disclosure a web target can suffer: a single misconfiguration exposes commit history, deleted branches, abandoned stashes, and any credentials a developer once committed in error. Despite a decade of off-the-shelf exploitation tools, no two pillagers behave identically — one will brute-force tag names that another silently skips, one will follow a malicious redirect into the attacker\'s filesystem while another refuses. This site reports a side-by-side measurement.',
      findingsHeading: 'Summary of Findings',
      findingsLead:
        'Three findings emerge from our measurement; each links to the underlying data:',
      finding1:
        '<strong>Completeness varies by 60+ points.</strong>  Mean recovery rate across the five web-server scenarios ranges from below 30% (legacy single-threaded tools) to above 95% (GitHacker, git-dumper).  See <a href="/benchmark#completeness">Benchmark §3</a>.',
      finding2:
        '<strong>HTTP cost is not free.</strong>  The most aggressive tool issues an order of magnitude more requests for an equal-or-worse recovery.  Quiet, targeted brute-force matters.  See <a href="/benchmark#cost">Benchmark §5</a>.',
      finding3:
        '<strong>Every tool except GitHacker fails at least one adversarial test.</strong>  Six of seven pillagers are vulnerable to <code>core.fsmonitor</code> code execution from a malicious <code>.git/config</code>; SSRF and arbitrary-file-write findings remain under embargo pending upstream patches.  See <a href="/security">Security</a>.',
      figure1Caption:
        'Mean completeness ratio per tool, averaged across five web-server scenarios (Apache / Nginx, directory-index on / off, PHP-LFI).  GitHacker shown in accent; bars sorted descending.',
      reproduceHeading: 'Reproduce',
      reproduce:
        'The entire benchmark — server containers, tool containers, test repository generator, scoring harness — runs from a single Docker invocation:',
      reproduceCta: 'Full instructions ›',
      relatedHeading: 'Related Work',
      relatedLead:
        'Justin Steven\'s 2022 advisory documents the original <code>core.fsmonitor</code> RCE in <code>.git/config</code>; Driver Tom\'s 2021 blog post catalogued generic counter-attacks against source-code pillagers; Git\'s own security advisory feed lists more than a dozen CVEs reachable via <code>git clone</code> of a hostile repository.',
      citationHeading: 'Citation',
    },
  },
  zh: {
    common: {
      generated: '生成时间',
      randomSeed: '随机种子',
      commit: '提交',
      home: '首页',
      benchmark: '基准测试',
      security: '安全',
      github: 'GitHub',
      pypi: 'PyPI',
      pageOf: '页 /',
    },
    home: {
      titleLine1: 'GitHacker',
      titleLine2: '<code>.git</code> 泄露利用的实证研究',
      abstractHeading: '摘要',
      abstract:
        '当 Web 服务器无意中暴露 <code>.git</code> 目录后，任何能访问该 HTTP 端点的人都可以重建整个仓库 —— 源代码、提交历史、分支、stash 一应俱全。我们在 5 种服务器配置、15 个对抗场景下对 7 款开源 pillager 工具进行系统评测，发现：工具间的完整率差距超过 60 个百分点；最激进的工具发出的 HTTP 请求数比最高效的多十倍；除 <em>GitHacker</em> 外，所有 pillager 在面对恶意 <code>.git</code> 时至少有一项已公开的代码执行测试未通过。本站发布可复现的基准、逐场景的完整数据，以及未公开发现的协调披露跟踪。',
      introHeading: '研究背景',
      intro:
        '泄露的 <code>.git</code> 目录是 Web 目标可能遭遇的最浓缩的源代码披露：一次错误配置即可暴露提交历史、已删分支、被遗忘的 stash 以及任何曾被误提交的凭据。即便业界已有十年现成的利用工具，没有两款 pillager 行为完全一致 —— 一款会暴力枚举另一款悄悄跳过的 tag 名称；一款会顺着恶意重定向落入攻击者的文件系统，另一款则拒绝。本站记录一次横向测量。',
      findingsHeading: '主要发现',
      findingsLead: '我们的测量得到三条主要发现，每条均链入底层数据：',
      finding1:
        '<strong>完整率差距超过 60 个百分点。</strong>五种 Web 服务器场景下的平均恢复率，从 30% 以下（老式单线程工具）到 95% 以上（GitHacker、git-dumper）。详见 <a href="/benchmark#completeness">Benchmark §3</a>。',
      finding2:
        '<strong>HTTP 代价并非可忽略。</strong>最激进的工具发出的请求数高出一个数量级，恢复率却相当甚至更差。安静、精准的暴力枚举有其价值。详见 <a href="/benchmark#cost">Benchmark §5</a>。',
      finding3:
        '<strong>除 GitHacker 外，所有工具至少一项对抗测试失败。</strong>7 款 pillager 中有 6 款会被恶意 <code>.git/config</code> 里的 <code>core.fsmonitor</code> 命令执行打穿；SSRF 与任意文件写入的发现尚在禁运、等待上游修复。详见 <a href="/security">Security</a>。',
      figure1Caption:
        'Mean completeness ratio per tool, averaged across five web-server scenarios (Apache / Nginx, directory-index on / off, PHP-LFI).  GitHacker shown in accent; bars sorted descending.',
      reproduceHeading: '复现',
      reproduce: '完整基准 —— 服务器容器、工具容器、测试仓库生成器、评分管线 —— 可通过单条 Docker 命令运行：',
      reproduceCta: '完整说明 ›',
      relatedHeading: '相关工作',
      relatedLead:
        'Justin Steven 在 2022 年的安全通告中记录了恶意 <code>.git/config</code> 的 <code>core.fsmonitor</code> RCE；Driver Tom 在 2021 年的博文中梳理了针对源码偷盗者的通用反制；Git 官方安全通告列出了十余个可通过 <code>git clone</code> 恶意仓库触发的 CVE。',
      citationHeading: '引用',
    },
  },
};

/**
 * Convenience: get an i18n value from a "page.key" dotted path against
 * the given language.  Returns the English value if the zh translation
 * is missing.
 */
export function pick(lang: Lang, key: string): string {
  const path = key.split('.');
  const dig = (obj: any): any => path.reduce((o, p) => (o ? o[p] : undefined), obj);
  return dig(strings[lang]) ?? dig(strings.en) ?? '';
}
