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

export interface BenchmarkStrings {
  preTitle: string;
  title: string;
  byline: string;
  s1Heading: string;
  s1Body: string;
  s2Heading: string;
  t1Caption: string;
  t1HeaderTool: string;
  t1HeaderVersion: string;
  t1HeaderTotal: string;
  t1NoteEnabled: string;
  t1NoteDisabled: string;
  s3Heading: string;
  s3Body: string;
  t2Caption: string;
  t2HeaderTool: string;
  t2HeaderRatio: string;
  t2HeaderDuration: string;
  t2HeaderRequests: string;
  fig2Caption: string;
  s4Heading: string;
  s4Body: string;
  t3Caption: string;
  fig3Caption: string;
  s5Heading: string;
  s5Body: string;
  fig4Caption: string;
  s6Heading: string;
  s6Body: string;
  scen: Record<string, string>;
  feat: Record<string, string>;
}

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
    acksHeading: string;
    acksLead: string;
    citationHeading: string;
  };
  benchmark: BenchmarkStrings;
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
      acksHeading: 'Acknowledgements',
      acksLead:
        'GitHacker exists because of the security researchers and contributors who reported issues, sent patches, and reviewed work in progress:',
      citationHeading: 'Citation',
    },
    benchmark: {
      preTitle: 'Empirical Study',
      title: 'A Benchmark of <code>.git/</code> Pillagers',
      byline: 'Seven open-source tools, five web-server scenarios, deterministic test repository.',
      s1Heading: 'Setup',
      s1Body: 'A ground-truth Git repository (random seed 0) is served over HTTP under five configurations: Apache and Nginx with directory listing on / off, plus a PHP-LFI entry point. Each tool runs in its own Docker container against the same target, with a 300-second timeout. Full methodology: see <a href="/methodology" class="underline">/methodology</a>.',
      s2Heading: 'Feature Support',
      t1Caption: '✓ = supported by the tool in at least one scenario, ✗ = absent. Tools sorted by total feature count.',
      t1HeaderTool: 'Tool',
      t1HeaderVersion: 'Version',
      t1HeaderTotal: 'Total',
      t1NoteEnabled: 'directory listing enabled',
      t1NoteDisabled: 'directory listing disabled',
      s3Heading: 'Completeness',
      s3Body: 'Mean recovery ratio (% of ground-truth files reconstructed correctly), averaged across all five scenarios. Higher is better. Best in bold.',
      t2Caption: 'Aggregate per-tool metrics, averaged across five scenarios. Best value in each column is bold.',
      t2HeaderTool: 'Tool',
      t2HeaderRatio: 'Recovery (%)',
      t2HeaderDuration: 'Duration (s)',
      t2HeaderRequests: 'HTTP requests',
      fig2Caption: 'Mean recovery per tool with per-scenario min–max whiskers. Tight whiskers around a high mean indicate consistent behavior across deployments.',
      s4Heading: 'Per-Scenario Breakdown',
      s4Body: 'Recovery rate (%) for every (tool, scenario) cell. Empty cells (—) mean the tool did not complete the run.',
      t3Caption: 'Per-scenario recovery rate. Rows in descending mean order, GitHacker highlighted.',
      fig3Caption: 'Monochrome heatmap of the same data as Table 3. Cell darkness encodes recovery rate. Mono ramp chosen so the figure prints to grayscale without losing comparison.',
      s5Heading: 'Cost vs. Completeness',
      s5Body: 'Recovery rate plotted against HTTP requests issued (log scale). One point per (tool, scenario). The Pareto frontier reveals which tools recover the most while issuing the fewest requests.',
      fig4Caption: 'HTTP requests vs. recovery rate, one point per (tool, scenario). Lower-left dots cost less for less return; upper-left is the Pareto sweet spot.',
      s6Heading: 'Discussion',
      s6Body: 'The largest spread is on directory-listing-disabled scenarios where some tools refuse to brute-force tag and branch names — a defensible default but one that costs 30+ percentage points in completeness. The cost-completeness scatter (FIG. 4) shows that high request counts do not buy recovery: the most aggressive tool issues 10× the requests of GitHacker on the same scenario without improving the ratio.',
      scen: {
        'apache-index-enabled':  'Apache (index on)',
        'apache-index-disabled': 'Apache (index off)',
        'nginx-index-enabled':   'Nginx (index on)',
        'nginx-index-disabled':  'Nginx (index off)',
        'php-lfi':               'PHP-LFI',
      },
      feat: {
        source_code: 'Source code',
        reflogs:     'Reflogs',
        stashes:     'Stashes',
        commits:     'Commits',
        branches:    'Branches',
        remotes:     'Remotes',
        tags:        'Tags',
      },
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
      acksHeading: '致谢',
      acksLead:
        'GitHacker 的存在离不开报告问题、提交补丁、审阅在制工作的安全研究者与贡献者：',
      citationHeading: '引用',
    },
    benchmark: {
      preTitle: '实证研究',
      title: '<code>.git/</code> 利用工具基准测试',
      byline: '七款开源工具、五种 Web 服务器场景、确定性测试仓库。',
      s1Heading: '实验设置',
      s1Body: '在固定随机种子（seed=0）下生成 ground-truth Git 仓库，在五种 HTTP 配置下提供服务：Apache / Nginx 各配目录列表开/关，以及一个 PHP-LFI 入口。每个工具在独立 Docker 容器中针对同一目标运行，每次超时 300 秒。完整方法论参见 <a href="/methodology" class="underline">/methodology</a>。',
      s2Heading: '功能支持',
      t1Caption: '✓ = 工具在至少一个场景下支持该功能，✗ = 不支持。按功能总数排序。',
      t1HeaderTool: '工具',
      t1HeaderVersion: '版本',
      t1HeaderTotal: '合计',
      t1NoteEnabled: '目录列表启用',
      t1NoteDisabled: '目录列表禁用',
      s3Heading: '完整率',
      s3Body: '在五种场景下取均值的恢复率（正确重建的 ground-truth 文件比例）。越高越好，最优值加粗。',
      t2Caption: '按工具汇总的指标，在五种场景下取均值。每列最优值加粗。',
      t2HeaderTool: '工具',
      t2HeaderRatio: '恢复率 (%)',
      t2HeaderDuration: '耗时 (s)',
      t2HeaderRequests: 'HTTP 请求数',
      fig2Caption: '各工具的平均恢复率，配以场景间最小–最大值的须线。须线越紧、均值越高，说明跨部署越稳定。',
      s4Heading: '分场景详情',
      s4Body: '每个 (工具, 场景) 单元的恢复率 (%)。空白单元 (—) 表示工具未完成运行。',
      t3Caption: '分场景恢复率。行按平均值降序，GitHacker 高亮。',
      fig3Caption: '与表 3 相同数据的单色热力图。单元颜色深度即恢复率。采用单色梯度是为了灰度打印时也能保留对比。',
      s5Heading: '代价 vs. 完整率',
      s5Body: '恢复率 vs. 发出的 HTTP 请求数（对数刻度），每个 (工具, 场景) 一点。Pareto 前沿揭示了哪些工具用最少的请求换来了最高的恢复。',
      fig4Caption: 'HTTP 请求数 vs. 恢复率，每个 (工具, 场景) 一点。左下方点代价小、收益小；左上方为 Pareto 最优。',
      s6Heading: '讨论',
      s6Body: '差距最大的是目录列表禁用场景：部分工具拒绝暴力枚举分支与 tag 名 —— 这是合理的默认，但代价是 30 个百分点以上的完整率。代价-完整率散点（FIG. 4）显示高请求数并不能换来更高恢复：最激进的工具在同一场景下发出 10× 于 GitHacker 的请求，恢复率却没有提升。',
      scen: {
        'apache-index-enabled':  'Apache (索引开)',
        'apache-index-disabled': 'Apache (索引关)',
        'nginx-index-enabled':   'Nginx (索引开)',
        'nginx-index-disabled':  'Nginx (索引关)',
        'php-lfi':               'PHP-LFI',
      },
      feat: {
        source_code: '源代码',
        reflogs:     'Reflogs',
        stashes:     'Stashes',
        commits:     'Commits',
        branches:    'Branches',
        remotes:     'Remotes',
        tags:        'Tags',
      },
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
