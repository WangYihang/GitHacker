// GitHacker Benchmark - Frontend Application

let benchmarkData = null;
let currentGroup = 'index-enabled';
let currentScenario = null;

// Feature display names
const FEATURE_LABELS = {
  source_code: 'Source Code',
  reflogs: 'Reflogs',
  stashes: 'Stashes',
  commits: 'Commits',
  branches: 'Branches',
  remotes: 'Remotes',
  tags: 'Tags',
};

// Scenario display names
const SCENARIO_LABELS = {
  'apache-index-enabled': 'Apache (Index On)',
  'apache-index-disabled': 'Apache (Index Off)',
  'nginx-index-enabled': 'Nginx (Index On)',
  'nginx-index-disabled': 'Nginx (Index Off)',
  'php-lfi': 'PHP LFI',
};

// Scenario groups
const SCENARIO_GROUPS = {
  'index-enabled': ['apache-index-enabled', 'nginx-index-enabled'],
  'index-disabled': ['apache-index-disabled', 'nginx-index-disabled'],
  'all': null, // all scenarios
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  loadData();
});

async function loadData() {
  try {
    const response = await fetch('data/benchmark.json');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    benchmarkData = await response.json();
    initUI();
  } catch (err) {
    console.error('Failed to load benchmark data:', err);
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('error').classList.remove('hidden');
  }
}

function initUI() {
  document.getElementById('loading').classList.add('hidden');
  document.getElementById('content').classList.remove('hidden');

  renderMetadata();
  setupGroupTabs();
  setupScenarioSelect();
  renderFeatureMatrix();
  renderDetailTable();
  renderScoreCards();
}

function renderMetadata() {
  const meta = benchmarkData.metadata;
  const date = new Date(meta.generated_at).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
  document.getElementById('metadata').innerHTML =
    `Generated: ${date} &middot; Commit: <code class="bg-gray-800 px-1.5 py-0.5 rounded text-xs">${meta.git_commit}</code> &middot; Seed: ${meta.test_repo_seed}`;
}

function setupGroupTabs() {
  document.querySelectorAll('.group-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      currentGroup = btn.dataset.group;
      document.querySelectorAll('.group-tab').forEach(b => {
        b.className = 'group-tab px-4 py-2 rounded-lg text-sm font-medium ' +
          (b === btn ? 'bg-gray-900 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300');
      });
      renderFeatureMatrix();
    });
  });
}

function setupScenarioSelect() {
  const select = document.getElementById('scenario-select');
  benchmarkData.scenarios.forEach(s => {
    const opt = document.createElement('option');
    opt.value = s;
    opt.textContent = SCENARIO_LABELS[s] || s;
    select.appendChild(opt);
  });
  currentScenario = benchmarkData.scenarios[0];
  select.addEventListener('change', () => {
    currentScenario = select.value;
    renderDetailTable();
  });
}

function getScenariosForGroup() {
  if (currentGroup === 'all') return benchmarkData.scenarios;
  return SCENARIO_GROUPS[currentGroup] || benchmarkData.scenarios;
}

function getToolOrder() {
  // Sort tools: githacker first, then alphabetically
  const toolIds = Object.keys(benchmarkData.tools);
  return toolIds.sort((a, b) => {
    if (a === 'githacker') return -1;
    if (b === 'githacker') return 1;
    return a.localeCompare(b);
  });
}

// Aggregate feature support across a group of scenarios.
// A feature is "supported" if it's supported in ANY scenario of the group.
function aggregateFeatures(toolId, scenarios) {
  const features = {};
  for (const feat of benchmarkData.features) {
    let supported = false;
    let totalCorrect = 0;
    let totalFiles = 0;
    for (const scenario of scenarios) {
      const result = benchmarkData.results[toolId]?.[scenario];
      if (result?.features?.[feat]) {
        const f = result.features[feat];
        if (f.supported) supported = true;
        totalCorrect += f.correct;
        totalFiles += f.total;
      }
    }
    const ratio = totalFiles > 0 ? (totalCorrect / totalFiles * 100) : 0;
    features[feat] = { supported, ratio: Math.round(ratio * 100) / 100 };
  }
  return features;
}

function featureIcon(supported, ratio) {
  if (!supported && ratio === 0) {
    return '<span class="icon-unsupported" title="Not supported">&times;</span>';
  }
  if (supported && ratio === 100) {
    return '<span class="icon-supported" title="Fully supported">&check;</span>';
  }
  if (supported && ratio > 0) {
    return `<span class="icon-brute" title="${ratio.toFixed(1)}% recovered">${ratio.toFixed(0)}%</span>`;
  }
  return '<span class="icon-unsupported" title="Not supported">&times;</span>';
}

function renderFeatureMatrix() {
  const scenarios = getScenariosForGroup();
  const toolOrder = getToolOrder();

  let html = '<table class="benchmark-table">';

  // Header
  html += '<thead><tr><th>Tool</th>';
  for (const feat of benchmarkData.features) {
    html += `<th>${FEATURE_LABELS[feat] || feat}</th>`;
  }
  html += '</tr></thead>';

  // Body
  html += '<tbody>';
  for (const toolId of toolOrder) {
    const tool = benchmarkData.tools[toolId];
    const features = aggregateFeatures(toolId, scenarios);
    const isHighlight = toolId === 'githacker';

    html += `<tr class="${isHighlight ? 'highlight' : ''}">`;
    html += `<td><a href="${escapeHtml(tool.url)}" target="_blank" rel="noopener" class="tool-link">${escapeHtml(tool.name)}</a></td>`;
    for (const feat of benchmarkData.features) {
      const f = features[feat];
      html += `<td>${featureIcon(f.supported, f.ratio)}</td>`;
    }
    html += '</tr>';
  }
  html += '</tbody></table>';

  document.getElementById('feature-matrix').innerHTML = html;
}

function renderDetailTable() {
  const scenario = currentScenario;
  const toolOrder = getToolOrder();

  let html = '<table class="benchmark-table">';

  // Header
  html += '<thead><tr>';
  html += '<th>Tool</th><th>Correct</th><th>Total</th><th>Recovery Rate</th><th></th>';
  html += '</tr></thead>';

  // Body
  html += '<tbody>';
  for (const toolId of toolOrder) {
    const tool = benchmarkData.tools[toolId];
    const result = benchmarkData.results[toolId]?.[scenario];
    const isHighlight = toolId === 'githacker';

    if (!result) {
      html += `<tr class="${isHighlight ? 'highlight' : ''}">`;
      html += `<td><a href="${escapeHtml(tool.url)}" target="_blank" rel="noopener" class="tool-link">${escapeHtml(tool.name)}</a></td>`;
      html += '<td colspan="4" class="text-gray-400">No data</td>';
      html += '</tr>';
      continue;
    }

    const ratioClass = result.ratio >= 90 ? 'high' : result.ratio >= 50 ? 'medium' : 'low';
    const hasDetails = (result.different_files?.length > 0 || result.absent_files?.length > 0 || result.features);

    html += `<tr class="${isHighlight ? 'highlight' : ''}" id="row-${toolId}">`;
    html += `<td><a href="${escapeHtml(tool.url)}" target="_blank" rel="noopener" class="tool-link">${escapeHtml(tool.name)}</a></td>`;
    html += `<td>${result.correct}</td>`;
    html += `<td>${result.total}</td>`;
    html += '<td>';
    html += `<div class="flex items-center gap-2">`;
    html += `<span class="text-sm font-medium w-16 text-right">${result.ratio.toFixed(2)}%</span>`;
    html += `<div class="ratio-bar flex-1"><div class="ratio-bar-fill ${ratioClass}" style="width: ${result.ratio}%"></div></div>`;
    html += '</div></td>';
    html += `<td>${hasDetails ? `<span class="detail-toggle" data-tool="${toolId}">Details &#9660;</span>` : ''}</td>`;
    html += '</tr>';

    // Detail row (hidden by default)
    if (hasDetails) {
      html += `<tr class="detail-row" id="detail-${toolId}"><td colspan="5">`;
      html += renderDetailContent(result);
      html += '</td></tr>';
    }
  }
  html += '</tbody></table>';

  document.getElementById('detail-table').innerHTML = html;

  // Attach toggle handlers
  document.querySelectorAll('.detail-toggle').forEach(el => {
    el.addEventListener('click', () => {
      const toolId = el.dataset.tool;
      const detailRow = document.getElementById(`detail-${toolId}`);
      if (detailRow) {
        detailRow.classList.toggle('open');
        el.innerHTML = detailRow.classList.contains('open')
          ? 'Details &#9650;' : 'Details &#9660;';
      }
    });
  });
}

function renderDetailContent(result) {
  let html = '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">';

  // Per-feature breakdown
  if (result.features) {
    html += '<div>';
    html += '<h4 class="text-sm font-semibold text-gray-600 mb-2">Per-Feature Breakdown</h4>';
    html += '<table class="w-full text-sm">';
    for (const feat of benchmarkData.features) {
      const f = result.features[feat];
      if (!f) continue;
      const ratioClass = f.ratio >= 90 ? 'high' : f.ratio >= 50 ? 'medium' : 'low';
      html += '<tr class="border-b border-gray-100">';
      html += `<td class="py-1 text-gray-600">${FEATURE_LABELS[feat] || feat}</td>`;
      html += `<td class="py-1 text-right">${f.correct}/${f.total}</td>`;
      html += `<td class="py-1 w-24"><div class="ratio-bar"><div class="ratio-bar-fill ${ratioClass}" style="width: ${f.ratio}%"></div></div></td>`;
      html += `<td class="py-1 text-right w-16 text-xs">${f.ratio.toFixed(1)}%</td>`;
      html += '</tr>';
    }
    html += '</table></div>';
  }

  // Missing/different files
  html += '<div>';
  if (result.absent_files?.length > 0) {
    html += '<h4 class="text-sm font-semibold text-gray-600 mb-2">Absent Files (' + result.absent_files.length + ')</h4>';
    html += '<ul class="file-list">';
    for (const f of result.absent_files.slice(0, 50)) {
      html += `<li>${escapeHtml(f)}</li>`;
    }
    if (result.absent_files.length > 50) {
      html += `<li class="text-gray-400">... and ${result.absent_files.length - 50} more</li>`;
    }
    html += '</ul>';
  }
  if (result.different_files?.length > 0) {
    html += '<h4 class="text-sm font-semibold text-gray-600 mb-2 mt-3">Different Files (' + result.different_files.length + ')</h4>';
    html += '<ul class="file-list">';
    for (const f of result.different_files.slice(0, 50)) {
      html += `<li>${escapeHtml(f)}</li>`;
    }
    if (result.different_files.length > 50) {
      html += `<li class="text-gray-400">... and ${result.different_files.length - 50} more</li>`;
    }
    html += '</ul>';
  }
  if (!result.absent_files?.length && !result.different_files?.length) {
    html += '<p class="text-sm text-green-600 font-medium">All files recovered correctly.</p>';
  }
  html += '</div>';

  html += '</div>';
  return html;
}

function renderScoreCards() {
  const toolOrder = getToolOrder();
  const container = document.getElementById('score-chart');

  // Calculate average recovery rate across all scenarios
  const scores = {};
  for (const toolId of toolOrder) {
    let totalRatio = 0;
    let count = 0;
    for (const scenario of benchmarkData.scenarios) {
      const result = benchmarkData.results[toolId]?.[scenario];
      if (result) {
        totalRatio += result.ratio;
        count++;
      }
    }
    scores[toolId] = count > 0 ? totalRatio / count : 0;
  }

  // Find best score
  const bestScore = Math.max(...Object.values(scores));

  let html = '';
  for (const toolId of toolOrder) {
    const tool = benchmarkData.tools[toolId];
    const score = scores[toolId];
    const isBest = score === bestScore && score > 0;

    html += `<div class="score-card ${isBest ? 'best' : ''}">`;
    html += `<div class="flex items-center justify-between mb-3">`;
    html += `<a href="${escapeHtml(tool.url)}" target="_blank" rel="noopener" class="font-semibold tool-link">${escapeHtml(tool.name)}</a>`;
    if (isBest) {
      html += '<span class="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full font-medium">Best</span>';
    }
    html += '</div>';

    // Big score number
    html += `<div class="text-3xl font-bold ${score >= 90 ? 'text-green-600' : score >= 50 ? 'text-amber-600' : 'text-red-600'}">${score.toFixed(1)}%</div>`;
    html += '<div class="text-xs text-gray-500 mt-1">Average recovery rate</div>';

    // Per-scenario mini bars
    html += '<div class="mt-3 space-y-1">';
    for (const scenario of benchmarkData.scenarios) {
      const result = benchmarkData.results[toolId]?.[scenario];
      const ratio = result?.ratio || 0;
      const ratioClass = ratio >= 90 ? 'high' : ratio >= 50 ? 'medium' : 'low';
      html += `<div class="flex items-center gap-2 text-xs">`;
      html += `<span class="w-28 text-gray-500 truncate" title="${scenario}">${SCENARIO_LABELS[scenario] || scenario}</span>`;
      html += `<div class="ratio-bar flex-1"><div class="ratio-bar-fill ${ratioClass}" style="width: ${ratio}%"></div></div>`;
      html += `<span class="w-12 text-right text-gray-600">${ratio.toFixed(0)}%</span>`;
      html += '</div>';
    }
    html += '</div>';

    html += '</div>';
  }

  container.innerHTML = html;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
