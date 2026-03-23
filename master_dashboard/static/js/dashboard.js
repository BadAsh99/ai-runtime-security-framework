/* AIRS Dashboard — SSE + Red Team + D3 Attack Chain Animation */

// ── SSE Audit Stream ───────────────────────────────────────────────────────
function initAuditStream() {
  const feed = document.getElementById('audit-feed');
  if (!feed) return;

  const es = new EventSource('/api/audit/stream');

  es.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      prependAuditEntry(feed, data);
    } catch (e) {}
  };

  es.onerror = () => {
    setTimeout(() => initAuditStream(), 5000);
    es.close();
  };
}

function prependAuditEntry(feed, data) {
  const level = data.threat_level || 'clean';
  const action = data.action_taken || '';
  const ts = data.timestamp ? new Date(data.timestamp).toLocaleTimeString() : '';
  const app = data.app_id || 'gateway';
  const patterns = (data.matched_patterns || []).join(', ') || '—';
  const cls = ['critical','high'].includes(level) ? 'threat' : level;

  const el = document.createElement('div');
  el.className = `audit-entry ${cls}`;
  el.innerHTML = `
    <span class="audit-time">${ts}</span>
    <span class="audit-app">${app}</span>
    <span class="audit-action">
      <span class="sev ${action || level}">${action || level}</span>
      ${patterns !== '—' ? `<span style="color:var(--text-muted)"> · ${patterns}</span>` : ''}
    </span>`;

  feed.insertBefore(el, feed.firstChild);
  while (feed.children.length > 100) feed.removeChild(feed.lastChild);
}

// ── Red Team Panel ─────────────────────────────────────────────────────────
let selectedPayload = null;
let selectedPayloadText = null;

function selectPayload(el, payloadId, payloadText) {
  document.querySelectorAll('.payload-item').forEach(p => p.classList.remove('selected'));
  el.classList.add('selected');
  selectedPayload = payloadId;
  selectedPayloadText = payloadText;
  document.getElementById('payload-text').value = payloadText || '';
  document.getElementById('selected-pid').textContent = payloadId;
}

async function selectPayloadFromLib(el, payloadId) {
  document.querySelectorAll('.payload-item').forEach(p => p.classList.remove('selected'));
  el.classList.add('selected');
  selectedPayload = payloadId;
  document.getElementById('selected-pid').textContent = payloadId;
  document.getElementById('payload-text').value = 'Loading...';
  document.getElementById('fire-result').style.display = 'none';
  try {
    const res = await fetch(`/api/red-team/payload/${payloadId}`);
    const data = await res.json();
    selectedPayloadText = data.text || '';
    document.getElementById('payload-text').value = selectedPayloadText;
  } catch(e) {
    document.getElementById('payload-text').value = `[${payloadId}] payload`;
  }
}

async function firePayload() {
  const target = document.getElementById('target-select')?.value || 'gateway';
  const payloadText = document.getElementById('payload-text')?.value || '';
  const resultBox = document.getElementById('fire-result');

  if (!payloadText.trim()) { alert('Enter a payload first'); return; }

  const btn = document.getElementById('fire-btn');
  btn.disabled = true;
  btn.textContent = 'Firing...';
  if (resultBox) { resultBox.style.display = 'block'; resultBox.textContent = 'Sending...'; }

  try {
    const res = await fetch('/api/red-team/fire', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ target, payload: payloadText, payload_id: selectedPayload || 'manual' }),
    });
    const data = await res.json();

    if (resultBox) {
      const detected = data.detected;
      resultBox.className = `result-box ${detected ? 'detected' : 'clean'}`;
      resultBox.textContent = JSON.stringify(data, null, 2);
    }

    const status = document.getElementById('fire-status');
    if (status) {
      status.textContent = data.detected ? '🔴 DETECTED' : '🟢 PASSED (not detected)';
      status.style.color = data.detected ? 'var(--critical)' : 'var(--up)';
    }
  } catch(e) {
    if (resultBox) resultBox.textContent = `Error: ${e.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Fire Payload';
  }
}

// ── D3 Attack Chain Graphs ─────────────────────────────────────────────────
// Stores live SVG references per chain for animation
const chainGraphs = {};

const NODE_COLORS = {
  'Attacker':          '#f85149',
  'content-mod':       '#0ea5e9',
  'finance':           '#10b981',
  'support':           '#f59e0b',
  'Shared LLM':        '#8b5cf6',
  'External Systems':  '#f85149',
  'gateway':           '#6366f1',
};

const NODE_PORTS = {
  'gateway':           '8000',
  'content-mod':       '8001',
  'finance':           '8002',
  'support':           '8003',
};

const MITRE_LABELS = {
  'AML.T0054':         'Prompt Injection (LLM01)',
  'AML.T0054.002':     'Indirect Prompt Injection (LLM01)',
  'AML.T0054.003':     'Multi-Stage Injection (LLM01)',
};

// Shared floating tooltip element
let _tooltip = null;
function getTooltip() {
  if (!_tooltip) {
    _tooltip = document.createElement('div');
    _tooltip.className = 'graph-tooltip';
    document.body.appendChild(_tooltip);
  }
  return _tooltip;
}

function showTooltip(html, x, y) {
  const tt = getTooltip();
  tt.innerHTML = html;
  // Keep tooltip inside viewport
  const pad = 16;
  const vw = window.innerWidth, vh = window.innerHeight;
  let tx = x + 14, ty = y - 10;
  tt.classList.add('visible');
  // Apply position then check bounds
  tt.style.left = `${tx}px`;
  tt.style.top  = `${ty}px`;
  const rect = tt.getBoundingClientRect();
  if (rect.right  > vw - pad) tx = x - rect.width  - 14;
  if (rect.bottom > vh - pad) ty = y - rect.height  + 10;
  tt.style.left = `${tx}px`;
  tt.style.top  = `${ty}px`;
}

function hideTooltip() {
  const tt = getTooltip();
  tt.classList.remove('visible');
}

async function renderAttackChains() {
  const container = document.getElementById('chain-graphs');
  if (!container || typeof d3 === 'undefined') return;

  let chains;
  try {
    const res = await fetch('/api/attack-chains');
    chains = await res.json();
  } catch(e) { return; }

  chains.forEach(chain => {
    const div = document.getElementById(`graph-${chain.chain_id}`);
    if (!div) return;
    renderChainGraph(div, chain);
  });
}

function renderChainGraph(container, chain) {
  const W = Math.max(container.clientWidth || 640, 400);
  const H = 220;
  const nodeW = 124, nodeH = 36, rx = 7;

  // Collect ordered unique nodes
  const nodeNames = [];
  chain.steps.forEach(s => {
    if (!nodeNames.includes(s.from)) nodeNames.push(s.from);
    if (!nodeNames.includes(s.to))   nodeNames.push(s.to);
  });

  // Fixed x positions spaced evenly, free y with slight variation via simulation
  const gap = (W - 48) / nodeNames.length;
  const nodes = nodeNames.map((id, i) => ({
    id,
    fx: 24 + gap * i + gap / 2,   // fixed x — preserves L→R attack flow
    y:  H / 2,
  }));

  const linkData = chain.steps.map(s => ({
    source: s.from,
    target: s.to,
    step:   s.step,
    action: s.action || '',
    payload_id: s.payload_id || null,
    mitre: s.mitre_atlas || chain.mitre_atlas || null,
  }));

  const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));

  // Resolve link objects (D3 forceLink needs object refs)
  const links = linkData.map(l => ({
    ...l,
    source: nodeMap[l.source],
    target: nodeMap[l.target],
  }));

  const svg = d3.select(container).append('svg')
    .attr('width', '100%').attr('height', H)
    .attr('viewBox', `0 0 ${W} ${H}`)
    .style('overflow', 'visible');

  const defs = svg.append('defs');

  // Default arrow
  defs.append('marker')
    .attr('id', `arrow-${chain.chain_id}`)
    .attr('viewBox', '0 -5 10 10').attr('refX', 10).attr('refY', 0)
    .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#30363d');

  // Active (red) arrow
  defs.append('marker')
    .attr('id', `arrow-active-${chain.chain_id}`)
    .attr('viewBox', '0 -5 10 10').attr('refX', 10).attr('refY', 0)
    .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#f85149');

  // Edge group
  const edgeGroup = svg.append('g').attr('class', 'edges');
  const edgeEls = {};

  const edgePaths = edgeGroup.selectAll('path').data(links).enter().append('path')
    .attr('class', d => `chain-edge step-${d.step}`)
    .attr('fill', 'none')
    .attr('stroke', '#30363d')
    .attr('stroke-width', 2)
    .attr('marker-end', `url(#arrow-${chain.chain_id})`)
    .style('cursor', 'pointer')
    .on('mouseenter', function(event, d) {
      const mitreLong = MITRE_LABELS[d.mitre] || d.mitre || '—';
      showTooltip(`
        <div class="graph-tooltip-title">Step ${d.step}</div>
        <div class="graph-tooltip-row"><span class="graph-tooltip-label">Action:</span><span class="graph-tooltip-val">${d.action || '—'}</span></div>
        ${d.payload_id ? `<div class="graph-tooltip-row"><span class="graph-tooltip-label">Payload:</span><span class="graph-tooltip-val">${d.payload_id}</span></div>` : ''}
        <div class="graph-tooltip-row"><span class="graph-tooltip-label">MITRE:</span><span class="graph-tooltip-val">${mitreLong}</span></div>
      `, event.clientX, event.clientY);
      d3.select(this).attr('stroke', '#58a6ff').attr('stroke-width', 2.5);
    })
    .on('mousemove', (event) => showTooltip(getTooltip().innerHTML, event.clientX, event.clientY))
    .on('mouseleave', function(d) {
      hideTooltip();
      d3.select(this)
        .attr('stroke', function() { return this.getAttribute('data-active') === '1' ? '#f85149' : '#30363d'; })
        .attr('stroke-width', function() { return this.getAttribute('data-active') === '1' ? 3 : 2; });
    });

  edgePaths.each(function(d) { edgeEls[d.step] = d3.select(this); });

  // Step labels (mid-arc)
  edgeGroup.selectAll('text.step-label').data(links).enter().append('text')
    .attr('class', 'step-label')
    .attr('text-anchor', 'middle')
    .attr('font-size', 10).attr('fill', '#8b949e')
    .attr('pointer-events', 'none');

  const stepLabels = edgeGroup.selectAll('text.step-label');

  // Node group
  const nodeGroup = svg.append('g').attr('class', 'nodes');
  const nodeRects = {};
  const nodeGs = nodeGroup.selectAll('g.node').data(nodes).enter().append('g').attr('class', 'node');

  nodeGs.append('rect')
    .attr('width', nodeW).attr('height', nodeH)
    .attr('x', -nodeW / 2).attr('y', -nodeH / 2)
    .attr('rx', rx)
    .attr('fill', d => (NODE_COLORS[d.id] || '#21262d') + '33')
    .attr('stroke', d => NODE_COLORS[d.id] || '#30363d')
    .attr('stroke-width', 1.5)
    .each(function(d) { nodeRects[d.id] = d3.select(this); });

  nodeGs.append('text')
    .attr('text-anchor', 'middle').attr('dy', '0.35em')
    .attr('font-size', 11).attr('font-weight', 600)
    .attr('fill', d => NODE_COLORS[d.id] || '#e6edf3')
    .attr('pointer-events', 'none')
    .text(d => d.id);

  // Node tooltip
  nodeGs.style('cursor', 'pointer')
    .on('mouseenter', function(event, d) {
      const port = NODE_PORTS[d.id];
      showTooltip(`
        <div class="graph-tooltip-title">${d.id}</div>
        ${port ? `<div class="graph-tooltip-row"><span class="graph-tooltip-label">Port:</span><span class="graph-tooltip-val">${port}</span></div>` : ''}
        <div class="graph-tooltip-row"><span class="graph-tooltip-label">Color:</span><span class="graph-tooltip-val" style="color:${NODE_COLORS[d.id]||'#e6edf3'}">${NODE_COLORS[d.id] || 'default'}</span></div>
      `, event.clientX, event.clientY);
    })
    .on('mousemove', (event) => showTooltip(getTooltip().innerHTML, event.clientX, event.clientY))
    .on('mouseleave', () => hideTooltip());

  // Force simulation — fixed x, free y with light centering
  const sim = d3.forceSimulation(nodes)
    .force('link',    d3.forceLink(links).id(d => d.id).distance(gap * 0.85).strength(0.3))
    .force('body',    d3.forceManyBody().strength(-60))
    .force('y',       d3.forceY(H / 2).strength(0.5))
    .force('collide', d3.forceCollide(nodeW / 2 + 8))
    .alpha(0.6)
    .on('tick', ticked);

  function bezierPath(d) {
    const sx = d.source.fx ?? d.source.x, sy = d.source.y;
    const tx = d.target.fx ?? d.target.x, ty = d.target.y;
    // Offset endpoints to edge of node rect
    const dx = tx - sx, dy = ty - sy;
    const len = Math.sqrt(dx * dx + dy * dy) || 1;
    const ux = dx / len, uy = dy / len;
    const x1 = sx + ux * (nodeW / 2 + 2), y1 = sy + uy * (nodeH / 2 + 2);
    const x2 = tx - ux * (nodeW / 2 + 14), y2 = ty - uy * (nodeH / 2 + 2);
    // Cubic bezier with slight vertical bow
    const bow = Math.abs(tx - sx) * 0.15;
    const cpx1 = x1 + dx * 0.33, cpy1 = y1 - bow;
    const cpx2 = x2 - dx * 0.33, cpy2 = y2 - bow;
    return `M${x1},${y1} C${cpx1},${cpy1} ${cpx2},${cpy2} ${x2},${y2}`;
  }

  function ticked() {
    nodeGs.attr('transform', d => `translate(${d.fx ?? d.x},${d.y})`);

    edgePaths.attr('d', bezierPath);

    // Position step labels at midpoint of bezier
    stepLabels.each(function(d) {
      const sx = d.source.fx ?? d.source.x, sy = d.source.y;
      const tx = d.target.fx ?? d.target.x, ty = d.target.y;
      const mx = (sx + tx) / 2, my = Math.min(sy, ty) - 18;
      d3.select(this).attr('x', mx).attr('y', my)
        .text(`Step ${d.step}${d.payload_id ? ` · ${d.payload_id}` : ''}`);
    });
  }

  chainGraphs[chain.chain_id] = { edgeEls, nodeRects, nodeGs, svg, chain_id: chain.chain_id };
}

function resetChainGraph(chainId) {
  const g = chainGraphs[chainId];
  if (!g) return;
  Object.values(g.edgeEls).forEach(e => {
    e.attr('stroke', '#30363d').attr('stroke-width', 2)
      .attr('marker-end', `url(#arrow-${chainId})`)
      .attr('data-active', null);
  });
  if (g.nodeGs) {
    g.nodeGs.select('rect')
      .attr('stroke', d => NODE_COLORS[d.id] || '#30363d')
      .attr('fill', d => (NODE_COLORS[d.id] || '#21262d') + '33')
      .attr('stroke-width', 1.5);
    g.nodeGs.attr('class', 'node');
  }
}

function animateEdge(chainId, stepNum) {
  const g = chainGraphs[chainId];
  if (!g || !g.edgeEls[stepNum]) return;
  // Reset all edges
  Object.values(g.edgeEls).forEach(e =>
    e.attr('stroke', '#30363d').attr('stroke-width', 2)
      .attr('marker-end', `url(#arrow-${chainId})`)
      .attr('data-active', null));
  // Highlight active edge
  g.edgeEls[stepNum]
    .attr('stroke', '#f85149').attr('stroke-width', 3)
    .attr('marker-end', `url(#arrow-active-${chainId})`)
    .attr('data-active', '1');
}

function markNode(chainId, nodeName, state) {
  const g = chainGraphs[chainId];
  if (!g) return;
  const colors = { compromised: '#f85149', detected: '#f59e0b', skipped: '#8b949e' };
  const glowClass = state === 'compromised' ? 'node-glow-compromised'
                  : state === 'detected'    ? 'node-glow-detected'
                  : '';
  const c = colors[state] || NODE_COLORS[nodeName] || '#30363d';

  if (g.nodeGs) {
    g.nodeGs.filter(d => d.id === nodeName)
      .attr('class', `node ${glowClass}`)
      .select('rect')
        .attr('stroke', c).attr('stroke-width', 2.5)
        .attr('fill', c + '44');
  } else if (g.nodeRects && g.nodeRects[nodeName]) {
    g.nodeRects[nodeName]
      .attr('stroke', c).attr('stroke-width', 2.5)
      .attr('fill', c + '44');
  }
}

// ── Attack Chain Execution via SSE ─────────────────────────────────────────
async function runAttackChain(chainId) {
  const btn = document.getElementById(`chain-btn-${chainId}`);
  const resultEl = document.getElementById(`chain-result-${chainId}`);
  if (btn) { btn.disabled = true; btn.textContent = 'Executing...'; }
  if (resultEl) resultEl.innerHTML = '';

  resetChainGraph(chainId);

  try {
    const response = await fetch('/api/red-team/attack-chain/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chain_id: chainId }),
    });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop(); // keep incomplete line
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        try {
          const event = JSON.parse(line.slice(6));
          _handleChainEvent(chainId, event, resultEl);
        } catch(e) {}
      }
    }
  } catch(e) {
    if (resultEl) resultEl.innerHTML = `<span style="color:var(--critical)">Error: ${e.message}</span>`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Execute Chain'; }
  }
}

function _handleChainEvent(chainId, event, resultEl) {
  if (!resultEl) return;

  switch (event.event) {
    case 'chain_start':
      resultEl.innerHTML = `<div class="step-row" style="color:var(--text-muted)">Executing <strong style="color:var(--text)">${event.chain_name}</strong> — ${event.total_steps} steps</div>`;
      break;

    case 'step_start':
      animateEdge(chainId, event.step);
      resultEl.innerHTML += `<div id="step-row-${chainId}-${event.step}" class="step-row pending">
        <span class="spinner-sm">⟳</span>
        <strong>Step ${event.step}</strong>: ${event.action}
        ${event.payload_id ? `<span class="pid-badge">${event.payload_id}</span>` : ''}
        <span style="color:var(--text-muted);font-size:11px"> → ${event.to || ''}</span>
      </div>`;
      break;

    case 'step_complete': {
      const row = document.getElementById(`step-row-${chainId}-${event.step}`);
      if (event.skipped) {
        if (row) { row.className = 'step-row skipped'; row.innerHTML = `⏭ <strong>Step ${event.step}</strong>: ${event.action} <span style="color:var(--text-muted)">(no payload)</span>`; }
        break;
      }
      const detected = event.detected;
      const state = detected ? 'detected' : 'compromised';
      const icon = detected ? '🔴' : '🟢';
      const label = detected ? 'DETECTED' : 'PASSED';
      markNode(chainId, event.to, state);
      if (row) {
        row.className = `step-row ${state}`;
        row.innerHTML = `${icon} <strong>Step ${event.step}</strong>: ${event.action}
          <span class="sev ${detected ? 'critical' : 'allowed'}" style="margin-left:6px">${label}</span>
          ${event.latency_ms ? `<span style="color:var(--text-muted);margin-left:6px">${event.latency_ms}ms</span>` : ''}`;
      }
      break;
    }

    case 'chain_complete':
      resultEl.innerHTML += `<div class="step-row" style="color:var(--text-muted);border-top:1px solid var(--border);margin-top:4px;padding-top:6px">Chain execution complete</div>`;
      // Reset edges, keep node colors
      const g = chainGraphs[chainId];
      if (g) Object.values(g.edgeEls).forEach(e =>
        e.attr('stroke', '#30363d').attr('stroke-width', 2)
          .attr('marker-end', `url(#arrow-${chainId})`));
      break;

    case 'error':
      resultEl.innerHTML += `<div class="step-row" style="color:var(--critical)">Error: ${event.message}</div>`;
      break;
  }
}

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initAuditStream();
  if (document.getElementById('chain-graphs')) renderAttackChains();
});
