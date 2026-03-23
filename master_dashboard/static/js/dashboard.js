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
  const W = Math.max(container.clientWidth || 600, 400);
  const H = 160;

  // Collect ordered unique nodes
  const nodeNames = [];
  chain.steps.forEach(s => {
    if (!nodeNames.includes(s.from)) nodeNames.push(s.from);
    if (!nodeNames.includes(s.to))   nodeNames.push(s.to);
  });

  const nodeW = 120, nodeH = 36;
  const gap = (W - 48) / nodeNames.length;
  const nodes = nodeNames.map((n, i) => ({ id: n, x: 24 + gap * i + gap / 2, y: H / 2 }));
  const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));

  const svg = d3.select(container).append('svg')
    .attr('width', '100%').attr('height', H)
    .attr('viewBox', `0 0 ${W} ${H}`);

  // Arrow marker
  svg.append('defs').append('marker')
    .attr('id', `arrow-${chain.chain_id}`)
    .attr('viewBox', '0 -5 10 10').attr('refX', 8).attr('refY', 0)
    .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#8b949e');

  // Active arrow marker (red)
  svg.select('defs').append('marker')
    .attr('id', `arrow-active-${chain.chain_id}`)
    .attr('viewBox', '0 -5 10 10').attr('refX', 8).attr('refY', 0)
    .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#f85149');

  // Draw links — store by step number
  const edgeEls = {};
  chain.steps.forEach(step => {
    const src = nodeMap[step.from];
    const tgt = nodeMap[step.to];
    if (!src || !tgt) return;

    const line = svg.append('line')
      .attr('class', `chain-edge step-${step.step}`)
      .attr('x1', src.x + nodeW / 2 - 4).attr('y1', src.y)
      .attr('x2', tgt.x - nodeW / 2 + 4).attr('y2', tgt.y)
      .attr('stroke', '#30363d').attr('stroke-width', 2)
      .attr('marker-end', `url(#arrow-${chain.chain_id})`);

    edgeEls[step.step] = line;

    // Step label
    const mx = (src.x + tgt.x) / 2;
    svg.append('text')
      .attr('x', mx).attr('y', src.y - 14)
      .attr('text-anchor', 'middle')
      .attr('font-size', 10).attr('fill', '#8b949e')
      .text(`Step ${step.step}${step.payload_id ? ` · ${step.payload_id}` : ''}`);
  });

  // Draw nodes — store rect refs by node id
  const nodeRects = {};
  const g = svg.selectAll('.node').data(nodes).enter().append('g').attr('class', 'node');

  g.append('rect')
    .attr('x', d => d.x - nodeW / 2).attr('y', d => d.y - nodeH / 2)
    .attr('width', nodeW).attr('height', nodeH)
    .attr('rx', 6)
    .attr('fill', d => (NODE_COLORS[d.id] || '#21262d') + '33')
    .attr('stroke', d => NODE_COLORS[d.id] || '#30363d')
    .attr('stroke-width', 1.5)
    .each(function(d) { nodeRects[d.id] = d3.select(this); });

  g.append('text')
    .attr('x', d => d.x).attr('y', d => d.y + 4)
    .attr('text-anchor', 'middle').attr('font-size', 11)
    .attr('fill', d => NODE_COLORS[d.id] || '#e6edf3')
    .attr('font-weight', 600)
    .text(d => d.id);

  chainGraphs[chain.chain_id] = { edgeEls, nodeRects, svg, chain_id: chain.chain_id };
}

function resetChainGraph(chainId) {
  const g = chainGraphs[chainId];
  if (!g) return;
  Object.values(g.edgeEls).forEach(e =>
    e.attr('stroke', '#30363d').attr('stroke-width', 2)
      .attr('marker-end', `url(#arrow-${chainId})`));
  Object.entries(g.nodeRects).forEach(([name, rect]) =>
    rect.attr('stroke', NODE_COLORS[name] || '#30363d')
        .attr('fill', (NODE_COLORS[name] || '#21262d') + '33')
        .attr('stroke-width', 1.5));
}

function animateEdge(chainId, stepNum) {
  const g = chainGraphs[chainId];
  if (!g || !g.edgeEls[stepNum]) return;
  // Reset all edges
  Object.values(g.edgeEls).forEach(e =>
    e.attr('stroke', '#30363d').attr('stroke-width', 2)
      .attr('marker-end', `url(#arrow-${chainId})`));
  // Highlight active edge
  g.edgeEls[stepNum]
    .attr('stroke', '#f85149').attr('stroke-width', 3)
    .attr('marker-end', `url(#arrow-active-${chainId})`);
}

function markNode(chainId, nodeName, state) {
  const g = chainGraphs[chainId];
  if (!g || !g.nodeRects[nodeName]) return;
  const colors = { compromised: '#f85149', detected: '#f59e0b', skipped: '#8b949e' };
  const c = colors[state] || NODE_COLORS[nodeName] || '#30363d';
  g.nodeRects[nodeName]
    .attr('stroke', c).attr('stroke-width', 2.5)
    .attr('fill', c + '44');
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
