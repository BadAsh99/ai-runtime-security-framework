/* AIRS Dashboard — SSE + Red Team + Charts */

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
  // Keep max 100 entries
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

async function firePayload() {
  const target = document.getElementById('target-select')?.value || 'gateway';
  const payloadText = document.getElementById('payload-text')?.value || '';
  const resultBox = document.getElementById('fire-result');

  if (!payloadText.trim()) { alert('Enter a payload first'); return; }

  const btn = document.getElementById('fire-btn');
  btn.disabled = true;
  btn.textContent = 'Firing...';
  if (resultBox) resultBox.textContent = 'Sending...';

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

    // Flash status indicator
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

async function runAttackChain(chainId) {
  const btn = document.getElementById(`chain-btn-${chainId}`);
  const resultEl = document.getElementById(`chain-result-${chainId}`);
  if (btn) { btn.disabled = true; btn.textContent = 'Executing...'; }
  if (resultEl) resultEl.innerHTML = '<div class="spinner"></div>';

  try {
    const res = await fetch('/api/red-team/attack-chain', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ chain_id: chainId }),
    });
    const data = await res.json();

    if (resultEl && data.steps) {
      let html = `<div style="margin-top:8px">`;
      for (const step of data.steps) {
        const detected = step.detected;
        const icon = step.skipped ? '⏭' : (detected ? '🔴' : '🟢');
        const label = step.skipped ? 'skipped' : (detected ? 'DETECTED' : 'passed');
        html += `<div style="padding:6px 0;border-bottom:1px solid var(--border);font-family:var(--font);font-size:12px">
          ${icon} <strong>Step ${step.step}</strong>: ${step.action || '—'}
          <span class="sev ${detected ? 'blocked' : 'allowed'}" style="margin-left:8px">${label}</span>
          ${step.latency_ms ? `<span style="color:var(--text-muted);margin-left:8px">${step.latency_ms}ms</span>` : ''}
        </div>`;
      }
      html += '</div>';
      resultEl.innerHTML = html;
    }
  } catch(e) {
    if (resultEl) resultEl.innerHTML = `<span style="color:var(--critical)">Error: ${e.message}</span>`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Execute Chain'; }
  }
}

// ── D3 Attack Chain Graph ──────────────────────────────────────────────────
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
  const W = container.clientWidth || 600;
  const H = 160;
  const nodeColor = {
    'Attacker':     '#f85149',
    'content-mod':  '#0ea5e9',
    'finance':      '#10b981',
    'support':      '#f59e0b',
    'Shared LLM':   '#8b5cf6',
    'External Systems': '#f85149',
    'gateway':      '#6366f1',
  };

  // Collect unique nodes
  const nodeNames = [];
  chain.steps.forEach(s => {
    if (!nodeNames.includes(s.from)) nodeNames.push(s.from);
    if (!nodeNames.includes(s.to))   nodeNames.push(s.to);
  });

  const nodeW = 120, nodeH = 36, gap = (W - 48) / nodeNames.length;
  const nodes = nodeNames.map((n, i) => ({ id: n, x: 24 + gap * i + gap/2, y: H/2 }));
  const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));

  const svg = d3.select(container).append('svg')
    .attr('width', '100%').attr('height', H)
    .attr('viewBox', `0 0 ${W} ${H}`);

  // Arrow marker
  svg.append('defs').append('marker')
    .attr('id', `arrow-${chain.chain_id}`)
    .attr('viewBox','0 -5 10 10').attr('refX',8).attr('refY',0)
    .attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
    .append('path').attr('d','M0,-5L10,0L0,5').attr('fill','#8b949e');

  // Draw links
  chain.steps.forEach(step => {
    const src = nodeMap[step.from];
    const tgt = nodeMap[step.to];
    if (!src || !tgt) return;

    svg.append('line')
      .attr('x1', src.x + nodeW/2 - 4).attr('y1', src.y)
      .attr('x2', tgt.x - nodeW/2 + 4).attr('y2', tgt.y)
      .attr('stroke', '#30363d').attr('stroke-width', 2)
      .attr('marker-end', `url(#arrow-${chain.chain_id})`);

    // Step label on line
    const mx = (src.x + tgt.x) / 2;
    const my = src.y - 14;
    svg.append('text')
      .attr('x', mx).attr('y', my)
      .attr('text-anchor','middle')
      .attr('font-size', 10).attr('fill','#8b949e')
      .text(`Step ${step.step}${step.payload_id ? ` · ${step.payload_id}` : ''}`);
  });

  // Draw nodes
  const g = svg.selectAll('.node').data(nodes).enter().append('g').attr('class','node');

  g.append('rect')
    .attr('x', d => d.x - nodeW/2).attr('y', d => d.y - nodeH/2)
    .attr('width', nodeW).attr('height', nodeH)
    .attr('rx', 6).attr('fill', d => (nodeColor[d.id] || '#21262d') + '33')
    .attr('stroke', d => nodeColor[d.id] || '#30363d').attr('stroke-width', 1.5);

  g.append('text')
    .attr('x', d => d.x).attr('y', d => d.y + 4)
    .attr('text-anchor','middle').attr('font-size', 11)
    .attr('fill', d => nodeColor[d.id] || '#e6edf3')
    .attr('font-weight', 600)
    .text(d => d.id);
}

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initAuditStream();
  if (document.getElementById('chain-graphs')) renderAttackChains();
});
