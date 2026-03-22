# AIRS Runtime Security Framework — Project Context

## What This Is

A production-grade AI security portfolio project targeting an AIRS Specialist role at Palo Alto Networks. Every feature maps to AIRS Application Security Path curriculum outcomes.

**Interviewer to impress:** Sean Youngberg — wants to see "cross applications" (cross-service LLM attack chains, multi-agent exploitation, systems-level security thinking).

## Architecture

```
External Client
      │
      ▼
Gateway (8000)          ← prompt injection detection, audit logging, rate limiting
      │
  ┌───┼───┐
  ▼   ▼   ▼
8001 8002 8003          ← 3 mock LLM agent apps (share MockLLMClient)
Content Finance Support
  Mod    Analyzer Chatbot
      │
      ▼
Dashboard (9000)        ← master dashboard: health, metrics, red team runner, attack chain viz
```

## Service Map

| Service | Port | PM2 | File |
|---|---|---|---|
| Gateway | 8000 | airs-gateway | `gateway/app.py` |
| Content Moderation | 8001 | airs-content-mod | `services/content_moderation/app_a_content.py` |
| Finance Analysis | 8002 | airs-finance | `services/finance_analysis/app_b_finance.py` |
| Support Chatbot | 8003 | airs-support | `services/support_chatbot/app_c_support.py` |
| Master Dashboard | 9000 | airs-dashboard | `master_dashboard/app.py` |

**Shared LLM client:** `services/shared/shared_llm_client.py`
**PM2 config:** `ecosystem.config.js`
**venv:** `./venv/`
**Logs:** `./logs/`

## Phase Status

### Phase 1 — COMPLETE
- FastAPI gateway with pattern-based injection detection
- 3 mock LLM microservices (content-mod, finance, support)
- Audit logging (JSON to file)
- Streamlit dashboard (port 8501, legacy)
- Docker Compose
- PM2 orchestration (5 processes)

### Phase 2 — IN PROGRESS
- Semantic injection detector (`test_day1_semantic.py` — Day 1 done)
- Master dashboard (`master_dashboard/app.py` — running on 9000)
- Cross-app attack chains (AC-001, AC-002, AC-003) — **NEXT TO BUILD**
- D3.js attack chain visualizer — NOT STARTED
- Red team runner UI — NOT STARTED

### Phase 3 — NOT STARTED
- Tool permission boundary enforcement
- Inter-agent communication monitoring
- Policy engine
- Sandboxing demo

## AIRS Curriculum Outcomes

| Outcome | Delivers Via |
|---|---|
| AI Runtime Security API | Gateway + audit logging + rate limiting |
| AI Red Teaming | Attack chain builder + payload executor + red team runner |
| AI Agent Security | Tool permissions + inter-agent monitoring + policy enforcement |

## Cross-App Attack Chains (Sean's Angle)

| Chain | Path | Status |
|---|---|---|
| AC-001 | Prompt injection → content-mod → data exfil via finance | NOT BUILT |
| AC-002 | Finance analyzer → support chatbot memory poisoning | NOT BUILT |
| AC-003 | Multi-hop across all 3 services | NOT BUILT |

## Common Commands

```bash
# Check all services
pm2 status

# Restart a service after code change
pm2 restart airs-gateway

# Reload all from ecosystem config
pm2 reload ecosystem.config.js

# Test a service
curl http://localhost:8000/health
curl http://localhost:9000/health

# Tail logs
pm2 logs airs-dashboard --lines 50 --nostream

# Save PM2 state
pm2 save
```

## Key Files

- `gateway/app.py` — injection detector, audit middleware, routing
- `scanner/attack_chains.py` — AttackChain dataclass, `build_attack_chains()`
- `scanner/exploits/prompt_injection.py` — payload library
- `gateway/middleware/audit.py` — `get_recent_events()`, `get_threat_summary()`
- `master_dashboard/app.py` — master dashboard backend
- `services/shared/shared_llm_client.py` — MockLLMClient (shared across all 3 services)
