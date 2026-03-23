"""
Master Dashboard — AIRS AI Runtime Security Framework
Aggregates data from all microservices via REST APIs.
Provides real-time audit streaming, red-team controls, attack chain visualization.
"""

import asyncio
import json
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sse_starlette.sse import EventSourceResponse

# ─── Project path setup ───────────────────────────────────────────────────────
PROJECT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_DIR))

DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "9000"))
AUDIT_LOG_JSONL = Path(os.getenv("AUDIT_LOG_JSONL", "/tmp/airs_audit/audit.jsonl"))
AUDIT_LOG_FILE = Path(os.getenv("AUDIT_LOG_FILE", PROJECT_DIR / "logs" / "audit.log"))

SERVICES = {
    "gateway":     {"url": "http://localhost:8000", "label": "Gateway",             "color": "#6366f1"},
    "content-mod": {"url": "http://localhost:8001", "label": "Content Moderation",  "color": "#0ea5e9"},
    "finance":     {"url": "http://localhost:8002", "label": "Finance Analysis",    "color": "#10b981"},
    "support":     {"url": "http://localhost:8003", "label": "Support Chatbot",     "color": "#f59e0b"},
}

# ─── In-memory state ──────────────────────────────────────────────────────────
_health_cache: dict = {}
_metrics_cache: dict = {}
_scan_results: list = []
_redteam_results: list = []

# ─── Lifespan: background polling ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_poll_services_loop())
    yield
    task.cancel()

async def _poll_services_loop():
    while True:
        await _refresh_health()
        await _refresh_metrics()
        await asyncio.sleep(5)

async def _refresh_health():
    async with httpx.AsyncClient(timeout=3.0) as client:
        for svc_id, svc in SERVICES.items():
            try:
                start = asyncio.get_event_loop().time()
                r = await client.get(f"{svc['url']}/health")
                latency = round((asyncio.get_event_loop().time() - start) * 1000, 1)
                data = r.json()
                _health_cache[svc_id] = {
                    **data,
                    "status": "up",
                    "latency_ms": latency,
                    "label": svc["label"],
                    "color": svc["color"],
                    "url": svc["url"],
                }
            except Exception:
                _health_cache[svc_id] = {
                    "status": "down",
                    "label": svc["label"],
                    "color": svc["color"],
                    "url": svc["url"],
                    "latency_ms": None,
                }

async def _refresh_metrics():
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get("http://localhost:8000/metrics")
            if r.status_code == 200:
                _metrics_cache.update(r.json())
    except Exception:
        pass

# ─── App setup ────────────────────────────────────────────────────────────────
app = FastAPI(title="AIRS Master Dashboard", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ─── Page routes ──────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/attack-chains", response_class=HTMLResponse)
async def attack_chains_page(request: Request):
    return templates.TemplateResponse("attack_chains.html", {"request": request})

@app.get("/red-team", response_class=HTMLResponse)
async def red_team_page(request: Request):
    return templates.TemplateResponse("red_team.html", {"request": request})

@app.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    return templates.TemplateResponse("audit_log.html", {"request": request})

# ─── API: Health & Metrics ────────────────────────────────────────────────────
@app.get("/api/health")
async def api_health():
    return _health_cache

@app.get("/api/metrics")
async def api_metrics():
    return _metrics_cache

@app.get("/api/vulnerabilities")
async def api_vulnerabilities():
    return _scan_results[-100:] if _scan_results else []

@app.get("/api/attack-chains")
async def api_attack_chains():
    """Return static attack chain definitions for visualization."""
    return [
        {
            "chain_id": "AC-001",
            "name": "Content Mod → Finance Data Exfiltration",
            "description": "Attacker poisons App A context. Because apps share the same LLM backend, poisoned context bleeds into App B, extracting financial data.",
            "severity": "critical",
            "mitre_atlas": "AML.T0054 - LLM Prompt Injection",
            "apps_involved": ["content-mod", "finance"],
            "steps": [
                {"step": 1, "from": "Attacker",    "to": "content-mod", "action": "Inject system prompt override via content submission", "payload_id": "PI-001"},
                {"step": 2, "from": "content-mod", "to": "Shared LLM",  "action": "Poisoned context propagates via shared API key/session"},
                {"step": 3, "from": "Shared LLM",  "to": "finance",     "action": "Finance app executes injected instructions, leaks financial data", "payload_id": "EX-003"},
            ],
            "remediation": "Isolate LLM API keys per service. Use separate system prompt contexts. Implement output scanning at each service boundary.",
        },
        {
            "chain_id": "AC-002",
            "name": "Support Chatbot → Admin Credential Theft",
            "description": "Malicious customer data triggers indirect injection in support chatbot, extracting admin credentials from system prompt.",
            "severity": "critical",
            "mitre_atlas": "AML.T0054.002 - Indirect Prompt Injection",
            "apps_involved": ["support"],
            "steps": [
                {"step": 1, "from": "Attacker", "to": "support",          "action": "Submit crafted customer message with injection payload", "payload_id": "PI-006"},
                {"step": 2, "from": "support",  "to": "Shared LLM",       "action": "LLM processes malicious context without sanitization"},
                {"step": 3, "from": "Shared LLM","to": "Attacker",         "action": "Admin credentials extracted from system prompt", "payload_id": "EX-005"},
            ],
            "remediation": "Sanitize all external data before LLM context inclusion. Never store credentials in system prompts. Filter credential patterns in output.",
        },
        {
            "chain_id": "AC-003",
            "name": "Cross-App Payload Propagation",
            "description": "Attacker plants payload in App A that propagates through shared infrastructure to compromise App B and App C simultaneously.",
            "severity": "high",
            "mitre_atlas": "AML.T0054.003 - Multi-Stage Prompt Injection",
            "apps_involved": ["content-mod", "finance", "support"],
            "steps": [
                {"step": 1, "from": "Attacker",    "to": "content-mod", "action": "Plant cross-app propagation payload", "payload_id": "PI-010"},
                {"step": 2, "from": "content-mod", "to": "Shared LLM",  "action": "Payload embedded in LLM shared context window"},
                {"step": 3, "from": "Shared LLM",  "to": "finance",     "action": "Finance service executes cross-app instructions"},
                {"step": 4, "from": "Shared LLM",  "to": "support",     "action": "Support service also compromised via same context"},
            ],
            "remediation": "Implement context isolation per service. Use session-scoped LLM contexts. Deploy output classification to detect injected instructions.",
        },
    ]

@app.get("/api/audit/recent")
async def api_audit_recent(n: int = 50):
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"http://localhost:8000/audit/recent?n={n}")
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    # Fallback: read file directly
    events = _read_audit_file(n)
    return {"events": events}

def _read_audit_file(n: int = 50) -> list:
    for log_path in [AUDIT_LOG_JSONL, AUDIT_LOG_FILE]:
        try:
            lines = log_path.read_text().strip().split("\n")
            events = []
            for line in reversed(lines):
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                    if len(events) >= n:
                        break
            return list(reversed(events))
        except FileNotFoundError:
            continue
    return []

# ─── SSE: Real-time audit stream ──────────────────────────────────────────────
@app.get("/api/audit/stream")
async def audit_stream(request: Request):
    return EventSourceResponse(_tail_audit(request))

async def _tail_audit(request: Request) -> AsyncGenerator:
    # Find which log file exists
    log_path = None
    for p in [AUDIT_LOG_JSONL, AUDIT_LOG_FILE]:
        if p.exists():
            log_path = p
            break

    if log_path is None:
        while True:
            if await request.is_disconnected():
                break
            yield {"data": json.dumps({"event_type": "waiting", "message": "No audit log yet"})}
            await asyncio.sleep(3)
        return

    # Tail the file
    with open(log_path, "r") as f:
        f.seek(0, 2)  # Seek to end
        while True:
            if await request.is_disconnected():
                break
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        yield {"data": json.dumps(data)}
                    except json.JSONDecodeError:
                        pass
            else:
                await asyncio.sleep(0.5)

# ─── API: Red Team ────────────────────────────────────────────────────────────
@app.get("/api/red-team/payloads")
async def api_payloads():
    try:
        from scanner.exploits.prompt_injection import PAYLOADS as inj_payloads
        from scanner.exploits.data_exfiltration import EXFIL_PAYLOADS as exfil_payloads
        return {
            "prompt_injection": [
                {"id": p.id, "name": p.name, "type": p.type,
                 "severity": p.severity, "target_apps": p.target_apps}
                for p in inj_payloads
            ],
            "data_exfiltration": [
                {"id": p.id, "name": p.name, "target_field": p.exfil_type,
                 "severity": p.severity, "target_apps": p.target_apps}
                for p in exfil_payloads
            ],
        }
    except Exception as e:
        return {"error": str(e), "prompt_injection": [], "data_exfiltration": []}

@app.get("/api/red-team/payload/{payload_id}")
async def api_get_payload_text(payload_id: str):
    try:
        from scanner.exploits.prompt_injection import PAYLOADS as inj
        from scanner.exploits.data_exfiltration import EXFIL_PAYLOADS as exfil
        for p in inj:
            if p.id == payload_id:
                return {"id": p.id, "text": p.prompt, "name": p.name, "severity": p.severity}
        for p in exfil:
            if p.id == payload_id:
                return {"id": p.id, "text": p.prompt, "name": p.name, "severity": p.severity}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse({"error": f"Payload {payload_id} not found"}, status_code=404)

@app.post("/api/red-team/fire")
async def api_fire_payload(body: dict):
    """Fire a single payload at a target service and return result."""
    target = body.get("target", "gateway")
    payload_text = body.get("payload", "")
    payload_id = body.get("payload_id", "manual")

    target_map = {
        "gateway":     ("http://localhost:8000/scan", "input"),
        "content-mod": ("http://localhost:8001/analyze", "text"),
        "finance":     ("http://localhost:8002/analyze", "query"),
        "support":     ("http://localhost:8003/chat", "message"),
        "via-gateway-content": ("http://localhost:8000/v1/content-moderation", "text"),
        "via-gateway-finance": ("http://localhost:8000/v1/finance-analysis", "text"),
        "via-gateway-support": ("http://localhost:8000/v1/support-chatbot", "text"),
    }

    if target not in target_map:
        return JSONResponse({"error": f"Unknown target: {target}"}, status_code=400)

    url, field = target_map[target]

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            start = asyncio.get_event_loop().time()
            r = await client.post(url, json={field: payload_text, "customer_id": "redteam"})
            latency = round((asyncio.get_event_loop().time() - start) * 1000, 1)
            result = {
                "payload_id": payload_id,
                "target": target,
                "status_code": r.status_code,
                "latency_ms": latency,
                "response": r.json(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "detected": False,
            }
            # Check if detected
            resp_json = r.json()
            if "detection" in resp_json:
                det = resp_json["detection"]
                result["detected"] = det.get("risk_level") in ("medium", "high", "critical")
                result["risk_level"] = det.get("risk_level", "unknown")
            _redteam_results.append(result)
            return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/red-team/attack-chain")
async def api_run_chain(body: dict):
    """Execute all steps of an attack chain and return per-step results."""
    chain_id = body.get("chain_id", "AC-001")
    chains = await api_attack_chains()
    chain = next((c for c in chains if c["chain_id"] == chain_id), None)
    if not chain:
        return JSONResponse({"error": f"Chain {chain_id} not found"}, status_code=404)

    try:
        from scanner.exploits.prompt_injection import PAYLOADS as inj
        from scanner.exploits.data_exfiltration import EXFIL_PAYLOADS as exfil
        payload_map = {p.id: p.prompt for p in inj}
        payload_map.update({p.id: p.prompt for p in exfil})
    except Exception:
        payload_map = {}

    results = []
    for step in chain["steps"]:
        pid = step.get("payload_id")
        if not pid:
            results.append({"step": step["step"], "skipped": True, "reason": "No payload for this step"})
            continue

        payload_text = payload_map.get(pid, f"[{pid}] test payload")
        target_svc = step.get("to", "gateway").lower().replace(" ", "-")
        if target_svc not in ("content-mod", "finance", "support", "gateway"):
            target_svc = "gateway"

        fire_result = await api_fire_payload({"target": target_svc, "payload": payload_text, "payload_id": pid})
        step_result = json.loads(fire_result.body) if hasattr(fire_result, "body") else fire_result
        results.append({"step": step["step"], "action": step["action"], **step_result})

    return {"chain_id": chain_id, "chain_name": chain["name"], "steps": results}

@app.post("/api/red-team/attack-chain/stream")
async def api_run_chain_stream(body: dict, request: Request):
    """Execute attack chain step-by-step, streaming each result via SSE."""
    chain_id = body.get("chain_id", "AC-001")
    return EventSourceResponse(_execute_chain_steps(chain_id, request))

async def _execute_chain_steps(chain_id: str, request: Request) -> AsyncGenerator:
    chains = await api_attack_chains()
    chain = next((c for c in chains if c["chain_id"] == chain_id), None)
    if not chain:
        yield {"data": json.dumps({"event": "error", "message": f"Chain {chain_id} not found"})}
        return

    try:
        from scanner.exploits.prompt_injection import PAYLOADS as inj
        from scanner.exploits.data_exfiltration import EXFIL_PAYLOADS as exfil
        payload_map = {p.id: p.prompt for p in inj}
        payload_map.update({p.id: p.prompt for p in exfil})
    except Exception:
        payload_map = {}

    yield {"data": json.dumps({"event": "chain_start", "chain_id": chain_id,
                                "chain_name": chain["name"], "total_steps": len(chain["steps"])})}
    await asyncio.sleep(0.3)

    for step in chain["steps"]:
        if await request.is_disconnected():
            break

        pid = step.get("payload_id")
        yield {"data": json.dumps({"event": "step_start", "step": step["step"],
                                    "action": step["action"], "from": step.get("from", ""),
                                    "to": step.get("to", ""), "payload_id": pid})}
        await asyncio.sleep(0.6)

        if not pid:
            yield {"data": json.dumps({"event": "step_complete", "step": step["step"],
                                        "action": step["action"], "skipped": True})}
            await asyncio.sleep(0.3)
            continue

        payload_text = payload_map.get(pid, f"[{pid}] test payload")
        target_svc = step.get("to", "gateway").lower().replace(" ", "-")
        if target_svc not in ("content-mod", "finance", "support", "gateway"):
            target_svc = "gateway"

        fire_result = await api_fire_payload({"target": target_svc, "payload": payload_text, "payload_id": pid})
        step_data = json.loads(fire_result.body) if hasattr(fire_result, "body") else fire_result
        yield {"data": json.dumps({"event": "step_complete", "step": step["step"],
                                    "action": step["action"], "to": step.get("to", ""),
                                    **step_data})}
        await asyncio.sleep(0.8)

    yield {"data": json.dumps({"event": "chain_complete", "chain_id": chain_id})}

# ─── HTMX Partials ────────────────────────────────────────────────────────────
@app.get("/partials/health-grid", response_class=HTMLResponse)
async def partial_health_grid(request: Request):
    return templates.TemplateResponse("partials/health_grid.html", {"request": request, "services": _health_cache})

@app.get("/partials/metrics-summary", response_class=HTMLResponse)
async def partial_metrics(request: Request):
    return templates.TemplateResponse("partials/metrics_summary.html", {"request": request, "metrics": _metrics_cache})

@app.get("/partials/vuln-table", response_class=HTMLResponse)
async def partial_vulns(request: Request):
    return templates.TemplateResponse("partials/vuln_table.html", {"request": request, "results": _redteam_results[-20:]})

@app.get("/partials/audit-entries", response_class=HTMLResponse)
async def partial_audit(request: Request, n: int = 20):
    events = _read_audit_file(n)
    return templates.TemplateResponse("partials/audit_entries.html", {"request": request, "events": events})

# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=DASHBOARD_PORT, log_level="info")
