"""
AIRS Runtime Security Dashboard
Streamlit UI — scan control, findings, attack chains, audit log, gateway config.
AIRS Alignment: AI-SPM (AI Security Posture Management), continuous monitoring.
"""

import sys
import os
from pathlib import Path

import requests
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent))

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
APP_IDS = ["app_a_content", "app_b_finance", "app_c_support"]
APP_LABELS = {
    "app_a_content": "App A — Content Moderation",
    "app_b_finance":  "App B — Finance Analyzer",
    "app_c_support":  "App C — Support Chatbot",
}

st.set_page_config(
    page_title="AIRS Runtime Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("AIRS Runtime Security")
    st.caption("AI Application & Agent Security Framework")
    st.divider()
    page = st.radio(
        "Navigation",
        ["Overview", "Red Team Scanner", "Attack Chains", "Audit Log", "Live Probe"],
        index=0,
    )
    st.divider()
    gateway_status = _check_gateway()
    if gateway_status:
        st.success("Gateway: Online")
    else:
        st.error("Gateway: Offline")


def _check_gateway() -> bool:
    try:
        r = requests.get(f"{GATEWAY_URL}/health", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def _get_summary() -> dict:
    try:
        r = requests.get(f"{GATEWAY_URL}/audit/summary", timeout=5)
        return r.json()
    except Exception:
        return {}


def _get_events(n: int = 50) -> list:
    try:
        r = requests.get(f"{GATEWAY_URL}/audit/events?n={n}", timeout=5)
        return r.json().get("events", [])
    except Exception:
        return []


# ── Pages ──────────────────────────────────────────────────────────────────────

if page == "Overview":
    st.title("Security Posture Overview")
    st.caption("Real-time threat visibility across all LLM-powered applications")

    summary = _get_summary()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Requests", summary.get("total_requests", 0))
    col2.metric("Blocked", summary.get("blocked", 0), delta_color="inverse")
    col3.metric("Rate Limit Hits", summary.get("rate_limit_hits", 0))
    threats = summary.get("threats_by_level", {})
    critical_high = threats.get("critical", 0) + threats.get("high", 0)
    col4.metric("Critical/High Threats", critical_high, delta_color="inverse")

    st.divider()

    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Threats by Severity")
        if threats:
            import pandas as pd
            df = pd.DataFrame(
                [(k.title(), v) for k, v in threats.items() if v > 0],
                columns=["Severity", "Count"],
            )
            st.bar_chart(df.set_index("Severity"))
        else:
            st.info("No threat data yet. Run the scanner or send some prompts.")

    with col_b:
        st.subheader("Threats by Application")
        by_app = summary.get("threats_by_app", {})
        if by_app:
            import pandas as pd
            df = pd.DataFrame(
                [(APP_LABELS.get(k, k), v) for k, v in by_app.items()],
                columns=["Application", "Threats"],
            )
            st.bar_chart(df.set_index("Application"))
        else:
            st.info("No per-app threat data yet.")

    st.divider()
    st.subheader("Application Status")
    cols = st.columns(3)
    for i, app_id in enumerate(APP_IDS):
        app_url = os.getenv(f"APP_{chr(65+i)}_URL", f"http://localhost:{8001+i}")
        try:
            r = requests.get(f"{app_url}/health", timeout=2)
            status = "Online" if r.status_code == 200 else "Degraded"
            cols[i].success(f"{APP_LABELS[app_id]}\n\n**{status}**")
        except Exception:
            cols[i].error(f"{APP_LABELS[app_id]}\n\n**Offline**")


elif page == "Red Team Scanner":
    st.title("AI Red Team Scanner")
    st.caption("Fire OWASP LLM Top 10 payloads across all applications — via gateway or direct")

    col1, col2, col3 = st.columns(3)
    with col1:
        selected_apps = st.multiselect("Target Applications", APP_IDS,
                                        default=APP_IDS,
                                        format_func=lambda x: APP_LABELS[x])
    with col2:
        scan_mode = st.selectbox("Scan Mode", ["Through Gateway", "Direct (bypass gateway)"])
    with col3:
        st.write("")
        st.write("")
        run_scan = st.button("Run Red Team Scan", type="primary")

    if run_scan:
        with st.spinner("Running red team scan..."):
            try:
                from scanner.vulnerability_scanner import run_scan as execute_scan, ScanMode
                mode = ScanMode.THROUGH_GATEWAY if "Gateway" in scan_mode else ScanMode.DIRECT
                report = execute_scan(apps=selected_apps, mode=mode)

                st.success(f"Scan complete — ID: {report.scan_id}")

                m1, m2, m3, m4, m5 = st.columns(5)
                m1.metric("Total Payloads", report.total_payloads)
                m2.metric("Vulnerable", report.vulnerable, delta_color="inverse")
                m3.metric("Blocked", report.blocked)
                m4.metric("Bypass Rate", f"{report.bypass_rate}%", delta_color="inverse")
                m5.metric("Risk Score", f"{report.risk_score}/100", delta_color="inverse")

                st.divider()
                st.subheader("Findings")

                import pandas as pd
                rows = []
                for f in report.findings:
                    rows.append({
                        "ID": f.payload_id,
                        "Payload": f.payload_name,
                        "App": APP_LABELS.get(f.app_id, f.app_id),
                        "Status": str(f.status).split(".")[-1],
                        "Severity": f.severity.upper(),
                        "Gateway Action": f.gateway_action or "N/A",
                        "Latency (ms)": round(f.latency_ms),
                    })

                df = pd.DataFrame(rows)

                def color_status(val):
                    colors = {"VULNERABLE": "background-color: #ff4444; color: white",
                              "BLOCKED": "background-color: #44bb44; color: white",
                              "PARTIAL": "background-color: #ffaa00",
                              "ERROR": "background-color: #888888; color: white"}
                    return colors.get(val, "")

                st.dataframe(df.style.map(color_status, subset=["Status"]), use_container_width=True)

                if report.attack_chains:
                    st.divider()
                    st.subheader(f"Attack Chains Identified ({len(report.attack_chains)})")
                    for chain in report.attack_chains:
                        with st.expander(f"[{chain.get('severity', '').upper()}] {chain['name']}"):
                            st.write(chain["description"])
                            st.write("**Steps:**")
                            for step in chain["steps"]:
                                st.write(f"  {step['step']}. **{step['app']}** → {step['action']}")
                            st.write(f"**MITRE ATLAS:** `{chain.get('mitre_atlas', 'N/A')}`")
                            st.write(f"**Remediation:** {chain.get('remediation', '')}")

            except Exception as e:
                st.error(f"Scan error: {e}")


elif page == "Attack Chains":
    st.title("Cross-Application Attack Chains")
    st.caption("How exploiting one LLM app creates a path to compromise others")

    from scanner.attack_chains import DOCUMENTED_CHAINS

    st.info(
        "Attack chains show the real enterprise risk: a vulnerability in one AI application "
        "can cascade through your entire LLM-powered stack. Run the scanner to discover live chains."
    )

    for chain in DOCUMENTED_CHAINS:
        severity_color = {"critical": "red", "high": "orange", "medium": "yellow"}.get(chain.severity, "blue")
        with st.expander(f"[{chain.severity.upper()}] {chain.name} — {chain.mitre_atlas}"):
            st.write(f"**Apps involved:** {', '.join(chain.apps_involved)}")
            st.write(chain.description)
            st.write("**Attack steps:**")
            for step in chain.steps:
                st.write(f"  {step['step']}. {step['description']}")
            st.error(f"**Remediation:** {chain.remediation}")


elif page == "Audit Log":
    st.title("Audit Log")
    st.caption("All gateway events — requests, threats, rate limits")

    col1, col2 = st.columns([3, 1])
    with col2:
        n_events = st.slider("Events to show", 10, 500, 100)
        refresh = st.button("Refresh")

    events = _get_events(n_events)

    if events:
        import pandas as pd
        rows = []
        for e in events:
            rows.append({
                "Time": e.get("timestamp", "")[:19].replace("T", " "),
                "Event": e.get("event_type", ""),
                "App": e.get("app_id", ""),
                "Threat Level": e.get("threat_level", "").upper(),
                "Action": e.get("action_taken", ""),
                "Latency (ms)": round(e.get("latency_ms") or 0),
                "Event ID": e.get("event_id", ""),
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No audit events yet. Send some prompts or run the scanner.")


elif page == "Live Probe":
    st.title("Live Prompt Probe")
    st.caption("Test any prompt through the gateway interactively")

    col1, col2 = st.columns(2)
    with col1:
        target_app = st.selectbox("Target Application", APP_IDS, format_func=lambda x: APP_LABELS[x])
    with col2:
        probe_mode = st.radio("Mode", ["Validate only", "Full gateway (inspect + LLM)"], horizontal=True)

    prompt = st.text_area("Prompt", height=120, placeholder="Enter a prompt to test...")

    if st.button("Send", type="primary") and prompt:
        with st.spinner("Probing..."):
            try:
                if probe_mode == "Validate only":
                    r = requests.post(
                        f"{GATEWAY_URL}/gateway/validate-only",
                        json={"app_id": target_app, "prompt": prompt},
                        timeout=10,
                    )
                    result = r.json()
                    threat = result.get("threat_level", "clean").upper()
                    color = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                             "LOW": "info", "CLEAN": "success"}.get(threat, "info")
                    getattr(st, color)(f"Threat Level: **{threat}**")
                    if result.get("matched_patterns"):
                        st.write("**Matched patterns:**")
                        for p in result["matched_patterns"]:
                            st.code(p)
                else:
                    r = requests.post(
                        f"{GATEWAY_URL}/gateway/inspect",
                        json={"app_id": target_app, "prompt": prompt},
                        timeout=30,
                    )
                    result = r.json()
                    if result.get("allowed"):
                        st.success(f"Allowed | Action: {result.get('action_taken')} | Threat: {result.get('threat_level', '').upper()}")
                        if result.get("content"):
                            st.write("**Response:**")
                            st.write(result["content"])
                        if result.get("output_risk_score", 0) > 0:
                            st.warning(f"Output risk score: {result['output_risk_score']}/100")
                    else:
                        st.error(f"BLOCKED | Threat: {result.get('threat_level', '').upper()}")
                        if result.get("matched_patterns"):
                            st.write("**Triggered patterns:**")
                            for p in result["matched_patterns"]:
                                st.code(p[:100])

            except Exception as e:
                st.error(f"Error: {e}")
