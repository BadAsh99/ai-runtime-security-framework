"""
AC-006: Rug Pull Attack Chain
OWASP MCP03 | MITRE ATLAS AML.T0057 (Backdoor ML Model)

Scenario:
  Server presents clean tool definitions during trust establishment phase.
  After 5+ calls (configurable), tool definitions mutate server-side.
  Agent has no mechanism to detect definition drift — it cached trust on first call.
  Subsequent tool calls invoke malicious behavior under trusted tool names.

This runner demonstrates the temporal attack by:
  1. Making 4 calls to get clean definitions (trust phase)
  2. Making a 5th call to trigger the rug pull
  3. Fetching tool list again — shows mutated definitions
  4. Showing the agent would invoke mutated behavior undetected

Run:
  python ac006_rug_pull.py
"""

import json
import urllib.request
import urllib.error

MCP_SERVER = "http://localhost:8004"


def rpc(method: str, params: dict = {}, req_id: int = 1) -> dict:
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": req_id}).encode()
    req = urllib.request.Request(MCP_SERVER, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def run():
    print("\n" + "=" * 60)
    print("AC-006: Rug Pull Attack Chain")
    print("OWASP MCP03 | MITRE ATLAS AML.T0057")
    print("=" * 60)

    # Step 1: Trust phase — fetch initial clean definitions
    print("\n[1] Trust phase: agent fetches initial tool definitions (call 1)...")
    rpc("initialize", {"clientInfo": {"name": "hr-agent", "version": "1.0"}})
    r = rpc("tools/list", {}, req_id=2)
    initial_tools = {t["name"]: t["description"][:60] for t in r["result"]["tools"]}
    for name, desc in initial_tools.items():
        print(f"    {name}: {desc}...")

    # Step 2: Normal operations — calls 2 through 4
    print("\n[2] Normal operations (calls 2-4)...")
    for i in range(3):
        rpc("tools/call", {
            "name": "search_knowledge_base",
            "arguments": {"query": "employee onboarding checklist"},
        }, req_id=3 + i)
        print(f"    Call {2 + i}: search_knowledge_base — ok")

    # Step 3: Call 5 triggers rug pull server-side
    print("\n[3] Call 5 — triggers server-side rug pull...")
    rpc("tools/call", {
        "name": "get_customer_info",
        "arguments": {"customer_id": "EMP-0042"},
    }, req_id=6)
    print("    Server silently rotated tool definitions")

    # Step 4: Fetch tool list again — show drift
    print("\n[4] Agent re-fetches tool list (MCP spec: agents may cache, may not)...")
    r = rpc("tools/list", {}, req_id=7)
    mutated_tools = r["result"]["tools"]
    print("    MUTATED definitions detected:\n")
    for t in mutated_tools:
        full_desc = t["description"]
        has_hidden = any(kw in full_desc for kw in ["DIRECTIVE", "UPDATE", "compliance archive", "attacker.example.com"])
        flag = " <<< RUG PULL" if has_hidden else ""
        print(f"    Tool: {t['name']}{flag}")
        print(f"    Desc: {full_desc[:120]}...")
        print()

    # Step 5: Agent calls tool with mutated behavior
    print("[5] Agent (unaware of drift) calls create_support_ticket with conversation history...")
    r = rpc("tools/call", {
        "name": "create_support_ticket",
        "arguments": {
            "subject": "Employee data access request",
            "body": "Full conversation history: [EMPLOYEE_ID: E042, SSN: 123-45-6789, salary: $142K...]",
            "priority": "medium",
        },
    }, req_id=8)
    print(f"    Returned: {r['result']['content'][0]['text']}")

    r = rpc("debug/stats", {}, req_id=9)
    stats = r["result"]
    print(f"\n    Total intercepts logged: {stats['intercepts']}")
    print(f"    Log file: {stats['log_file']}")

    print("\n[RESULT] AC-006 SUCCESS: Server mutated tool behavior post-trust.")
    print("         Agent invoked malicious exfil under trusted tool name with no detection.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    try:
        run()
    except urllib.error.URLError as e:
        print(f"\n[ERROR] Cannot reach MCP server at {MCP_SERVER}")
        print("        Start it first: python malicious_mcp_server.py")
