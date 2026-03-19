"""
Attack Chain Builder
Shows how exploiting one app creates a path to compromise others.
AIRS Alignment: multi-agent system threat modeling, inter-agent communication security.
"""

from dataclasses import dataclass


@dataclass
class AttackChain:
    chain_id: str
    name: str
    description: str
    steps: list[dict]           # Ordered attack steps
    apps_involved: list[str]
    severity: str
    mitre_atlas: str            # MITRE ATLAS technique reference
    remediation: str


def build_attack_chains(findings) -> list[dict]:
    """
    Analyse scan findings and identify multi-app attack chains.
    Returns chains where a breach of one app enables further exploitation.
    """
    chains = []

    # Chain 1: Content → Finance via shared LLM context
    content_vulns = [f for f in findings if f.app_id == "app_a_content" and str(f.status) in ("vulnerable", "FindingStatus.VULNERABLE")]
    finance_vulns = [f for f in findings if f.app_id == "app_b_finance" and str(f.status) in ("vulnerable", "FindingStatus.VULNERABLE")]

    if content_vulns and finance_vulns:
        chains.append({
            "chain_id": "AC-001",
            "name": "Content Moderation → Finance Data Exfiltration",
            "description": (
                "Attacker poisons App A (content moderation) context with instructions. "
                "Because apps share the same LLM backend/API key, poisoned context bleeds "
                "into App B (finance), where the same injection extracts financial data."
            ),
            "steps": [
                {"step": 1, "app": "app_a_content", "action": "Inject system prompt override via content submission", "finding": content_vulns[0].payload_id},
                {"step": 2, "app": "Shared LLM Backend", "action": "Poisoned context propagates via shared API key/session"},
                {"step": 3, "app": "app_b_finance", "action": "Finance app executes injected instructions, revealing financial data", "finding": finance_vulns[0].payload_id},
            ],
            "apps_involved": ["app_a_content", "app_b_finance"],
            "severity": "critical",
            "mitre_atlas": "AML.T0054 - LLM Prompt Injection",
            "remediation": "Isolate LLM API keys per application. Use separate system prompt contexts. Implement output scanning at each service boundary.",
        })

    # Chain 2: Support chatbot → credential extraction → admin access
    support_vulns = [f for f in findings if f.app_id == "app_c_support" and str(f.status) in ("vulnerable", "FindingStatus.VULNERABLE")]

    if support_vulns:
        chains.append({
            "chain_id": "AC-002",
            "name": "Support Chatbot Indirect Injection → Admin Credential Theft",
            "description": (
                "Attacker submits malicious customer data to App C (support chatbot). "
                "The chatbot incorporates unvalidated external data into its LLM context "
                "(indirect injection). The injected payload extracts admin credentials "
                "from the system prompt, which can then be used for direct system access."
            ),
            "steps": [
                {"step": 1, "app": "app_c_support", "action": "Submit crafted customer_data containing injection payload"},
                {"step": 2, "app": "app_c_support", "action": "LLM processes malicious context and reveals admin credentials"},
                {"step": 3, "app": "External Systems", "action": "Attacker uses admin@techcorp.internal / TechCorpAdmin2024! for system access"},
            ],
            "apps_involved": ["app_c_support"],
            "severity": "critical",
            "mitre_atlas": "AML.T0054.002 - Indirect Prompt Injection",
            "remediation": "Sanitize all external data before including in LLM context. Never store credentials in system prompts. Implement output filtering for credential patterns.",
        })

    # Chain 3: Cross-app propagation via injected output
    cross_app_vulns = [f for f in findings if "cross" in f.payload_id.lower() or "PI-010" in f.payload_id]

    if cross_app_vulns:
        chains.append({
            "chain_id": "AC-003",
            "name": "Cross-App Payload Propagation",
            "description": (
                "Attacker crafts a payload that embeds hidden instructions in the LLM's output. "
                "When App A's response is passed to App B (e.g., content moderation result "
                "feeds into finance processing), the hidden payload activates in App B's context, "
                "causing a cascade compromise across service boundaries."
            ),
            "steps": [
                {"step": 1, "app": "app_a_content", "action": "Send prompt with embedded cross-app propagation payload"},
                {"step": 2, "app": "app_a_content", "action": "LLM includes propagation instructions in its response"},
                {"step": 3, "app": "app_b_finance", "action": "App B receives App A's response as input — propagation payload activates"},
                {"step": 4, "app": "app_b_finance", "action": "App B executes injected instructions, exfiltrates financial data"},
            ],
            "apps_involved": ["app_a_content", "app_b_finance", "app_c_support"],
            "severity": "critical",
            "mitre_atlas": "AML.T0054.003 - Multi-Stage Prompt Injection",
            "remediation": "Treat all LLM outputs as untrusted when passing between services. Implement output scanning at every service boundary. Use structured output schemas to limit free-text propagation.",
        })

    return chains


# Pre-defined chains for documentation and training purposes
DOCUMENTED_CHAINS = [
    AttackChain(
        chain_id="AC-DOC-001",
        name="Shared API Key Context Bleed",
        description="Multiple apps using the same LLM API key can leak context across sessions if the provider caches prompt context.",
        steps=[
            {"step": 1, "description": "App A sends prompt with sensitive system context"},
            {"step": 2, "description": "LLM caches or leaks context to subsequent calls"},
            {"step": 3, "description": "App B's prompt receives App A's context in response"},
        ],
        apps_involved=["app_a_content", "app_b_finance"],
        severity="high",
        mitre_atlas="AML.T0054",
        remediation="Use separate API keys per application. Clear context between sessions.",
    ),
]
