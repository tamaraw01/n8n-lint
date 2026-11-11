from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class RuleSpec:
    id: str
    severity: str
    category: str
    title: str
    description: str


ALL_RULES: tuple[RuleSpec, ...] = (
    RuleSpec("SCHEMA001", "error", "schema", "Invalid workflow JSON root", "Top-level JSON must be an object with a nodes list and connections map."),
    RuleSpec("SCHEMA002", "error", "schema", "Broken node object schema", "Each node requires name, type, typeVersion, numeric [x, y] position, and object parameters."),
    RuleSpec("SCHEMA003", "error", "schema", "Duplicate node name or ID", "Duplicate node names or IDs corrupt n8n connection routing."),
    RuleSpec("SCHEMA004", "warn", "schema", "Broken or legacy node typeVersion", "Non-positive or legacy node typeVersions break across n8n v1.x/v2.x imports."),
    RuleSpec("SCHEMA005", "warn", "schema", "Unpinned community node or risky code primitive", "Community nodes or Code/ExecuteCommand nodes using eval/child_process/process.env require review."),
    RuleSpec("GRAPH001", "error", "graph", "Broken connection target or source", "Connections must reference existing node names in the workflow."),
    RuleSpec("GRAPH002", "warn", "graph", "Orphaned non-trigger node", "Non-trigger node has no incoming connections and will never execute."),
    RuleSpec("GRAPH003", "error", "graph", "Malformed n8n expression syntax", "Template expressions with {{ }} must start with '=' and have balanced braces."),
    RuleSpec("GRAPH004", "warn", "graph", "Disconnected or missing trigger", "Workflow has no trigger node or a trigger has zero outgoing connections."),
    RuleSpec("SEC001", "error", "security", "Hardcoded secret or API key", "API keys, private keys, or password literals must use n8n credentials or $env."),
    RuleSpec("SEC002", "warn", "security", "Exported pinData payload", "Pinned execution snapshots inside workflow JSON leak test or customer data."),
    RuleSpec("SEC003", "error", "security", "Inline auth header or embedded credential secret", "Raw Authorization/API-key headers or secret fields should use credential stores."),
    RuleSpec("SEC004", "error", "security", "Unauthenticated Webhook or MCP trigger", "Public Webhook or MCP Server Trigger has authentication unset or set to none."),
    RuleSpec("SEC005", "warn", "security", "Hardcoded email or PII literal", "Literal non-example email addresses in parameters risk leaking customer or operator PII."),
    RuleSpec("URL001", "warn", "urls", "Hardcoded HTTP/HTTPS URL", "Static endpoint URLs break between staging and prod; prefer $env or $vars."),
    RuleSpec("URL002", "error", "urls", "Cleartext http:// endpoint", "Non-local http:// URLs expose payloads and credentials in transit."),
    RuleSpec("URL003", "error", "urls", "Localhost, tunnel, or private-IP URL", "Localhost, ngrok, or RFC1918/metadata URLs fail in prod or risk SSRF."),
    RuleSpec("URL004", "warn", "urls", "Hardcoded chat or webhook callback URL", "Hardcoded Slack, Discord, or webhook.site URLs should move to $env or credentials."),
    RuleSpec("REL001", "error", "reliability", "Silent green-run continueOnFail trap", "continueOnFail or continueRegularOutput without an error branch hides failures."),
    RuleSpec("REL002", "warn", "reliability", "Missing workflow errorWorkflow", "Configure settings.errorWorkflow so uncaught crashes trigger alerts."),
    RuleSpec("REL003", "warn", "reliability", "HTTP Request missing timeout or retry guard", "Set bounded options.timeout (<= 120000 ms) and retryOnFail on external HTTP calls."),
    RuleSpec("REL004", "error", "reliability", "Active scheduleTrigger in exported JSON", "Exporting active: true with a scheduleTrigger fires cron jobs on staging import."),
    RuleSpec("REL005", "warn", "reliability", "Subworkflow call lacks error branch", "executeWorkflow or toolWorkflow should set onError: continueErrorOutput or errorWorkflow."),
    RuleSpec("IDEMP001", "warn", "idempotency", "Webhook mutation without idempotency guard", "Webhook triggers feeding mutating nodes need a dedupe/idempotency check for retries."),
    RuleSpec("MCP001", "warn", "mcp", "MCP trigger wired to slow synchronous branch", "Long-running MCP branches risk 125s HTTP 502 timeouts and double execution."),
    RuleSpec("MCP002", "warn", "mcp", "AI Agent or tool lacks output schema or error guard", "Attach an output parser or error branch to avoid empty tool observations."),
)

RULE_INDEX: dict[str, RuleSpec] = {r.id: r for r in ALL_RULES}

SECRET_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{12,}\b")),
    ("OpenAI key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b")),
    ("PEM private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
)

SECRET_KEY_RE = re.compile(r"(api[_-]?key|secret|password|passwd|private[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|bot[_-]?token)", re.IGNORECASE)
AUTH_HEADER_KEY_RE = re.compile(r"^(authorization|x-api-key|x-auth-token|api-key)$", re.IGNORECASE)
INLINE_BEARER_RE = re.compile(r"^\s*(?:Bearer|Basic|Token)\s+[A-Za-z0-9._+/=-]{8,}\s*$", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
URL_RE = re.compile(r"https?://[^\s\"'<>`\\]+", re.IGNORECASE)
RISKY_CODE_RE = re.compile(r"\b(?:eval|Function)\s*\(|child_process|process\.env\b")
CHAT_WEBHOOK_RE = re.compile(r"(hooks\.slack\.com/services/|discord(?:app)?\.com/api/webhooks/|webhook\.site/)", re.IGNORECASE)

SAFE_EMAIL_DOMAINS = {"example.com", "example.org", "example.net", "localhost", "test.local"}
SAFE_SCHEMA_HOSTS = {"json-schema.org", "www.w3.org", "schema.org"}

LEGACY_MIN_VERSIONS: dict[str, float] = {
    "n8n-nodes-base.httpRequest": 4.0,
    "n8n-nodes-base.webhook": 2.0,
}

MUTATING_NODE_HINTS = (
    "slack",
    "gmail",
    "email",
    "postgres",
    "mysql",
    "supabase",
    "airtable",
    "hubspot",
    "notion",
    "stripe",
    "sheets",
    "salesforce",
    "jira",
)
DEDUPE_NODE_TYPES = {
    "n8n-nodes-base.if",
    "n8n-nodes-base.switch",
    "n8n-nodes-base.filter",
    "n8n-nodes-base.redis",
    "n8n-nodes-base.dataTable",
}
DEDUPE_NAME_RE = re.compile(r"(dedup|idempoten|seen|cache)", re.IGNORECASE)


def mask_secret(raw: str) -> str:
    cleaned = raw.strip()
    if len(cleaned) <= 8:
        return "***"
    return f"{cleaned[:4]}***{cleaned[-2:]}"


def _is_expression(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("=") and ("{{" in stripped or "$" in stripped)


def _is_placeholder(value: str) -> bool:
    upper = value.strip().upper()
    return not upper or upper in {"REDACTED", "__REDACTED__", "CHANGEME", "YOUR_API_KEY", "REPLACE_ME"} or "***" in upper


def _walk_strings(obj: Any, path: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub = f"{path}.{k}" if path else str(k)
            found.extend(_walk_strings(v, sub))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            sub = f"{path}[{idx}]"
            found.extend(_walk_strings(item, sub))
    elif isinstance(obj, str):
        found.append((path, obj))
    return found


def _extract_header_pairs(parameters: dict[str, Any]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    hp = parameters.get("headerParameters")
    if isinstance(hp, dict):
        items = hp.get("parameters")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    name = str(item.get("name", ""))
                    val = item.get("value")
                    if isinstance(val, str):
                        pairs.append((name, val))
    return pairs


def _is_trigger_node(node_type: str) -> bool:
    lower = node_type.lower()
    return "trigger" in lower or lower.endswith(".webhook") or lower.endswith(".cron") or lower.endswith(".form")


def _extract_edges(connections: dict[str, Any]) -> list[tuple[str, str, str, int]]:
    edges: list[tuple[str, str, str, int]] = []
    for src_name, port_map in connections.items():
        if not isinstance(port_map, dict):
            continue
        for conn_type, branches in port_map.items():
            if not isinstance(branches, list):
                continue
            for branch_idx, branch in enumerate(branches):
                if not isinstance(branch, list):
                    continue
                for target in branch:
                    if isinstance(target, dict) and isinstance(target.get("node"), str):
                        edges.append((src_name, target["node"], str(conn_type), branch_idx))
    return edges


def _is_local_or_private_host(host: str) -> bool:
    lower = host.lower().strip("[]")
    if lower in {"localhost", "0.0.0.0", "host.docker.internal"} or lower.endswith(".local") or "ngrok" in lower:
        return True
    try:
        ip = ipaddress.ip_address(lower)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified
    except ValueError:
        return False


def _add_finding(
    findings: list[dict[str, Any]],
    rule_id: str,
    source: str,
    node_name: str,
    detail: str,
    remediation: str,
    ignore_rules: set[str],
) -> None:
    if rule_id in ignore_rules:
        return
    spec = RULE_INDEX[rule_id]
    findings.append(
        {
            "rule_id": spec.id,
            "severity": spec.severity,
            "category": spec.category,
            "title": spec.title,
            "detail": detail,
            "remediation": remediation,
            "file": source,
            "node": node_name,
        }
    )


def lint_workflow_data(
    data: Any,
    source: str = "<memory>",
    ignore_rules: set[str] | None = None,
) -> list[dict[str, Any]]:
    ignored = {r.upper() for r in (ignore_rules or set())}
    findings: list[dict[str, Any]] = []

    if not isinstance(data, dict) or not isinstance(data.get("nodes"), list) or not isinstance(data.get("connections"), dict):
        _add_finding(
            findings,
            "SCHEMA001",
            source,
            "<workflow>",
            "Workflow JSON must be an object containing a 'nodes' list and 'connections' object.",
            "Export a valid n8n workflow JSON object with 'nodes' and 'connections' keys.",
            ignored,
        )
        return findings

    nodes: list[Any] = data["nodes"]
    connections: dict[str, Any] = data["connections"]
    settings = data.get("settings") if isinstance(data.get("settings"), dict) else {}

    if data.get("pinData"):
        _add_finding(
            findings,
            "SEC002",
            source,
            "<workflow>",
            f"Workflow contains non-empty 'pinData' across {len(data['pinData'])} node(s).",
            "Clear pinned data or run 'n8n-lint redact' before committing workflow JSON.",
            ignored,
        )

    if not settings.get("errorWorkflow"):
        _add_finding(
            findings,
            "REL002",
            source,
            "<workflow>",
            "settings.errorWorkflow is unset; uncaught trigger or node crashes will not alert.",
            "Set settings.errorWorkflow to a dedicated Error Trigger handler workflow ID.",
            ignored,
        )

    seen_names: set[str] = set()
    seen_ids: set[str] = set()
    valid_nodes: dict[str, dict[str, Any]] = {}

    for idx, raw_node in enumerate(nodes):
        if not isinstance(raw_node, dict):
            _add_finding(
                findings,
                "SCHEMA002",
                source,
                f"nodes[{idx}]",
                "Node entry is not a JSON object.",
                "Ensure every entry in 'nodes' is a valid n8n node object.",
                ignored,
            )
            continue

        node_name = str(raw_node.get("name") or f"nodes[{idx}]")
        node_type = raw_node.get("type")
        type_ver = raw_node.get("typeVersion")
        pos = raw_node.get("position")
        params = raw_node.get("parameters")

        missing_fields = [k for k in ("name", "type", "typeVersion", "position") if k not in raw_node]
        bad_pos = not (isinstance(pos, list) and len(pos) == 2 and all(isinstance(n, (int, float)) and not isinstance(n, bool) for n in pos))
        bad_params = params is not None and not isinstance(params, dict)
        if missing_fields or bad_pos or bad_params or not isinstance(node_type, str):
            _add_finding(
                findings,
                "SCHEMA002",
                source,
                node_name,
                f"Invalid node schema (missing={missing_fields}, bad_position={bad_pos}, bad_parameters={bad_params}).",
                "Provide name, string type, numeric typeVersion, [x, y] position, and object parameters.",
                ignored,
            )

        if isinstance(raw_node.get("name"), str):
            if raw_node["name"] in seen_names:
                _add_finding(
                    findings,
                    "SCHEMA003",
                    source,
                    node_name,
                    f"Duplicate node name '{node_name}' breaks connection routing.",
                    "Rename duplicate nodes so every node name in the workflow is unique.",
                    ignored,
                )
            seen_names.add(raw_node["name"])
            valid_nodes[raw_node["name"]] = raw_node

        node_id = raw_node.get("id")
        if isinstance(node_id, str) and node_id:
            if node_id in seen_ids:
                _add_finding(
                    findings,
                    "SCHEMA003",
                    source,
                    node_name,
                    f"Duplicate node id '{node_id}' detected.",
                    "Regenerate unique UUIDs/IDs per node.",
                    ignored,
                )
            seen_ids.add(node_id)

        if not isinstance(type_ver, (int, float)) or isinstance(type_ver, bool) or type_ver <= 0:
            _add_finding(
                findings,
                "SCHEMA004",
                source,
                node_name,
                f"Invalid typeVersion '{type_ver}' on node type '{node_type}'.",
                "Use a positive numeric typeVersion matching your target n8n release.",
                ignored,
            )
        elif isinstance(node_type, str) and node_type in LEGACY_MIN_VERSIONS:
            min_v = LEGACY_MIN_VERSIONS[node_type]
            if float(type_ver) < min_v:
                _add_finding(
                    findings,
                    "SCHEMA004",
                    source,
                    node_name,
                    f"Legacy typeVersion {type_ver} on {node_type} (recommended >= {min_v:g}).",
                    f"Upgrade {node_type} to typeVersion >= {min_v:g} for current error and auth options.",
                    ignored,
                )

        if isinstance(node_type, str):
            is_community = not node_type.startswith("n8n-nodes-base.") and not node_type.startswith("@n8n/")
            code_text = ""
            if isinstance(params, dict):
                code_text = "\n".join(str(params.get(k, "")) for k in ("jsCode", "pythonCode", "functionCode", "command"))
            if is_community or RISKY_CODE_RE.search(code_text):
                _add_finding(
                    findings,
                    "SCHEMA005",
                    source,
                    node_name,
                    f"Node '{node_type}' uses a third-party/community package or risky eval/process.env/shell primitive.",
                    "Pin community package versions and avoid eval/process.env dumps inside Code nodes.",
                    ignored,
                )

    edges = _extract_edges(connections)
    outgoing_by_node: dict[str, list[tuple[str, str, int]]] = {name: [] for name in valid_nodes}
    incoming_by_node: dict[str, int] = {name: 0 for name in valid_nodes}

    for src, dst, ctype, branch_idx in edges:
        if src not in valid_nodes or dst not in valid_nodes:
            _add_finding(
                findings,
                "GRAPH001",
                source,
                src,
                f"Connection '{src}' -> '{dst}' ({ctype}[{branch_idx}]) references a missing node.",
                "Remove stale connection entries or restore the missing source/target node.",
                ignored,
            )
            continue
        outgoing_by_node[src].append((dst, ctype, branch_idx))
        incoming_by_node[dst] += 1

    trigger_names: list[str] = []
    for name, node in valid_nodes.items():
        ntype = str(node.get("type", ""))
        if ntype.endswith(".stickyNote"):
            continue
        if _is_trigger_node(ntype):
            trigger_names.append(name)
            if not outgoing_by_node.get(name):
                _add_finding(
                    findings,
                    "GRAPH004",
                    source,
                    name,
                    f"Trigger node '{name}' has zero outgoing connections.",
                    "Connect the trigger to a downstream handler or remove the dead trigger.",
                    ignored,
                )
        elif incoming_by_node.get(name, 0) == 0:
            _add_finding(
                findings,
                "GRAPH002",
                source,
                name,
                f"Non-trigger node '{name}' ({ntype}) has no incoming connections.",
                "Connect this node into an active branch or delete the orphaned node.",
                ignored,
            )

    if not trigger_names:
        _add_finding(
            findings,
            "GRAPH004",
            source,
            "<workflow>",
            "Workflow contains zero trigger nodes.",
            "Add an explicit trigger node (Webhook, Schedule, Manual, or Execute Workflow Trigger).",
            ignored,
        )

    # Per-node parameter, secret, URL, reliability, and MCP checks
    for name, node in valid_nodes.items():
        ntype = str(node.get("type", ""))
        params = node.get("parameters") if isinstance(node.get("parameters"), dict) else {}
        creds = node.get("credentials") if isinstance(node.get("credentials"), dict) else {}

        # Check embedded credential secrets beyond standard {id, name} metadata
        for cred_key, cred_val in creds.items():
            if isinstance(cred_val, dict):
                extra_secret_keys = [k for k in cred_val if SECRET_KEY_RE.search(str(k)) or str(k) == "data"]
                if extra_secret_keys:
                    _add_finding(
                        findings,
                        "SEC003",
                        source,
                        name,
                        f"Credential '{cred_key}' embeds unexpected raw secret fields ({', '.join(extra_secret_keys)}).",
                        "Store only credential id/name references in workflow JSON.",
                        ignored,
                    )

        # Inline auth headers in HTTP Request nodes
        for h_name, h_val in _extract_header_pairs(params):
            if AUTH_HEADER_KEY_RE.match(h_name) and not _is_expression(h_val) and not _is_placeholder(h_val):
                _add_finding(
                    findings,
                    "SEC003",
                    source,
                    name,
                    f"Inline auth header '{h_name}' contains a hardcoded literal ({mask_secret(h_val)}).",
                    "Move header authentication into n8n Credentials or '={{ $env... }}'.",
                    ignored,
                )

        # SEC004: unauthenticated Webhook or MCP Server Trigger
        if ntype.endswith(".webhook") or ntype.endswith(".mcpTrigger"):
            auth_mode = str(params.get("authentication", "")).strip()
            if not auth_mode or auth_mode == "none":
                _add_finding(
                    findings,
                    "SEC004",
                    source,
                    name,
                    f"Public trigger '{name}' ({ntype}) has authentication='{auth_mode or 'unset'}'.",
                    "Require headerAuth, bearerAuth, or basicAuth on public Webhook/MCP triggers.",
                    ignored,
                )

        # REL004: active scheduleTrigger export
        if data.get("active") is True and ("scheduletrigger" in ntype.lower() or ntype.lower().endswith(".cron")):
            _add_finding(
                findings,
                "REL004",
                source,
                name,
                "Workflow is exported with active: true and a schedule/cron trigger.",
                "Set active: false before export/promotion so staging imports do not fire prod schedules.",
                ignored,
            )

        # REL001: continueOnFail / continueRegularOutput without connected error branch
        on_error = str(node.get("onError", ""))
        continue_on_fail = bool(node.get("continueOnFail", False))
        has_error_branch = on_error == "continueErrorOutput" and any(
            ctype == "main" and branch_idx >= 1 for _, ctype, branch_idx in outgoing_by_node.get(name, [])
        )
        if (continue_on_fail or on_error == "continueRegularOutput") and not has_error_branch:
            _add_finding(
                findings,
                "REL001",
                source,
                name,
                f"Node '{name}' swallows errors (continueOnFail={continue_on_fail}, onError='{on_error or 'unset'}') with no connected error branch.",
                "Use onError: 'continueErrorOutput' and wire main[1] to an alert or DLQ handler.",
                ignored,
            )

        # REL003: HTTP Request timeout + retry check
        if ntype.endswith(".httpRequest"):
            options = params.get("options") if isinstance(params.get("options"), dict) else {}
            timeout = options.get("timeout")
            bad_timeout = not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0 or timeout > 120000
            no_retry = not bool(node.get("retryOnFail", False))
            if bad_timeout or no_retry:
                _add_finding(
                    findings,
                    "REL003",
                    source,
                    name,
                    f"HTTP Request '{name}' lacks bounded timeout/retry (timeout={timeout!r}, retryOnFail={node.get('retryOnFail', False)!r}).",
                    "Set options.timeout (for example 10000 ms) and enable retryOnFail.",
                    ignored,
                )

        # REL005: Subworkflow call without error branch
        if ntype.endswith(".executeWorkflow") or "toolworkflow" in ntype.lower():
            if not has_error_branch:
                _add_finding(
                    findings,
                    "REL005",
                    source,
                    name,
                    f"Subworkflow node '{name}' has no connected error branch.",
                    "Set onError: 'continueErrorOutput' on subworkflow calls and wire main[1].",
                    ignored,
                )

        # MCP002: AI Agent / toolWorkflow / toolCode missing output parser or error branch
        if ntype.endswith(".agent") or "toolworkflow" in ntype.lower() or "toolcode" in ntype.lower():
            has_parser = bool(params.get("hasOutputParser")) or any(
                ctype == "ai_outputParser" for src, dst, ctype, _ in edges if dst == name or src == name
            )
            if not has_parser and not has_error_branch:
                _add_finding(
                    findings,
                    "MCP002",
                    source,
                    name,
                    f"AI node '{name}' ({ntype}) lacks a structured output parser or error branch.",
                    "Attach an ai_outputParser node or wire onError: 'continueErrorOutput' to catch empty tool observations.",
                    ignored,
                )

        # Walk string fields in node parameters for expressions, secrets, PII, and URLs
        seen_urls: set[str] = set()
        for param_path, text in _walk_strings(params):
            leaf_key = param_path.split(".")[-1].split("[")[0]
            is_code_field = leaf_key in {"jsCode", "pythonCode", "functionCode"}

            # GRAPH003: malformed expression syntax
            if not is_code_field and ("{{" in text or "}}" in text):
                unbalanced = text.count("{{") != text.count("}}")
                missing_eq = not text.lstrip().startswith("=")
                if unbalanced or missing_eq:
                    _add_finding(
                        findings,
                        "GRAPH003",
                        source,
                        name,
                        f"Parameter '{param_path}' contains expression braces without leading '=' or unbalanced '{{{{ }}}}'.",
                        "Prefix n8n expressions with '=' (e.g. '={{ $json.id }}') and balance braces.",
                        ignored,
                    )

            # SEC001: secret signatures or secret-named literals
            matched_secret = False
            for label, pat in SECRET_VALUE_PATTERNS:
                m = pat.search(text)
                if m:
                    _add_finding(
                        findings,
                        "SEC001",
                        source,
                        name,
                        f"Detected {label} literal in '{param_path}' ({mask_secret(m.group(0))}).",
                        "Replace hardcoded secret with n8n Credentials or '={{ $env.SECRET_NAME }}'.",
                        ignored,
                    )
                    matched_secret = True
                    break

            if not matched_secret and SECRET_KEY_RE.search(leaf_key):
                if INLINE_BEARER_RE.match(text) or (not _is_expression(text) and not _is_placeholder(text) and len(text.strip()) >= 8):
                    _add_finding(
                        findings,
                        "SEC001",
                        source,
                        name,
                        f"Secret-like parameter '{param_path}' holds a hardcoded literal ({mask_secret(text)}).",
                        "Use '={{ $env... }}' or n8n Credentials instead of a literal secret.",
                        ignored,
                    )

            # SEC005: hardcoded PII email literals
            if not _is_expression(text):
                for email_match in EMAIL_RE.finditer(text):
                    domain = email_match.group(1).lower()
                    if domain not in SAFE_EMAIL_DOMAINS:
                        _add_finding(
                            findings,
                            "SEC005",
                            source,
                            name,
                            f"Parameter '{param_path}' contains hardcoded email address (*@{domain}).",
                            "Move recipient addresses to $env, $vars, or incoming trigger data.",
                            ignored,
                        )
                        break

            # URL001..URL004: hardcoded URL literals
            if not _is_expression(text):
                for url_match in URL_RE.finditer(text):
                    raw_url = url_match.group(0).rstrip(".,);")
                    if raw_url in seen_urls:
                        continue
                    seen_urls.add(raw_url)
                    parsed = urlparse(raw_url)
                    host = parsed.hostname or ""
                    if host.lower() in SAFE_SCHEMA_HOSTS:
                        continue
                    _add_finding(
                        findings,
                        "URL001",
                        source,
                        name,
                        f"Hardcoded URL '{raw_url}' in '{param_path}'.",
                        "Parameterize base URLs via '={{ $env.API_BASE_URL }}' or '$vars'.",
                        ignored,
                    )
                    if CHAT_WEBHOOK_RE.search(raw_url):
                        _add_finding(
                            findings,
                            "URL004",
                            source,
                            name,
                            f"Hardcoded chat/webhook callback URL in '{param_path}' ({parsed.netloc}).",
                            "Store webhook callback URLs in $env or n8n Credentials.",
                            ignored,
                        )
                    if host and _is_local_or_private_host(host):
                        _add_finding(
                            findings,
                            "URL003",
                            source,
                            name,
                            f"Localhost, tunnel, or private-network URL '{raw_url}' in '{param_path}'.",
                            "Replace local/private URLs with environment-configured HTTPS endpoints.",
                            ignored,
                        )
                    elif parsed.scheme.lower() == "http":
                        _add_finding(
                            findings,
                            "URL002",
                            source,
                            name,
                            f"Cleartext http:// URL '{raw_url}' in '{param_path}'.",
                            "Upgrade endpoint to https:// to protect tokens and payloads in transit.",
                            ignored,
                        )

    # Graph reachability checks: IDEMP001 and MCP001
    for name, node in valid_nodes.items():
        ntype = str(node.get("type", ""))
        if ntype.endswith(".webhook"):
            _check_webhook_idempotency(name, valid_nodes, outgoing_by_node, findings, source, ignored)
        if ntype.endswith(".mcpTrigger"):
            _check_mcp_sync_timeout(name, valid_nodes, outgoing_by_node, findings, source, ignored)

    return findings


def _is_mutating_node(node: dict[str, Any]) -> bool:
    ntype = str(node.get("type", "")).lower()
    params = node.get("parameters") if isinstance(node.get("parameters"), dict) else {}
    if ntype.endswith(".httprequest"):
        method = str(params.get("method", "GET")).upper()
        return method in {"POST", "PUT", "PATCH", "DELETE"}
    return any(hint in ntype for hint in MUTATING_NODE_HINTS)


def _is_dedupe_node(node: dict[str, Any]) -> bool:
    ntype = str(node.get("type", ""))
    name = str(node.get("name", ""))
    return ntype in DEDUPE_NODE_TYPES or bool(DEDUPE_NAME_RE.search(name))


def _check_webhook_idempotency(
    trigger_name: str,
    valid_nodes: dict[str, dict[str, Any]],
    outgoing_by_node: dict[str, list[tuple[str, str, int]]],
    findings: list[dict[str, Any]],
    source: str,
    ignored: set[str],
) -> None:
    queue: deque[tuple[str, bool]] = deque([(trigger_name, False)])
    visited: set[tuple[str, bool]] = {(trigger_name, False)}
    exposed_mutators: list[str] = []

    while queue:
        cur, has_guard = queue.popleft()
        for nxt, ctype, _ in outgoing_by_node.get(cur, []):
            if ctype != "main" or nxt not in valid_nodes:
                continue
            nxt_node = valid_nodes[nxt]
            nxt_guard = has_guard or _is_dedupe_node(nxt_node)
            if _is_mutating_node(nxt_node) and not nxt_guard:
                exposed_mutators.append(nxt)
            state = (nxt, nxt_guard)
            if state not in visited:
                visited.add(state)
                queue.append(state)

    if exposed_mutators:
        targets = ", ".join(sorted(set(exposed_mutators)))
        _add_finding(
            findings,
            "IDEMP001",
            source,
            trigger_name,
            f"Webhook '{trigger_name}' reaches mutating node(s) ({targets}) without an idempotency/dedupe guard.",
            "Insert a dedupe lookup + If/Switch check before side-effect nodes to survive duplicate webhook deliveries.",
            ignored,
        )


def _check_mcp_sync_timeout(
    trigger_name: str,
    valid_nodes: dict[str, dict[str, Any]],
    outgoing_by_node: dict[str, list[tuple[str, str, int]]],
    findings: list[dict[str, Any]],
    source: str,
    ignored: set[str],
) -> None:
    # An async 202 pattern responds immediately from the trigger branch before slow work.
    direct_targets = [nxt for nxt, ctype, _ in outgoing_by_node.get(trigger_name, []) if ctype == "main"]
    has_immediate_ack = any(
        str(valid_nodes[nxt].get("type", "")).lower().endswith(".respondtowebhook")
        for nxt in direct_targets
        if nxt in valid_nodes
    )
    if has_immediate_ack:
        return

    queue: deque[str] = deque([trigger_name])
    visited: set[str] = {trigger_name}
    slow_nodes: list[str] = []

    while queue:
        cur = queue.popleft()
        for nxt, ctype, _ in outgoing_by_node.get(cur, []):
            if ctype != "main" or nxt not in valid_nodes:
                continue
            nxt_node = valid_nodes[nxt]
            ntype = str(nxt_node.get("type", "")).lower()
            if ntype.endswith(".httprequest") or ntype.endswith(".executeworkflow") or ntype.endswith(".agent"):
                slow_nodes.append(nxt)
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)

    if slow_nodes or len(visited) >= 4:
        _add_finding(
            findings,
            "MCP001",
            source,
            trigger_name,
            f"MCP trigger '{trigger_name}' runs synchronous slow nodes ({', '.join(slow_nodes) or 'multi-hop'}) with no async 202 ack.",
            "Return an async 202 job ID immediately and poll status to avoid 125s HTTP 502 timeouts and double execution.",
            ignored,
        )
