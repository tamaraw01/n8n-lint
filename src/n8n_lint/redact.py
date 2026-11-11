from __future__ import annotations

import copy
from typing import Any

from n8n_lint.rules import AUTH_HEADER_KEY_RE, INLINE_BEARER_RE, SECRET_KEY_RE, SECRET_VALUE_PATTERNS


def _is_expression(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("=") and ("{{" in stripped or "$" in stripped)


def _scrub_value(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _scrub_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_value(key, item) for item in value]
    if isinstance(value, str):
        if _is_expression(value):
            return value
        for _, pat in SECRET_VALUE_PATTERNS:
            if pat.search(value):
                return "__REDACTED__"
        if INLINE_BEARER_RE.match(value):
            return "__REDACTED__"
        if SECRET_KEY_RE.search(key) and value.strip():
            return "__REDACTED__"
    return value


def redact_workflow_data(data: dict[str, Any], deactivate: bool = False) -> dict[str, Any]:
    cleaned = copy.deepcopy(data)
    if "pinData" in cleaned:
        cleaned["pinData"] = {}
    if deactivate:
        cleaned["active"] = False

    nodes = cleaned.get("nodes")
    if isinstance(nodes, list):
        for node in nodes:
            if not isinstance(node, dict):
                continue
            if deactivate:
                node_type = str(node.get("type", "")).lower()
                if "scheduletrigger" in node_type or "cron" in node_type:
                    node["disabled"] = True
            creds = node.get("credentials")
            if isinstance(creds, dict):
                for cred_obj in creds.values():
                    if isinstance(cred_obj, dict):
                        if "id" in cred_obj:
                            cred_obj["id"] = "__SCRUBBED_CREDENTIAL_ID__"
                        for k in list(cred_obj.keys()):
                            if k not in {"id", "name"}:
                                cred_obj[k] = "__REDACTED__"

            params = node.get("parameters")
            if isinstance(params, dict):
                hp = params.get("headerParameters")
                if isinstance(hp, dict) and isinstance(hp.get("parameters"), list):
                    for item in hp["parameters"]:
                        if isinstance(item, dict):
                            h_name = str(item.get("name", ""))
                            h_val = item.get("value")
                            if AUTH_HEADER_KEY_RE.match(h_name) and isinstance(h_val, str) and not _is_expression(h_val):
                                item["value"] = "__REDACTED__"
                node["parameters"] = _scrub_value("", params)

    return cleaned
