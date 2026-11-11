from __future__ import annotations

import json
from typing import Any

from n8n_lint import __version__
from n8n_lint.rules import ALL_RULES


def format_report(
    findings: list[dict[str, Any]],
    files_scanned: int,
    fmt: str = "text",
    use_color: bool = True,
) -> str:
    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warn")

    if fmt == "json":
        payload = {
            "tool": "n8n-lint",
            "version": __version__,
            "summary": {
                "files_scanned": files_scanned,
                "total_findings": len(findings),
                "errors": errors,
                "warnings": warnings,
                "status": "fail" if errors else ("warn" if warnings else "pass"),
            },
            "findings": findings,
        }
        return json.dumps(payload, indent=2)

    if fmt == "sarif":
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "n8n-lint",
                            "version": __version__,
                            "rules": [
                                {
                                    "id": r.id,
                                    "name": r.title,
                                    "shortDescription": {"text": r.title},
                                    "fullDescription": {"text": r.description},
                                    "defaultConfiguration": {
                                        "level": "error" if r.severity == "error" else "warning"
                                    },
                                }
                                for r in ALL_RULES
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": f["rule_id"],
                            "level": "error" if f["severity"] == "error" else "warning",
                            "message": {
                                "text": f"[{f['node']}] {f['detail']} Fix: {f['remediation']}"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f["file"]},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                        for f in findings
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    if fmt == "markdown":
        lines = [
            "# n8n-lint Report",
            "",
            f"- Files scanned: {files_scanned}",
            f"- Errors: {errors}",
            f"- Warnings: {warnings}",
            "",
        ]
        if not findings:
            lines.append("All checked workflows passed with zero findings.")
            return "\n".join(lines)
        lines.extend(
            [
                "| Severity | Rule | File | Node | Detail | Remediation |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for f in findings:
            detail = f["detail"].replace("|", "\\|")
            rem = f["remediation"].replace("|", "\\|")
            lines.append(
                f"| {f['severity'].upper()} | {f['rule_id']} | `{f['file']}` | `{f['node']}` | {detail} | {rem} |"
            )
        return "\n".join(lines)

    # Default terminal text output
    red = "\033[31m" if use_color else ""
    yellow = "\033[33m" if use_color else ""
    green = "\033[32m" if use_color else ""
    reset = "\033[0m" if use_color else ""
    bold = "\033[1m" if use_color else ""

    lines = [f"{bold}n8n-lint v{__version__}{reset} (scanned {files_scanned} file(s))"]
    if not findings:
        lines.append(f"{green}PASS{reset} 0 errors, 0 warnings")
        return "\n".join(lines)

    for f in findings:
        tag_color = red if f["severity"] == "error" else yellow
        sev = f["severity"].upper()
        lines.append(
            f"  {tag_color}{sev:5s}{reset} {bold}{f['rule_id']}{reset} {f['file']} :: {f['node']}"
        )
        lines.append(f"        {f['detail']}")
        lines.append(f"        Fix: {f['remediation']}")

    summary_color = red if errors else yellow
    lines.append("")
    lines.append(
        f"{summary_color}SUMMARY{reset}: {errors} error(s), {warnings} warning(s) across {files_scanned} file(s)"
    )
    return "\n".join(lines)
