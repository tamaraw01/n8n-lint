# n8n-lint

Static CLI linter and secret redactor for exported n8n workflow JSON files.

`n8n-lint` catches leaked API keys, exported `pinData`, hardcoded localhost or staging URLs, silent `continueOnFail` traps, unauthenticated Webhook and MCP triggers, missing idempotency checks, and broken node schemas before you push to Git or import into production. It runs offline using only Python's standard library (zero pip dependencies).

- Packaged ZIP release (`$0+` MIT): [Download n8n-lint on Gumroad](https://aditama1.gumroad.com/l/n8n-lint)
- Production runtime blueprints & GitOps kit: [n8n + MCP Agency Ops Kit ($39 / $79 / $149)](https://aditama1.gumroad.com/l/n8n-mcp-agency-ops) (use code `LINT20` for 20% off Pro `$79` or Agency `$149`)

## Quickstart

Requires Python 3.10+. This tool is not published on PyPI or npm, so `pip install n8n-lint`, `uvx n8n-lint`, and `npx n8n-lint` will not install it. Install from the GitHub tag instead:

```bash
pipx install git+https://github.com/tamaraw01/n8n-lint@v1.0.0
# or, inside a virtualenv:
pip install git+https://github.com/tamaraw01/n8n-lint@v1.0.0
```

From an extracted release ZIP (GitHub release or Gumroad download):

```bash
./install.sh
```

Or run directly without installing:

```bash
PYTHONPATH=src python3 -m n8n_lint scan examples/clean_workflow.json
PYTHONPATH=src python3 -m n8n_lint scan examples/broken_workflow.json
```

Windows PowerShell:

```powershell
.\install.ps1
```

## Example output

Running against `examples/clean_workflow.json`:

```text
n8n-lint v1.0.0 (scanned 1 file(s))
PASS 0 errors, 0 warnings
```

Running against `examples/broken_workflow.json`:

```text
n8n-lint v1.0.0 (scanned 1 file(s))
  WARN  SEC002 examples/broken_workflow.json :: <workflow>
        Workflow contains non-empty 'pinData' across 1 node(s).
        Fix: Clear pinned data or run 'n8n-lint redact' before committing workflow JSON.
  ERROR GRAPH001 examples/broken_workflow.json :: Call Staging API
        Connection 'Call Staging API' -> 'Missing Node' (main[0]) references a missing node.
        Fix: Remove stale connection entries or restore the missing source/target node.
  ERROR SEC004 examples/broken_workflow.json :: Webhook Trigger
        Public trigger 'Webhook Trigger' (n8n-nodes-base.webhook) has authentication='none'.
        Fix: Require headerAuth, bearerAuth, or basicAuth on public Webhook/MCP triggers.
  ERROR SEC003 examples/broken_workflow.json :: Call Staging API
        Inline auth header 'Authorization' contains a hardcoded literal (Bear***90).
        Fix: Move header authentication into n8n Credentials or '={{ $env... }}'.
  ERROR REL001 examples/broken_workflow.json :: Call Staging API
        Node 'Call Staging API' swallows errors (continueOnFail=True, onError='unset') with no connected error branch.
        Fix: Use onError: 'continueErrorOutput' and wire main[1] to an alert or DLQ handler.
  ERROR URL003 examples/broken_workflow.json :: Call Staging API
        Localhost, tunnel, or private-network URL 'http://127.0.0.1:8080/api/leads' in 'url'.
        Fix: Replace local/private URLs with environment-configured HTTPS endpoints.
  ERROR SEC001 examples/broken_workflow.json :: Call Staging API
        Detected Anthropic key literal in 'headerParameters.parameters[0].value' (sk-a***90).
        Fix: Replace hardcoded secret with n8n Credentials or '={{ $env.SECRET_NAME }}'.
...
SUMMARY: 6 error(s), 11 warning(s) across 1 file(s)
```

## Commands

### `scan`

Scan one or more workflow JSON files or directories recursively:

```bash
n8n-lint scan workflows/
n8n-lint scan workflows/ --strict --format json
n8n-lint scan workflows/ --format sarif --output n8n-lint.sarif
n8n-lint scan workflows/ --format markdown --ignore REL002,URL001
n8n-lint scan path1.json path2/ path3.json
```

When passing a directory, `scan` discovers all `*.json` files while automatically skipping `.git`, `.venv`, `venv`, `node_modules`, `__pycache__`, `dist`, and `build`.

If invoked without an explicit subcommand (such as `n8n-lint workflows/`), the CLI automatically routes to `scan`.

Supported options:
- `paths`: one or more files or directories to inspect.
- `--format {text,json,sarif,markdown}`: report output format (default: `text`).
- `--output <path>`: write report output to a file instead of stdout.
- `--strict`: exit with code `1` on warnings in addition to errors.
- `--ignore <rules>`: comma-separated list of rule IDs to suppress (case-insensitive, e.g. `--ignore REL002,URL001`).
- `--no-color`: disable ANSI color output (also honored when `NO_COLOR` environment variable is set or stdout is not a tty).

### `redact`

Scrub secrets, `pinData`, and credential IDs before sharing or committing:

```bash
# Write redacted JSON to a new file
n8n-lint redact workflow.json --output workflow.redacted.json --deactivate

# Overwrite the input file in place
n8n-lint redact workflow.json --in-place --deactivate

# Print redacted JSON to stdout for piping
n8n-lint redact workflow.json --deactivate | jq .
```

Redaction details:
- **`pinData`**: reset to an empty `{}` object across all nodes to remove captured execution snapshots.
- **Credential objects**: replaces `id` with `"__SCRUBBED_CREDENTIAL_ID__"` and scrubs any fields other than `name` to `"__REDACTED__"`.
- **Header parameters**: scrubs `Authorization`, `x-api-key`, `x-auth-token`, and `api-key` header values to `"__REDACTED__"`.
- **Sensitive parameters**: scrubs literal values matching token formats (Anthropic, OpenAI, AWS, GitHub, Slack, Stripe, PEM private keys, JWTs) or sensitive key names.
- **Dynamic expressions preserved**: values starting with `=` and containing `{{` or `$` (such as `={{ $env.SECRET }}`) are recognized as expressions and preserved.
- **`--deactivate`**: sets top-level `"active": false` and marks `scheduleTrigger` and `cron` nodes with `"disabled": true` so workflows cannot fire accidentally after import.

### `rules`

List all 26 built-in rules with rule ID, severity, category, and remediation details:

```bash
n8n-lint rules
n8n-lint rules --json
```

### Exit codes

- `0`: zero errors (and zero warnings when `--strict` is set)
- `1`: one or more errors (or warnings under `--strict`)
- `2`: invalid arguments, missing path, or no JSON files found

## CI and pre-commit integration

A ready-to-use GitHub Actions workflow is included at `.github/workflows/n8n-lint.yml` (runs `n8n-lint` and uploads SARIF results to GitHub Code Scanning). Copy this job into your own repo to lint exported workflows under `workflows/` on every pull request.

Note: In the workflow below, `workflows/` represents the directory containing your exported workflow JSON files. Adjust this path to match your repository structure (such as `examples/` or repository root), or ensure the target directory exists before running `n8n-lint scan` to avoid exit code 2.

```yaml
jobs:
  n8n-lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install git+https://github.com/tamaraw01/n8n-lint@v1.0.0
      - run: n8n-lint scan workflows/ --format sarif --output n8n-lint.sarif --no-color
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: n8n-lint.sarif
```

A pre-commit hook definition is included at `.pre-commit-hooks.yaml`:

```yaml
repos:
  - repo: https://github.com/tamaraw01/n8n-lint
    rev: v1.0.0
    hooks:
      - id: n8n-lint
```

## Rule catalog (26 rules)

| Rule ID | Severity | Category | Check |
| :--- | :--- | :--- | :--- |
| `SCHEMA001` | ERROR | schema | Top-level JSON object requires `nodes` list and `connections` map |
| `SCHEMA002` | ERROR | schema | Node requires `name`, `type`, `typeVersion`, `[x, y]` `position`, object `parameters` |
| `SCHEMA003` | ERROR | schema | Duplicate node `name` or non-empty `id` |
| `SCHEMA004` | WARN | schema | Non-positive or legacy node `typeVersion` (such as HTTP Request < 4, Webhook < 2) |
| `SCHEMA005` | WARN | schema | Community node package or `eval`/`child_process`/`process.env` in code nodes |
| `GRAPH001` | ERROR | graph | Connection source or target references missing node |
| `GRAPH002` | WARN | graph | Orphaned non-trigger node with zero incoming connections |
| `GRAPH003` | ERROR | graph | `{{ }}` expression missing leading `=` or unbalanced braces |
| `GRAPH004` | WARN | graph | Workflow has zero triggers or a trigger with zero outgoing connections |
| `SEC001` | ERROR | security | Hardcoded API key, JWT, PEM key, or secret parameter literal |
| `SEC002` | WARN | security | Non-empty `pinData` exported inside workflow JSON |
| `SEC003` | ERROR | security | Hardcoded `Authorization`/`x-api-key` header or embedded credential secret |
| `SEC004` | ERROR | security | Public Webhook or MCP Server Trigger with authentication unset or `none` |
| `SEC005` | WARN | security | Hardcoded non-example email literal in parameters |
| `URL001` | WARN | urls | Hardcoded `http://` or `https://` URL instead of `$env` or `$vars` |
| `URL002` | ERROR | urls | Non-local cleartext `http://` endpoint |
| `URL003` | ERROR | urls | Hardcoded `localhost`, `127.0.0.1`, tunnel (`ngrok`), or private RFC1918/metadata IP |
| `URL004` | WARN | urls | Hardcoded Slack, Discord, or `webhook.site` callback URL |
| `REL001` | ERROR | reliability | `continueOnFail: true` or `continueRegularOutput` without connected error branch |
| `REL002` | WARN | reliability | Missing `settings.errorWorkflow` handler |
| `REL003` | WARN | reliability | HTTP Request node missing bounded `options.timeout` or `retryOnFail` |
| `REL004` | ERROR | reliability | Exported workflow has `active: true` alongside a `scheduleTrigger` or `cron` node |
| `REL005` | WARN | reliability | `executeWorkflow` or `toolWorkflow` missing connected `continueErrorOutput` branch |
| `IDEMP001` | WARN | idempotency | Webhook feeding mutating nodes without a dedupe/idempotency check |
| `MCP001` | WARN | mcp | `mcpTrigger` connected to synchronous slow branch without immediate async ack |
| `MCP002` | WARN | mcp | AI Agent or tool node missing structured output parser or error branch |

## Compatibility matrix

| Target | Supported versions | Notes |
| :--- | :--- | :--- |
| Python | 3.10, 3.11, 3.12, 3.13 | Pure Python standard library, zero external packages |
| OS | Linux, macOS, Windows | Tested on POSIX shells and Windows PowerShell |
| n8n exports | v1.x, v2.x workflow JSON | Supports `n8n-nodes-base.*` and `@n8n/n8n-nodes-langchain.*` |
| CI outputs | Text, JSON, SARIF 2.1.0, Markdown | GitHub Code Scanning compatible via SARIF |

## Self-test and reproducible release build

Run the full `unittest` suite:

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -v
```

Build the deterministic release archive and SHA-256 checksum under `dist/`:

```bash
python3 scripts/build_release.py
```

## Upgrade Path: Runtime Safeguards & Agency Ops

`n8n-lint` (`$0+`, MIT) catches static hazards in exported workflow JSON before commit or deploy ([Gumroad release](https://aditama1.gumroad.com/l/n8n-lint)). When you need runtime safeguards, async MCP `202` handling, GitOps promotion, and client handoff tooling, compare [n8n + MCP Agency Ops Kit](https://aditama1.gumroad.com/l/n8n-mcp-agency-ops) tiers (use code `LINT20` at checkout for 20% off Pro `$79` or Agency `$149`):

| Tier | Price | What Is Included |
|---|---:|---|
| **[n8n-lint](https://aditama1.gumroad.com/l/n8n-lint)** | **$0+** | 26-rule static linter, `redact` sanitizer, SARIF/JSON/Markdown output, GitHub Actions + `pre-commit` hooks, 23 unit tests, MIT license (this package) |
| **[Starter](https://aditama1.gumroad.com/l/n8n-mcp-agency-ops)** | **$39** | 5 core reliability workflow blueprints (`01` to `05`: Silent-Failure Sentinel, Idempotent Webhook Dedupe, DLQ Replay, AI Empty-Output Guard, Slack/PagerDuty Escalation), strict agency validator (`10` policy checks), synthetic mock n8n smoke suite, 1-command installer & health check (`22` files) |
| **[Pro (Recommended)](https://aditama1.gumroad.com/l/n8n-mcp-agency-ops)** | **$79** | Everything in Starter + workflows `06` to `10` (Async MCP `202` Dispatcher & Poller, Heartbeat Watchdog, Staging Schedule Disarm, Execution Error Digest), Async 202 MCP Bridge (`stdio` + HTTP, `6` MCP tools), GitOps `promote.py` CLI with credential scrub & rollback snapshots, 15-minute walkthrough (`33` files, `$63.20` with `LINT20`) |
| **[Agency](https://aditama1.gumroad.com/l/n8n-mcp-agency-ops)** | **$149** | Everything in Pro + 5-seat commercial client-handoff license, multi-client tenant isolation router (`tenants/`), client SLA handoff generator (`handoff/` templates), and GitHub Actions CI gate (`46` files, `$119.20` with `LINT20`) |

## Name note

This project (`tamaraw01/n8n-lint`) is not affiliated with the PyPI package `n8n-lint` ([pypi.org/project/n8n-lint](https://pypi.org/project/n8n-lint/)) or with [lorenzespinosa/n8n-lint](https://github.com/lorenzespinosa/n8n-lint). They are separate tools that share the name.

## License

MIT. See [LICENSE](LICENSE).
