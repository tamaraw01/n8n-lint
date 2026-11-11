import unittest

from n8n_lint.rules import ALL_RULES, lint_workflow_data


def _clean_workflow() -> dict:
    return {
        "name": "Clean Lead Intake",
        "active": False,
        "settings": {"errorWorkflow": "wf_global_error_handler"},
        "nodes": [
            {
                "id": "n1",
                "name": "Webhook Trigger",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 2,
                "position": [100, 200],
                "parameters": {
                    "path": "lead-intake",
                    "httpMethod": "POST",
                    "authentication": "headerAuth",
                },
            },
            {
                "id": "n2",
                "name": "Dedupe Check",
                "type": "n8n-nodes-base.if",
                "typeVersion": 2,
                "position": [320, 200],
                "parameters": {
                    "conditions": {
                        "string": [
                            {"value1": "={{ $json.headers['x-idempotency-key'] }}"}
                        ]
                    }
                },
            },
            {
                "id": "n3",
                "name": "Upsert CRM",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4.2,
                "position": [540, 200],
                "onError": "continueErrorOutput",
                "retryOnFail": True,
                "maxTries": 3,
                "parameters": {
                    "method": "POST",
                    "url": "={{ $env.CRM_API_URL + '/leads' }}",
                    "options": {"timeout": 10000},
                },
                "credentials": {
                    "httpHeaderAuth": {"id": "cred_01", "name": "CRM Auth"}
                },
            },
            {
                "id": "n4",
                "name": "Respond OK",
                "type": "n8n-nodes-base.respondToWebhook",
                "typeVersion": 1.1,
                "position": [760, 140],
                "parameters": {
                    "respondWith": "json",
                    "responseBody": "={{ JSON.stringify({ok: true}) }}",
                },
            },
            {
                "id": "n5",
                "name": "Error Escalation",
                "type": "n8n-nodes-base.noOp",
                "typeVersion": 1,
                "position": [760, 280],
                "parameters": {},
            },
        ],
        "connections": {
            "Webhook Trigger": {
                "main": [[{"node": "Dedupe Check", "type": "main", "index": 0}]]
            },
            "Dedupe Check": {
                "main": [[{"node": "Upsert CRM", "type": "main", "index": 0}]]
            },
            "Upsert CRM": {
                "main": [
                    [{"node": "Respond OK", "type": "main", "index": 0}],
                    [{"node": "Error Escalation", "type": "main", "index": 0}],
                ]
            },
        },
    }


class TestRuleRegistryAndCleanWorkflow(unittest.TestCase):
    def test_at_least_25_rules_registered(self) -> None:
        self.assertGreaterEqual(len(ALL_RULES), 25)
        ids = [r.id for r in ALL_RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_clean_workflow_produces_zero_findings(self) -> None:
        findings = lint_workflow_data(_clean_workflow(), "clean.json")
        self.assertEqual(findings, [])


class TestSecretAndUrlRules(unittest.TestCase):
    def test_sec001_detects_and_redacts_hardcoded_api_key(self) -> None:
        wf = _clean_workflow()
        secret = "sk-ant-api03-1234567890abcdef1234567890abcdef"
        wf["nodes"][2]["parameters"]["headerParameters"] = {
            "parameters": [{"name": "x-api-key", "value": secret}]
        }
        findings = lint_workflow_data(wf, "leak.json")
        sec001 = [f for f in findings if f["rule_id"] == "SEC001"]
        self.assertTrue(sec001)
        self.assertEqual(sec001[0]["severity"], "error")
        self.assertNotIn(secret, sec001[0]["detail"])

    def test_sec002_detects_pindata(self) -> None:
        wf = _clean_workflow()
        wf["pinData"] = {"Webhook Trigger": [{"json": {"email": "alice@corp.test"}}]}
        findings = lint_workflow_data(wf, "pinned.json")
        self.assertTrue(any(f["rule_id"] == "SEC002" for f in findings))

    def test_sec003_detects_inline_auth_header_or_embedded_credential_secret(self) -> None:
        wf = _clean_workflow()
        wf["nodes"][2]["parameters"]["headerParameters"] = {
            "parameters": [{"name": "Authorization", "value": "Bearer hardcoded-token-value"}]
        }
        findings = lint_workflow_data(wf, "auth.json")
        self.assertTrue(any(f["rule_id"] == "SEC003" for f in findings))

    def test_sec004_detects_unauthenticated_webhook(self) -> None:
        wf = _clean_workflow()
        wf["nodes"][0]["parameters"]["authentication"] = "none"
        findings = lint_workflow_data(wf, "unauth.json")
        self.assertTrue(any(f["rule_id"] == "SEC004" for f in findings))

    def test_sec005_detects_hardcoded_pii_email(self) -> None:
        wf = _clean_workflow()
        wf["nodes"][4]["parameters"] = {"notifyEmail": "founder@privateclient.io"}
        findings = lint_workflow_data(wf, "pii.json")
        self.assertTrue(any(f["rule_id"] == "SEC005" for f in findings))

    def test_url001_002_003_004_detect_hardcoded_urls(self) -> None:
        wf = _clean_workflow()
        wf["nodes"][2]["parameters"]["url"] = "http://127.0.0.1:5678/webhook/test"
        wf["nodes"][4]["parameters"] = {
            "slackWebhook": "https://hooks.slack.com/services/T000/B000/XXXX"
        }
        findings = lint_workflow_data(wf, "urls.json")
        rule_ids = {f["rule_id"] for f in findings}
        self.assertIn("URL001", rule_ids)
        self.assertIn("URL003", rule_ids)
        self.assertIn("URL004", rule_ids)

        wf2 = _clean_workflow()
        wf2["nodes"][2]["parameters"]["url"] = "http://api.staging-client.com/v1/leads"
        findings2 = lint_workflow_data(wf2, "cleartext.json")
        self.assertIn("URL002", {f["rule_id"] for f in findings2})


class TestReliabilityMcpSchemaAndGraphRules(unittest.TestCase):
    def test_rel001_detects_continue_on_fail_without_error_branch(self) -> None:
        wf = _clean_workflow()
        wf["nodes"][2].pop("onError", None)
        wf["nodes"][2]["continueOnFail"] = True
        wf["connections"]["Upsert CRM"]["main"] = [
            [{"node": "Respond OK", "type": "main", "index": 0}]
        ]
        wf["nodes"].pop()  # remove Error Escalation so no orphan warning noise
        findings = lint_workflow_data(wf, "silent.json")
        self.assertTrue(any(f["rule_id"] == "REL001" for f in findings))

    def test_rel002_detects_missing_error_workflow(self) -> None:
        wf = _clean_workflow()
        wf["settings"] = {}
        findings = lint_workflow_data(wf, "noerrwf.json")
        self.assertTrue(any(f["rule_id"] == "REL002" for f in findings))

    def test_rel003_detects_missing_http_timeout_and_retry(self) -> None:
        wf = _clean_workflow()
        wf["nodes"][2]["parameters"]["options"] = {}
        wf["nodes"][2]["retryOnFail"] = False
        findings = lint_workflow_data(wf, "notimeout.json")
        self.assertTrue(any(f["rule_id"] == "REL003" for f in findings))

    def test_rel004_detects_active_schedule_trigger_export(self) -> None:
        wf = _clean_workflow()
        wf["active"] = True
        wf["nodes"][0] = {
            "id": "n1",
            "name": "Webhook Trigger",
            "type": "n8n-nodes-base.scheduleTrigger",
            "typeVersion": 1.2,
            "position": [100, 200],
            "parameters": {"rule": {"interval": [{"field": "minutes"}]}},
        }
        findings = lint_workflow_data(wf, "sched.json")
        self.assertTrue(any(f["rule_id"] == "REL004" for f in findings))

    def test_rel005_detects_execute_workflow_without_error_branch(self) -> None:
        wf = _clean_workflow()
        wf["nodes"][2] = {
            "id": "n3",
            "name": "Upsert CRM",
            "type": "n8n-nodes-base.executeWorkflow",
            "typeVersion": 1.1,
            "position": [540, 200],
            "parameters": {"workflowId": "sub_123"},
        }
        wf["connections"]["Upsert CRM"]["main"] = [
            [{"node": "Respond OK", "type": "main", "index": 0}]
        ]
        findings = lint_workflow_data(wf, "subwf.json")
        self.assertTrue(any(f["rule_id"] == "REL005" for f in findings))

    def test_idemp001_detects_webhook_to_mutation_without_dedupe(self) -> None:
        wf = _clean_workflow()
        wf["connections"]["Webhook Trigger"]["main"] = [
            [{"node": "Upsert CRM", "type": "main", "index": 0}]
        ]
        # Remove Dedupe Check cleanly
        wf["nodes"] = [n for n in wf["nodes"] if n["name"] != "Dedupe Check"]
        wf["connections"].pop("Dedupe Check")
        findings = lint_workflow_data(wf, "noidemp.json")
        self.assertTrue(any(f["rule_id"] == "IDEMP001" for f in findings))

    def test_mcp001_and_mcp002_detect_mcp_timeout_and_ai_tool_risks(self) -> None:
        wf = _clean_workflow()
        wf["nodes"][0] = {
            "id": "n1",
            "name": "MCP Server Trigger",
            "type": "@n8n/n8n-nodes-langchain.mcpTrigger",
            "typeVersion": 1,
            "position": [100, 200],
            "parameters": {"authentication": "bearerAuth"},
        }
        wf["nodes"][1] = {
            "id": "n2",
            "name": "AI Agent",
            "type": "@n8n/n8n-nodes-langchain.agent",
            "typeVersion": 1.7,
            "position": [320, 200],
            "parameters": {"text": "={{ $json.query }}"},
        }
        wf["connections"] = {
            "MCP Server Trigger": {
                "main": [[{"node": "AI Agent", "type": "main", "index": 0}]]
            },
            "AI Agent": {
                "main": [[{"node": "Upsert CRM", "type": "main", "index": 0}]]
            },
            "Upsert CRM": wf["connections"]["Upsert CRM"],
        }
        findings = lint_workflow_data(wf, "mcp.json")
        rule_ids = {f["rule_id"] for f in findings}
        self.assertIn("MCP001", rule_ids)
        self.assertIn("MCP002", rule_ids)

    def test_schema_and_graph_rules(self) -> None:
        bad_root = lint_workflow_data({"foo": "bar"}, "bad.json")
        self.assertIn("SCHEMA001", {f["rule_id"] for f in bad_root})

        wf = _clean_workflow()
        wf["nodes"][1]["name"] = "Upsert CRM"  # duplicate name (SCHEMA003)
        wf["nodes"][2]["typeVersion"] = 1  # legacy httpRequest (SCHEMA004)
        wf["nodes"].append(
            {
                "id": "n6",
                "name": "Custom Eval",
                "type": "n8n-nodes-custom-pkg.runner",
                "typeVersion": 1,
                "position": [900, 300],
                "parameters": {"jsCode": "const x = eval('1+1'); return process.env;"},
            }
        )
        wf["nodes"].append(
            {
                "id": "n7",
                "name": "Bad Expr",
                "type": "n8n-nodes-base.set",
                "typeVersion": 3,
                "position": "not-a-pair",  # SCHEMA002
                "parameters": {"value": "{{ $json.id }}"},  # GRAPH003
            }
        )
        wf["connections"]["Ghost Source"] = {
            "main": [[{"node": "Missing Target", "type": "main", "index": 0}]]
        }
        findings = lint_workflow_data(wf, "broken.json")
        rule_ids = {f["rule_id"] for f in findings}
        self.assertIn("SCHEMA002", rule_ids)
        self.assertIn("SCHEMA003", rule_ids)
        self.assertIn("SCHEMA004", rule_ids)
        self.assertIn("SCHEMA005", rule_ids)
        self.assertIn("GRAPH001", rule_ids)
        self.assertIn("GRAPH002", rule_ids)
        self.assertIn("GRAPH003", rule_ids)

    def test_graph004_detects_disconnected_trigger(self) -> None:
        wf = _clean_workflow()
        wf["connections"]["Webhook Trigger"]["main"] = [[]]
        findings = lint_workflow_data(wf, "notrig.json")
        self.assertIn("GRAPH004", {f["rule_id"] for f in findings})


if __name__ == "__main__":
    unittest.main()
