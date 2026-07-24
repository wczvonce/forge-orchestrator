import json
import tempfile
import unittest
from pathlib import Path

import forge
import forge_adaptive as adaptive


class CheckContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = Path(self.temp.name) / "project"
        self.project.mkdir()
        self.definition = adaptive.CheckDefinition(
            check_id="unit",
            command="npm run test",
            tier="release",
            required_before_done=True,
            check_kind="test",
            require_test_execution=True,
            report_path="test-results.json",
            report_format="vitest-json",
        )
        (self.project / "package.json").write_text(
            json.dumps({"scripts": {"test": "vitest run"}}), encoding="utf-8"
        )
        (self.project / "package-lock.json").write_text(
            '{"lockfileVersion":3}', encoding="utf-8"
        )

    def tearDown(self):
        self.temp.cleanup()

    def contract(self, definitions=None):
        return adaptive.build_check_contract(
            self.project,
            definitions or [self.definition],
            source="explicit_project_config",
            stacks=["typescript"],
            change_reason="Test contract.",
        )

    def test_contract_hash_is_stable(self):
        first = self.contract()
        second = self.contract()
        self.assertEqual(first.contract_hash, second.contract_hash)

    def test_json_key_order_does_not_change_hash(self):
        contract = self.contract()
        payload = contract.model_dump(mode="json")
        reordered = {key: payload[key] for key in reversed(list(payload))}
        loaded = adaptive.CheckContract.model_validate_json(
            json.dumps(reordered, sort_keys=False)
        )
        self.assertEqual(loaded.contract_hash, contract.contract_hash)

    def test_npm_script_change_changes_contract_hash(self):
        before = self.contract()
        (self.project / "package.json").write_text(
            json.dumps({"scripts": {"test": "vitest run --coverage"}}),
            encoding="utf-8",
        )
        after = self.contract()
        self.assertNotEqual(before.contract_hash, after.contract_hash)
        self.assertNotEqual(
            before.indirect_source_hashes["package.json#scripts.test"],
            after.indirect_source_hashes["package.json#scripts.test"],
        )

    def test_lockfile_change_changes_evidence_hash(self):
        before = self.contract()
        (self.project / "package-lock.json").write_text(
            '{"lockfileVersion":3,"packages":{"x":{}}}', encoding="utf-8"
        )
        after = self.contract()
        self.assertNotEqual(
            before.indirect_source_hashes["package-lock.json"],
            after.indirect_source_hashes["package-lock.json"],
        )

    def test_required_check_cannot_be_removed(self):
        previous = self.contract()
        replacement = adaptive.CheckDefinition(
            check_id="lint", command="npm run lint"
        )
        proposed = self.contract([replacement])
        with self.assertRaisesRegex(ValueError, "cannot be removed"):
            adaptive.validate_contract_update(
                previous, proposed, justification="Worker proposal."
            )

    def test_test_execution_requirement_cannot_be_disabled(self):
        previous = self.contract()
        weakened = self.definition.model_copy(
            update={"require_test_execution": False}
        )
        proposed = self.contract([weakened])
        with self.assertRaisesRegex(ValueError, "cannot be disabled"):
            adaptive.validate_contract_update(
                previous, proposed, justification="Worker proposal."
            )

    def test_structured_allowlisted_codex_proposal_is_materialized(self):
        proposal = adaptive.CheckProposal(
            check_id="pytest",
            runner="python-pytest",
            target="tests/unit",
            tier="release",
            required_before_done=True,
            require_test_execution=True,
        )
        definition = adaptive.materialize_check_proposal(proposal)
        self.assertIn("-m pytest tests/unit", definition.command)
        self.assertTrue(definition.required_before_done)

    def test_arbitrary_shell_in_codex_proposal_is_rejected(self):
        with self.assertRaises(ValueError):
            adaptive.CheckProposal(
                check_id="unsafe",
                runner="npm-script",
                target="test && git push",
            )

    def test_unallowlisted_runner_is_rejected(self):
        with self.assertRaises(ValueError):
            adaptive.CheckProposal(
                check_id="unsafe",
                runner="arbitrary-shell",
                target="echo",
            )

    def test_existing_project_without_contract_gets_safe_migration(self):
        config = {
            **forge.DEFAULT_CONFIG,
            "adaptive_orchestration": True,
            "check_definitions": [self.definition.model_dump(mode="json")],
        }
        contract = forge.ensure_check_contract(self.project, config)
        path = self.project / ".forge" / "check-contract.json"
        self.assertTrue(path.is_file())
        self.assertEqual(
            adaptive.CheckContract.model_validate_json(
                path.read_text(encoding="utf-8")
            ).contract_hash,
            contract.contract_hash,
        )

    def test_indirect_drift_is_visible_and_not_ignored(self):
        config = {
            **forge.DEFAULT_CONFIG,
            "adaptive_orchestration": True,
            "check_definitions": [self.definition.model_dump(mode="json")],
        }
        contract = forge.ensure_check_contract(self.project, config)
        (self.project / "package.json").write_text(
            json.dumps({"scripts": {"test": "vitest run --changed"}}),
            encoding="utf-8",
        )
        error = forge.check_contract_runtime_error(self.project, contract)
        self.assertIn("consistency review", error)
        self.assertIn("package.json", error)

    def test_contract_file_tampering_is_rejected(self):
        config = {
            **forge.DEFAULT_CONFIG,
            "adaptive_orchestration": True,
            "check_definitions": [self.definition.model_dump(mode="json")],
        }
        contract = forge.ensure_check_contract(self.project, config)
        path = self.project / ".forge" / "check-contract.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["change_reason"] = "tampered"
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.assertIn(
            "invalid hash",
            forge.check_contract_runtime_error(self.project, contract),
        )

    def test_resume_with_different_contract_hash_stops_safely(self):
        forge.ensure_git_repo(self.project)
        config = {
            **forge.DEFAULT_CONFIG,
            "adaptive_orchestration": True,
            "check_definitions": [self.definition.model_dump(mode="json")],
        }
        contract = forge.ensure_check_contract(self.project, config)
        plan = adaptive.load_or_create_plan(self.project, "Safe goal")
        plan.check_contract_hash = contract.contract_hash
        adaptive.save_plan(self.project, plan)
        run = self.project / ".forge" / "runs" / "source"
        run.mkdir(parents=True)
        (run / "run.json").write_text(
            json.dumps({"goal": "Safe goal", "config": config}), encoding="utf-8"
        )
        continuation = forge.ContinuationPayload(
            source_run_id="source",
            continuation_chain_id="chain",
            next_prompt="Continue exact packet.",
            acceptance_criteria=["Checks pass"],
            repository_fingerprint=forge.repo_fingerprint(self.project),
            repository_manifest=forge.repo_manifest(self.project),
            project_id=adaptive.stable_project_identity(self.project)["project_id"],
            plan_id=plan.plan_id,
            plan_hash=adaptive.plan_hash(plan),
            chain_child_runs=1,
            chain_codex_calls=1,
            chain_no_progress_events=0,
            check_contract_hash="0" * 64,
        )
        (run / "result.json").write_text(
            json.dumps(
                {
                    "schema_version": forge.SCHEMA_VERSION,
                    "run_id": "source",
                    "final_status": "needs_continuation",
                    "stop_reason_code": "reviewer_continue",
                    "automatic_resume_allowed": True,
                    "goal": "Safe goal",
                    "continuation": continuation.model_dump(mode="json"),
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "contract hash changed"):
            forge.load_resume_context(self.project, "source")

    def test_schema_three_plan_remains_readable(self):
        plan = adaptive.load_or_create_plan(self.project, "Legacy goal")
        payload = plan.model_dump(mode="json")
        payload["schema_version"] = 3
        payload.pop("check_contract_hash", None)
        loaded = adaptive.ProjectPlan.model_validate(payload)
        self.assertEqual(loaded.schema_version, 3)
        self.assertIsNone(loaded.check_contract_hash)


if __name__ == "__main__":
    unittest.main()
