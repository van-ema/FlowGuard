from __future__ import annotations

import unittest

from flowguard import (
    FlowguardBlocked,
    FlowguardRuntime,
    ModelDestination,
    ModelEgressAction,
    ModelEgressPolicy,
    ModelRule,
    Provenance,
    SourceRef,
)


def secret_provenance(name: str = "/secrets/id_rsa") -> Provenance:
    return Provenance.from_source("Secret", SourceRef.file(name))


class ModelPolicyTests(unittest.TestCase):
    def test_public_request_is_allowed(self) -> None:
        runtime = FlowguardRuntime()
        destination = ModelDestination("openai", "gpt-test", "external")

        result = runtime.check_model_egress(destination, Provenance.empty())

        self.assertEqual(result.action, ModelEgressAction.ALLOW)
        self.assertEqual(result.policy, "PublicToModel")
        self.assertEqual(runtime.report().summary.allowed_model_request_count, 1)

    def test_secret_request_to_external_model_is_blocked_by_default(self) -> None:
        runtime = FlowguardRuntime()
        destination = ModelDestination("openai", "gpt-test", "external")

        with self.assertRaises(FlowguardBlocked) as raised:
            runtime.check_model_egress(destination, secret_provenance())

        self.assertEqual(raised.exception.policy, "SecretToModel")
        report = runtime.report()
        self.assertEqual(report.summary.violation_count, 1)
        self.assertEqual(report.summary.model_request_count, 1)
        self.assertEqual(report.violations[0].target, destination.target)
        self.assertEqual(report.model_calls[0].action, "BLOCK")

    def test_approved_local_model_allows_and_propagates(self) -> None:
        destination = ModelDestination("ollama", "llama", "local")
        policy = ModelEgressPolicy(
            [
                ModelRule.allow_and_propagate(
                    labels={"Secret"},
                    destinations={"model:ollama:*:local"},
                )
            ]
        )
        runtime = FlowguardRuntime(model_policy=policy)

        result = runtime.check_model_egress(destination, secret_provenance())

        self.assertEqual(result.action, ModelEgressAction.ALLOW_AND_PROPAGATE)
        self.assertEqual(result.policy, "ApprovedSensitiveToModel")

    def test_approved_rule_must_cover_every_input_label(self) -> None:
        destination = ModelDestination("ollama", "llama", "local")
        policy = ModelEgressPolicy(
            [
                ModelRule.allow_and_propagate(
                    labels={"PII"},
                    destinations={"model:ollama:*:local"},
                )
            ]
        )
        provenance = secret_provenance().merge(
            Provenance.from_source("PII", SourceRef(kind="record", name="customer"))
        )
        runtime = FlowguardRuntime(model_policy=policy)

        with self.assertRaises(FlowguardBlocked) as raised:
            runtime.check_model_egress(destination, provenance)

        self.assertEqual(raised.exception.policy, "SecretToModel")

    def test_unknown_server_context_is_blocked_in_strict_mode(self) -> None:
        runtime = FlowguardRuntime(precision_mode="strict")
        destination = ModelDestination("openai", "gpt-test", "external")

        with self.assertRaises(FlowguardBlocked) as raised:
            runtime.check_model_egress(
                destination,
                Provenance.empty(),
                unknown_context_ids=("response:resp-missing",),
            )

        self.assertEqual(raised.exception.policy, "UntrackedModelContext")

    def test_report_never_contains_secret_content(self) -> None:
        secret_value = "FLOWGUARD_SECRET_VALUE_DO_NOT_EXPORT"
        runtime = FlowguardRuntime()

        with self.assertRaises(FlowguardBlocked):
            runtime.check_model_egress(
                ModelDestination("openai", "gpt-test", "external"),
                secret_provenance(),
            )

        self.assertNotIn(secret_value, runtime.report().to_json())


if __name__ == "__main__":
    unittest.main()
