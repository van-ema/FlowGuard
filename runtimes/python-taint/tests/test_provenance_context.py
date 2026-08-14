from __future__ import annotations

import asyncio
import unittest

from flowguard import Provenance, ProvenanceContext, SourceRef, TrackedStr
from flowguard.tracked import provenance_of


def secret_provenance(name: str) -> Provenance:
    return Provenance.from_source("Secret", SourceRef.file(name))


class ProvenanceContextTests(unittest.TestCase):
    def test_tool_output_survives_serialized_model_input(self) -> None:
        context = ProvenanceContext()
        provenance = secret_provenance("/secrets/a")
        context.bind_tool_output("call-read", provenance)

        resolved = context.provenance_for_model_input(
            [
                {
                    "type": "function_call_output",
                    "call_id": "call-read",
                    "output": "plain serialized value",
                }
            ]
        )

        self.assertEqual(resolved.provenance, provenance)
        self.assertEqual(resolved.unknown_context_ids, ())

    def test_unknown_tool_output_is_reported(self) -> None:
        context = ProvenanceContext()

        resolved = context.provenance_for_model_input(
            {
                "type": "function_call_output",
                "call_id": "call-missing",
                "output": "value",
            }
        )

        self.assertEqual(
            resolved.unknown_context_ids,
            ("tool_call:call-missing",),
        )

    def test_generated_call_provenance_is_applied_to_structured_arguments(self) -> None:
        context = ProvenanceContext()
        provenance = secret_provenance("/secrets/a")
        context.bind_generated_tool_call("call-send", provenance)

        with context.activate_tool_call("call-send"):
            args, kwargs = context.prepare_tool_arguments(
                (),
                {"payload": {"body": ["plain serialized value"]}},
            )

        payload = kwargs["payload"]["body"][0]
        self.assertEqual(args, ())
        self.assertIsInstance(payload, TrackedStr)
        self.assertTrue(provenance_of(payload).has_label("Secret"))

    def test_scope_releases_run_bindings(self) -> None:
        context = ProvenanceContext()
        provenance = secret_provenance("/secrets/a")

        with context.scope():
            context.bind_generated_tool_call("call-send", provenance)
            self.assertEqual(
                context.provenance_for_tool_call("call-send"),
                provenance,
            )

        self.assertEqual(
            context.provenance_for_tool_call("call-send"),
            Provenance.empty(),
        )


class ProvenanceContextIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_tasks_do_not_mix_bindings(self) -> None:
        context = ProvenanceContext()

        async def run(call_id: str, source: str) -> Provenance:
            with context.scope():
                expected = secret_provenance(source)
                context.bind_tool_output(call_id, expected)
                await asyncio.sleep(0)
                resolved = context.provenance_for_model_input(
                    {
                        "type": "function_call_output",
                        "call_id": call_id,
                        "output": "serialized",
                    }
                )
                return resolved.provenance

        left, right = await asyncio.gather(
            run("call-a", "/secrets/a"),
            run("call-b", "/secrets/b"),
        )

        self.assertEqual(left.sources[0].name, "/secrets/a")
        self.assertEqual(right.sources[0].name, "/secrets/b")
        self.assertNotEqual(left, right)


if __name__ == "__main__":
    unittest.main()
