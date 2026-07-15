from __future__ import annotations

from .decisions import Decision


class FlowguardBlocked(RuntimeError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.explanation)
        self.decision = decision
        self.policy = decision.policy
        self.explanation = decision.explanation

