from __future__ import annotations

import unittest
from pathlib import Path

from _bootstrap import SRC  # noqa: F401
from rule_cases import trigger_cases
from static.secrets import SecretDetectionEngine


class RulePositiveCasesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = SecretDetectionEngine()
        self.path = Path("workflow.yml")

    def test_each_rule_has_positive_case(self) -> None:
        for rule_cls, workflow in trigger_cases().items():
            with self.subTest(rule=rule_cls.__name__):
                findings = rule_cls().evaluate(workflow, self.path, self.engine)
                self.assertGreater(
                    len(findings),
                    0,
                    msg=f"Expected findings for {rule_cls.__name__}, got 0",
                )


if __name__ == "__main__":
    unittest.main()
