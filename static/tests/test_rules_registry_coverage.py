from __future__ import annotations

import unittest

from _bootstrap import SRC  # noqa: F401
from rule_cases import safe_cases, trigger_cases
from static.rules.registry import default_workflow_rules


class RuleRegistryCoverageTests(unittest.TestCase):
    def test_trigger_cases_cover_all_registered_rules(self) -> None:
        discovered = {type(rule) for rule in default_workflow_rules()}
        covered = set(trigger_cases().keys())
        self.assertSetEqual(
            covered,
            discovered,
            msg=(
                "Rule coverage mismatch for positive cases. "
                f"Missing in tests: {[c.__name__ for c in (discovered - covered)]}; "
                f"Extra in tests: {[c.__name__ for c in (covered - discovered)]}"
            ),
        )

    def test_safe_cases_cover_all_registered_rules(self) -> None:
        discovered = {type(rule) for rule in default_workflow_rules()}
        covered = set(safe_cases().keys())
        self.assertSetEqual(
            covered,
            discovered,
            msg=(
                "Rule coverage mismatch for negative cases. "
                f"Missing in tests: {[c.__name__ for c in (discovered - covered)]}; "
                f"Extra in tests: {[c.__name__ for c in (covered - discovered)]}"
            ),
        )


if __name__ == "__main__":
    unittest.main()
