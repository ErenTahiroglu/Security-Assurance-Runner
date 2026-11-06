"""Synthetic specification: future arming must pin the reviewed tree."""
import unittest


def matches_reviewed_arming(actual_tree, reviewed_tree, changed_paths):
    # A tree identity must be independently reviewed; a subject is not authority.
    return actual_tree == reviewed_tree and changed_paths == frozenset({
        ".github/workflows/gov02-pilot-01-scan.yml"
    })


class ArmingPlanTests(unittest.TestCase):
    def test_unrelated_arm_source_change_cannot_be_approved(self):
        workflow = ".github/workflows/gov02-pilot-01-scan.yml"
        self.assertTrue(matches_reviewed_arming("reviewed-tree", "reviewed-tree", frozenset({workflow})))
        self.assertFalse(matches_reviewed_arming("different-tree", "reviewed-tree", frozenset({workflow})))
        self.assertFalse(matches_reviewed_arming("different-tree", "reviewed-tree", frozenset({workflow, "scripts/gov02/pilot01/scan_once.sh"})))


if __name__ == "__main__":
    unittest.main()
