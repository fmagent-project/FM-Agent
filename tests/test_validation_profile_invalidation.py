from __future__ import annotations

import dataclasses
import hashlib
import unittest

from src.validation_core.contracts.base import ContractError
from src.validation_core.contracts.setup import (
    DependencyBinding,
    DependencyInvalidationManifest,
    DependencyKind,
    InvalidationAction,
)
from src.validation_core.setup.invalidation import (
    DependencyObservation,
    resolve_invalidation,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class InvalidationEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        review = InvalidationAction.REQUALIFY_REVIEW
        self.manifest = DependencyInvalidationManifest(
            manifest_id="profile.invalidation",
            manifest_version="1.0.0",
            candidate_sha256=_sha("candidate"),
            profile_graph_sha256=_sha("profile-graph"),
            dependencies=(
                DependencyBinding(
                    DependencyKind.SOURCE_SNAPSHOT,
                    "source",
                    _sha("source"),
                    InvalidationAction.PROFILE_GATE,
                ),
                DependencyBinding(
                    DependencyKind.PROFILE_GRAPH,
                    "profile.graph",
                    _sha("profile-graph"),
                    InvalidationAction.PROFILE_GATE,
                ),
                DependencyBinding(
                    DependencyKind.ORACLE,
                    "oracle.primary",
                    _sha("oracle"),
                    review,
                ),
                DependencyBinding(
                    DependencyKind.ADAPTER_CODE,
                    "adapter.code",
                    _sha("adapter-code"),
                    review,
                ),
                DependencyBinding(
                    DependencyKind.DEPENDENCY_LOCK,
                    "adapter.dependencies",
                    _sha("dependency-lock"),
                    review,
                ),
                DependencyBinding(
                    DependencyKind.TOOLCHAIN,
                    "toolchain",
                    _sha("toolchain"),
                    InvalidationAction.FULL_QUALIFICATION,
                ),
            ),
            unknown_change_action=InvalidationAction.FULL_QUALIFICATION,
            created_at="2026-08-17T00:00:00Z",
        )
        self.observations = tuple(
            DependencyObservation(item.kind, item.role, item.content_sha256)
            for item in self.manifest.dependencies
        )
        self.subject = _sha("semantic-subject")

    def evaluate(self, observations=None, *, current_subject=None, revoked=()):
        return resolve_invalidation(
            self.manifest,
            self.observations if observations is None else tuple(observations),
            revoked_sha256=frozenset(revoked),
            previous_semantic_subject_sha256=self.subject,
            current_semantic_subject_sha256=(
                self.subject if current_subject is None else current_subject
            ),
        )

    def replace(self, role: str, **changes):
        return tuple(
            dataclasses.replace(item, **changes) if item.role == role else item
            for item in self.observations
        )

    def test_unchanged_graph_reuses_only_the_exact_semantic_subject(self):
        decision = self.evaluate()
        self.assertIs(decision.action, InvalidationAction.REUSE_APPROVAL)
        self.assertTrue(decision.approval_reusable)
        self.assertFalse(decision.requires_new_profile_instance)
        changed_subject = self.evaluate(current_subject=_sha("new-subject"))
        self.assertIs(
            changed_subject.action,
            InvalidationAction.REQUALIFY_REVIEW_REAPPROVE,
        )
        self.assertFalse(changed_subject.approval_reusable)

    def test_source_change_requires_new_profile_but_can_reuse_exact_approval(self):
        decision = self.evaluate(
            self.replace("source", content_sha256=_sha("source-2"))
        )
        self.assertIs(decision.action, InvalidationAction.PROFILE_GATE)
        self.assertEqual(decision.changed_roles, ("source",))
        self.assertTrue(decision.approval_reusable)
        self.assertTrue(decision.requires_new_profile_instance)

    def test_semantic_change_reviews_and_subject_change_forces_reapproval(self):
        observations = self.replace(
            "adapter.code",
            content_sha256=_sha("adapter-code-2"),
        )
        reviewed = self.evaluate(observations)
        self.assertIs(reviewed.action, InvalidationAction.REQUALIFY_REVIEW)
        self.assertTrue(reviewed.approval_reusable)
        reapproved = self.evaluate(
            observations,
            current_subject=_sha("new-subject"),
        )
        self.assertIs(
            reapproved.action,
            InvalidationAction.REQUALIFY_REVIEW_REAPPROVE,
        )
        self.assertFalse(reapproved.approval_reusable)

    def test_strongest_action_wins_and_unknown_shapes_fail_closed(self):
        observations = self.replace(
            "source",
            content_sha256=_sha("source-2"),
        )
        observations = tuple(
            dataclasses.replace(item, content_sha256=_sha("adapter-code-2"))
            if item.role == "adapter.code"
            else item
            for item in observations
        )
        strongest = self.evaluate(observations)
        self.assertIs(strongest.action, InvalidationAction.REQUALIFY_REVIEW)
        self.assertTrue(strongest.requires_new_profile_instance)

        missing = tuple(
            item for item in self.observations if item.role != "toolchain"
        )
        self.assertIs(
            self.evaluate(missing).action,
            InvalidationAction.REQUALIFY_REVIEW,
        )
        wrong_kind = self.replace("toolchain", kind=DependencyKind.OS_IMAGE)
        self.assertIs(
            self.evaluate(wrong_kind).action,
            InvalidationAction.REQUALIFY_REVIEW,
        )
        extra = (
            *self.observations,
            DependencyObservation(
                DependencyKind.SOURCE_SNAPSHOT,
                "source.extra",
                _sha("extra-source"),
            ),
        )
        extra_decision = self.evaluate(extra)
        self.assertIs(
            extra_decision.action,
            InvalidationAction.REQUALIFY_REVIEW,
        )
        self.assertTrue(extra_decision.requires_new_profile_instance)

    def test_revoked_previous_or_current_dependency_is_rejected(self):
        with self.assertRaisesRegex(ContractError, "revoked"):
            self.evaluate(revoked=(_sha("oracle"),))
        observations = self.replace(
            "toolchain",
            content_sha256=_sha("toolchain-2"),
        )
        with self.assertRaisesRegex(ContractError, "revoked"):
            self.evaluate(observations, revoked=(_sha("toolchain-2"),))


if __name__ == "__main__":
    unittest.main()
