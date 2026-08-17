"""Deterministic dependency invalidation for frozen Project Profiles.

The previous, approved manifest owns every change action.  A newly observed
dependency may report only its role, kind, and digest; it cannot weaken the
approved invalidation policy attached to that role.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..contracts.base import ContractError, validate_identifier, validate_sha256
from ..contracts.setup import (
    DependencyInvalidationManifest,
    DependencyKind,
    InvalidationAction,
)


_ACTION_PRECEDENCE = {
    InvalidationAction.REUSE_APPROVAL: 0,
    InvalidationAction.PROFILE_GATE: 1,
    InvalidationAction.LIGHTWEIGHT_QUALIFICATION: 2,
    InvalidationAction.FULL_QUALIFICATION: 3,
    InvalidationAction.REQUALIFY_REVIEW: 4,
    InvalidationAction.REQUALIFY_REVIEW_REAPPROVE: 5,
}


def _unknown_shape_action(
    configured: InvalidationAction,
) -> InvalidationAction:
    """Unknown graph shapes always require a fresh independent review.

    The manifest may make that response stricter, but it cannot classify an
    added, removed, or retyped dependency as qualification-only.  Such a shape
    was never part of the reviewed dependency graph.
    """

    review = InvalidationAction.REQUALIFY_REVIEW
    return max((configured, review), key=_ACTION_PRECEDENCE.__getitem__)


@dataclass(frozen=True)
class DependencyObservation:
    """Authority-resolved current value, with no caller-chosen action."""

    kind: DependencyKind
    role: str
    content_sha256: str

    def __post_init__(self) -> None:
        if type(self.kind) is not DependencyKind:
            raise ContractError("kind must be a DependencyKind")
        validate_identifier(self.role, "role")
        validate_sha256(self.content_sha256, "content_sha256")


@dataclass(frozen=True)
class InvalidationDecision:
    action: InvalidationAction
    changed_roles: tuple[str, ...]
    approval_reusable: bool
    requires_new_profile_instance: bool

    def __post_init__(self) -> None:
        if type(self.action) is not InvalidationAction:
            raise ContractError("action must be an InvalidationAction")
        if type(self.changed_roles) not in (tuple, list):
            raise ContractError("changed_roles must be an ordered collection")
        roles = tuple(self.changed_roles)
        for role in roles:
            validate_identifier(role, "changed_roles")
        if len(roles) != len(set(roles)):
            raise ContractError("changed_roles must not contain duplicates")
        object.__setattr__(self, "changed_roles", tuple(sorted(roles)))
        if type(self.approval_reusable) is not bool:
            raise ContractError("approval_reusable must be a boolean")
        if type(self.requires_new_profile_instance) is not bool:
            raise ContractError("requires_new_profile_instance must be a boolean")
        if (
            self.action is InvalidationAction.REQUALIFY_REVIEW_REAPPROVE
            and self.approval_reusable
        ):
            raise ContractError("reapproval action cannot reuse approval")


class InvalidationEngine:
    """Resolve the strongest authority-owned action for dependency drift."""

    def evaluate(
        self,
        manifest: DependencyInvalidationManifest,
        current: tuple[DependencyObservation, ...],
        *,
        revoked_sha256: frozenset[str] = frozenset(),
        previous_semantic_subject_sha256: str,
        current_semantic_subject_sha256: str,
    ) -> InvalidationDecision:
        if type(manifest) is not DependencyInvalidationManifest:
            raise ContractError(
                "manifest must be a DependencyInvalidationManifest"
            )
        if type(current) not in (tuple, list):
            raise ContractError("current dependencies must be an ordered collection")
        observations = tuple(current)
        if any(type(item) is not DependencyObservation for item in observations):
            raise ContractError(
                "current dependencies must contain DependencyObservation values"
            )
        roles = tuple(item.role for item in observations)
        if len(roles) != len(set(roles)):
            raise ContractError("current dependency roles must be unique")
        if type(revoked_sha256) not in (frozenset, set, tuple, list):
            raise ContractError("revoked_sha256 must be a digest collection")
        revoked = frozenset(
            validate_sha256(value, "revoked_sha256") for value in revoked_sha256
        )
        previous = validate_sha256(
            previous_semantic_subject_sha256,
            "previous_semantic_subject_sha256",
        )
        current_subject = validate_sha256(
            current_semantic_subject_sha256,
            "current_semantic_subject_sha256",
        )
        semantic_subject_equal = previous == current_subject
        governed_hashes = {
            manifest.content_sha256,
            manifest.candidate_sha256,
            manifest.profile_graph_sha256,
            *(item.content_sha256 for item in manifest.dependencies),
            *(item.content_sha256 for item in observations),
        }
        if governed_hashes.intersection(revoked):
            raise ContractError("profile dependency graph is revoked")

        approved = {item.role: item for item in manifest.dependencies}
        observed = {item.role: item for item in observations}
        changed: set[str] = set()
        actions: list[InvalidationAction] = []

        for role in sorted(set(approved).union(observed)):
            before = approved.get(role)
            after = observed.get(role)
            if before is None or after is None:
                changed.add(role)
                actions.append(_unknown_shape_action(manifest.unknown_change_action))
                continue
            if before.kind is not after.kind:
                changed.add(role)
                actions.append(_unknown_shape_action(manifest.unknown_change_action))
                continue
            if before.content_sha256 != after.content_sha256:
                changed.add(role)
                actions.append(before.on_change)

        if not actions:
            action = InvalidationAction.REUSE_APPROVAL
        else:
            action = max(actions, key=_ACTION_PRECEDENCE.__getitem__)
        if semantic_subject_equal is False:
            action = InvalidationAction.REQUALIFY_REVIEW_REAPPROVE
        instance_kinds = {
            DependencyKind.SOURCE_SNAPSHOT,
            DependencyKind.PROFILE_GRAPH,
        }
        source_changed = any(
            (
                approved.get(role) is not None
                and approved[role].kind in instance_kinds
            )
            or (
                observed.get(role) is not None
                and observed[role].kind in instance_kinds
            )
            for role in changed
        )
        approval_reusable = (
            semantic_subject_equal
            and action is not InvalidationAction.REQUALIFY_REVIEW_REAPPROVE
        )
        return InvalidationDecision(
            action=action,
            changed_roles=tuple(changed),
            approval_reusable=approval_reusable,
            requires_new_profile_instance=source_changed,
        )


def resolve_invalidation(
    manifest: DependencyInvalidationManifest,
    current: tuple[DependencyObservation, ...],
    *,
    revoked_sha256: frozenset[str] = frozenset(),
    previous_semantic_subject_sha256: str,
    current_semantic_subject_sha256: str,
) -> InvalidationDecision:
    """Functional wrapper for callers that do not retain an engine."""

    return InvalidationEngine().evaluate(
        manifest,
        current,
        revoked_sha256=revoked_sha256,
        previous_semantic_subject_sha256=previous_semantic_subject_sha256,
        current_semantic_subject_sha256=current_semantic_subject_sha256,
    )


__all__ = [
    "DependencyObservation",
    "InvalidationDecision",
    "InvalidationEngine",
    "resolve_invalidation",
]
