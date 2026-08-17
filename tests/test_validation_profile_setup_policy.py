import hashlib
import unittest

from src.validation_core.contracts.base import ContractError
from src.validation_core.setup.policy import (
    SetupCapability,
    SetupCredentialPolicy,
    SetupNamespace,
    SetupNetworkPolicy,
    SetupRole,
    SetupRolePolicy,
    build_setup_role_policy,
)


def _digest(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


class ProfileSetupRolePolicyTests(unittest.TestCase):
    def _policy(self, role):
        return build_setup_role_policy(
            role,
            setup_session_id="setup-session-1",
            subject_sha256=_digest(f"subject:{role.value}"),
            governance_policy_sha256=_digest("governance"),
        )

    def test_every_role_is_closed_canonical_and_strictly_round_trips(self):
        hashes = set()
        for role in SetupRole:
            with self.subTest(role=role.value):
                policy = self._policy(role)
                self.assertEqual(
                    SetupRolePolicy.from_json(policy.to_json()),
                    policy,
                )
                self.assertEqual(
                    tuple(value.value for value in policy.capabilities),
                    tuple(sorted(value.value for value in policy.capabilities)),
                )
                self.assertEqual(
                    tuple(value.value for value in policy.namespaces),
                    tuple(sorted(value.value for value in policy.namespaces)),
                )
                hashes.add(policy.content_sha256)
        self.assertEqual(len(hashes), len(SetupRole))

    def test_hidden_fixtures_are_visible_only_to_qualification_worker(self):
        for role in SetupRole:
            policy = self._policy(role)
            expected = role is SetupRole.QUALIFICATION_WORKER
            self.assertEqual(
                SetupCapability.HIDDEN_FIXTURE_ACCESS in policy.capabilities,
                expected,
            )
            self.assertEqual(
                SetupNamespace.HIDDEN_QUALIFICATION_READ_ONLY
                in policy.namespaces,
                expected,
            )
        reviewer = self._policy(SetupRole.REVIEWER)
        self.assertEqual(
            reviewer.namespaces,
            (
                SetupNamespace.REVIEW_BUNDLE_READ_ONLY,
                SetupNamespace.REVIEW_RECORD_WRITE,
            ),
        )
        setup_agent = self._policy(SetupRole.SETUP_AGENT)
        worker = self._policy(SetupRole.QUALIFICATION_WORKER)
        self.assertIn(
            SetupNamespace.CANDIDATE_STAGING_READ_WRITE,
            setup_agent.namespaces,
        )
        self.assertNotIn(
            SetupNamespace.CANDIDATE_STAGING_READ_WRITE,
            worker.namespaces,
        )
        self.assertIn(
            SetupNamespace.CANDIDATE_STAGING_READ_ONLY,
            worker.namespaces,
        )

    def test_profile_gate_has_no_model_network_or_credentials(self):
        policy = self._policy(SetupRole.PROFILE_GATE)
        self.assertIs(policy.network_policy, SetupNetworkPolicy.NONE)
        self.assertIs(policy.credential_policy, SetupCredentialPolicy.NONE)
        self.assertNotIn(
            SetupCapability.MASKED_MODEL_PROVIDER,
            policy.capabilities,
        )
        self.assertNotIn(
            SetupCapability.REVIEW_PROVIDER,
            policy.capabilities,
        )

    def test_roles_cannot_add_or_remove_authority(self):
        policy = self._policy(SetupRole.REVIEWER)
        base = dict(policy.__dict__)
        for mutation in (
            {**base, "capabilities": ()},
            {
                **base,
                "capabilities": (
                    *policy.capabilities,
                    SetupCapability.PROFILE_REGISTRY_WRITE,
                ),
            },
            {
                **base,
                "namespaces": (
                    *policy.namespaces,
                    SetupNamespace.HIDDEN_QUALIFICATION_READ_ONLY,
                ),
            },
            {
                **base,
                "network_policy": (
                    SetupNetworkPolicy.ALLOWLIST_DISCOVERY_BROKER
                ),
            },
            {
                **base,
                "credential_policy": SetupCredentialPolicy.SETUP_SCOPED,
            },
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(ContractError):
                    SetupRolePolicy(**mutation)

    def test_parser_rejects_unknown_fields_versions_and_duplicate_keys(self):
        policy = self._policy(SetupRole.SETUP_AGENT)
        document = policy.to_document()
        with self.assertRaises(ContractError):
            SetupRolePolicy.from_document({**document, "host_path": "/tmp/leak"})
        with self.assertRaises(ContractError):
            SetupRolePolicy.from_document({**document, "schema_version": True})
        with self.assertRaises(ContractError):
            SetupRolePolicy.from_json(
                b'{"contract_kind":"profile_setup_role_policy",'
                b'"contract_kind":"profile_setup_role_policy"}'
            )


if __name__ == "__main__":
    unittest.main()
