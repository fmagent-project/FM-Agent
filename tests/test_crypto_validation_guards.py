import json
import tempfile
import unittest
from pathlib import Path

from src.crypto_reasoner import SAFE, VULNERABLE, WEAK, classify
from src.crypto_validation import validate_and_enrich
from src.plugins.base import (
    AbstractionRequest,
    DriverContext,
    FunctionId,
    FunctionUnit,
    FactEnvelope,
    ProgramIndex,
)
from src.plugins.crypto import CryptoPlugin


def _facts(operation, **metadata):
    return {
        "schema_version": "crypto_v1",
        "crypto_operations": [operation],
        "verify_events": [],
        "returns": [],
        "red_flags": [],
        **metadata,
    }


def _random(source):
    return {
        "id": "op_1",
        "kind": "random",
        "purpose": "token_generation",
        "api": "choice",
        "randomness": {"source": source},
        "evidence": "return choice(range(100000, 999999))",
    }


def _jwt(kind="sign", provenance="unknown", algorithm="HS256"):
    return {
        "id": "op_1",
        "kind": kind,
        "purpose": "security",
        "api": "jwt.encode" if kind == "sign" else "jwt.decode",
        "algorithm": algorithm,
        "key": {"provenance": provenance, "source": {"kind": "unknown"}},
        "jwt": {
            "algorithms_allowed": [algorithm],
            "allows_none": False,
            "signature_verification_disabled": False,
        },
        "evidence": "jwt operation",
    }


def _request(root, source_rel, function_name, extracted_source):
    source = root / source_rel
    extracted = root / "fm_agent_crypto" / "extracted_functions" / (
        source_rel.rsplit(".", 1)[0] + "-" + source_rel.rsplit(".", 1)[1]
    ) / f"{function_name}.{source_rel.rsplit('.', 1)[1]}"
    extracted.parent.mkdir(parents=True, exist_ok=True)
    extracted.write_text(extracted_source)
    fid = FunctionId(
        str(extracted.relative_to(root / "fm_agent_crypto" / "extracted_functions")),
        function_name,
        function_name,
        "python",
    )
    unit = FunctionUnit(fid, extracted_source, extracted_source.splitlines()[0], abs_path=str(extracted))
    program = ProgramIndex({fid: unit}, {fid: []}, {fid: []}, [fid])
    return AbstractionRequest(unit, DriverContext(program, unit, True))


class CryptoReasonerCharacterizationTests(unittest.TestCase):
    def test_predictable_randomness_is_a_cwe338_positive(self):
        result = classify(_facts(_random("insecure_prng")))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-338", result["findings"][0]["cwe"])

    def test_csprng_token_generation_is_negative(self):
        self.assertEqual(SAFE, classify(_facts(_random("csprng")))["verdict"])

    def test_modern_signing_api_does_not_excuse_a_hardcoded_key(self):
        result = classify(_facts(_jwt(algorithm="Ed25519", provenance="hardcoded_literal")))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-321/CWE-798", result["findings"][0]["cwe"])

    def test_jwt_verification_checks_key_provenance_too(self):
        result = classify(_facts(_jwt(kind="jwt_decode", provenance="hardcoded_literal")))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertIn("hardcoded_key_or_secret", {finding["kind"] for finding in result["findings"]})

    def test_explicit_md5_is_weak_when_security_purpose_is_not_disproved(self):
        operation = {
            "id": "op_1",
            "kind": "hash",
            "purpose": "unknown",
            "api": "hashlib.md5",
            "algorithm": "MD5",
            "evidence": "hashlib.md5(data)",
        }

        result = classify(_facts(operation))

        self.assertEqual(WEAK, result["verdict"])
        self.assertEqual("CWE-327", result["findings"][0]["cwe"])

    def test_official_cwe_conflict_is_metadata_not_a_detection_override(self):
        operation = {
            "id": "op_1",
            "kind": "hash",
            "purpose": "unknown",
            "algorithm": "MD5",
            "evidence": "hashlib.md5(data)",
        }
        metadata = {
            "evaluation_metadata": {
                "official_cwe": "CWE-326",
                "semantic_cwe": "CWE-327",
                "cwe_conflict": True,
            }
        }

        facts = _facts(operation, **metadata)
        result = classify(facts)

        self.assertEqual("CWE-327", result["findings"][0]["cwe"])
        self.assertEqual(metadata["evaluation_metadata"], facts["evaluation_metadata"])


class CryptoSourceValidationTests(unittest.TestCase):
    def test_source_overrides_a_false_csprng_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/tokens.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = "def make_code():\n    return random.choice(range(100000, 999999))\n"
            source.write_text("import random\n\n" + body)
            request = _request(root, source_rel, "make_code", body)

            enriched = validate_and_enrich(_facts(_random("csprng")), request.function)

        operation = enriched["crypto_operations"][0]
        self.assertEqual("insecure_prng", operation["randomness"]["source"])
        self.assertEqual(VULNERABLE, classify(enriched)["verdict"])

    def test_source_overrides_a_false_insecure_claim_for_csprng(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/tokens.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = "def make_code():\n    return secrets.choice(range(100000, 999999))\n"
            source.write_text("import secrets\n\n" + body)
            request = _request(root, source_rel, "make_code", body)

            enriched = validate_and_enrich(_facts(_random("insecure_prng")), request.function)

        self.assertEqual("csprng", enriched["crypto_operations"][0]["randomness"]["source"])
        self.assertEqual(SAFE, classify(enriched)["verdict"])

    def test_multiple_random_calls_are_matched_to_distinct_operations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/tokens.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = (
                "def make_tokens():\n"
                "    weak = random.choice(range(10))\n"
                "    strong = secrets.choice(range(10))\n"
                "    return weak, strong\n"
            )
            source.write_text("import random\nimport secrets\n\n" + body)
            request = _request(root, source_rel, "make_tokens", body)
            weak = _random("csprng")
            weak.update(id="op_weak", api="random.choice", evidence="random.choice(range(10))")
            strong = _random("insecure_prng")
            strong.update(id="op_strong", api="secrets.choice", evidence="secrets.choice(range(10))")

            enriched = validate_and_enrich(_facts(weak), request.function)
            enriched["crypto_operations"].append(strong)
            enriched = validate_and_enrich(enriched, request.function)

        sources = {
            operation["api"]: operation["randomness"]["source"]
            for operation in enriched["crypto_operations"]
        }
        self.assertEqual(
            {"random.choice": "insecure_prng", "secrets.choice": "csprng"},
            sources,
        )
        self.assertEqual(VULNERABLE, classify(enriched)["verdict"])

    def test_corrected_csprng_fact_discards_contradictory_red_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/tokens.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = "def make_code():\n    return secrets.choice(range(100000, 999999))\n"
            source.write_text("import secrets\n\n" + body)
            request = _request(root, source_rel, "make_code", body)
            facts = _facts(_random("insecure_prng"))
            facts["red_flags"] = [{
                "kind": "insecure_random", "operation_id": "op_1",
                "evidence": "secrets.choice(range(100000, 999999))",
            }]

            enriched = validate_and_enrich(facts, request.function)

        self.assertEqual([], enriched["red_flags"])
        self.assertEqual(SAFE, classify(enriched)["verdict"])

    def test_imported_literal_signing_key_is_resolved_from_project_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            core = root / "app/core/__init__.py"
            core.parent.mkdir(parents=True)
            core.write_text('WEBUI_SK = "public-repository-secret"\n')
            source_rel = "app/auth.py"
            source = root / source_rel
            source.parent.mkdir(parents=True, exist_ok=True)
            body = "def issue(payload):\n    return jwt.encode(payload, WEBUI_SK, algorithm=\"HS256\")\n"
            source.write_text("from app.core import WEBUI_SK\nimport jwt\n\n" + body)
            request = _request(root, source_rel, "issue", body)

            enriched = validate_and_enrich(_facts(_jwt()), request.function)

        key = enriched["crypto_operations"][0]["key"]
        self.assertEqual("hardcoded_literal", key["provenance"])
        self.assertEqual("project_source", key["source"]["visibility"])
        self.assertEqual(VULNERABLE, classify(enriched)["verdict"])

    def test_indented_method_resolves_imported_literal_signing_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            core = root / "app/core/__init__.py"
            core.parent.mkdir(parents=True)
            core.write_text('WEBUI_SK = "public-repository-secret"\n')
            source_rel = "app/auth.py"
            source = root / source_rel
            source.parent.mkdir(parents=True, exist_ok=True)
            method = "    def issue(self, payload):\n        return jwt.encode(payload, WEBUI_SK, algorithm=\"HS256\")\n"
            source.write_text("from app.core import WEBUI_SK\nimport jwt\n\nclass Auth:\n" + method)
            request = _request(root, source_rel, "issue", method)

            enriched = validate_and_enrich(_facts(_jwt()), request.function)

        self.assertEqual("hardcoded_literal", enriched["crypto_operations"][0]["key"]["provenance"])
        self.assertEqual(VULNERABLE, classify(enriched)["verdict"])

    def test_config_backed_signing_key_remains_nonliteral(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/auth.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = (
                "def issue(config, payload):\n"
                "    key = config[\"dashboard\"].get(\"jwt_secret\")\n"
                "    return jwt.encode(payload, key, algorithm=\"HS256\")\n"
            )
            source.write_text("import jwt\n\n" + body)
            request = _request(root, source_rel, "issue", body)

            enriched = validate_and_enrich(_facts(_jwt(provenance="hardcoded_literal")), request.function)

        self.assertEqual("from_config_or_env", enriched["crypto_operations"][0]["key"]["provenance"])
        self.assertEqual(SAFE, classify(enriched)["verdict"])

    def test_sibling_assignment_resolves_fixed_jwt_secret_to_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/auth.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            method = "    def verify(self, token):\n        return jwt.decode(token, self._jwt_secret, algorithms=[\"HS256\"])\n"
            source.write_text(
                "import jwt\n\nclass Auth:\n"
                "    def init_secret(self):\n"
                "        self._jwt_secret = self.config[\"dashboard\"][\"jwt_secret\"]\n\n"
                + method
            )
            request = _request(root, source_rel, "verify", method)

            enriched = validate_and_enrich(_facts(_jwt(kind="jwt_decode")), request.function)

        self.assertEqual("from_config_or_env", enriched["crypto_operations"][0]["key"]["provenance"])
        self.assertEqual(SAFE, classify(enriched)["verdict"])

    def test_environment_subscript_is_runtime_key_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/auth.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = (
                "def issue(payload):\n"
                "    key = os.environ[\"JWT_SECRET\"]\n"
                "    return jwt.encode(payload, key, algorithm=\"HS256\")\n"
            )
            source.write_text("import os\nimport jwt\n\n" + body)
            request = _request(root, source_rel, "issue", body)

            enriched = validate_and_enrich(_facts(_jwt()), request.function)

        self.assertEqual(
            "from_config_or_env",
            enriched["crypto_operations"][0]["key"]["provenance"],
        )
        self.assertEqual(SAFE, classify(enriched)["verdict"])

    def test_csprng_output_encoding_preserves_key_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/auth.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = (
                "def issue(payload):\n"
                "    key = os.urandom(32).hex()\n"
                "    return jwt.encode(payload, key, algorithm=\"HS256\")\n"
            )
            source.write_text("import os\nimport jwt\n\n" + body)
            request = _request(root, source_rel, "issue", body)

            enriched = validate_and_enrich(_facts(_jwt()), request.function)

        self.assertEqual(
            "from_csprng",
            enriched["crypto_operations"][0]["key"]["provenance"],
        )
        self.assertEqual(SAFE, classify(enriched)["verdict"])

    def test_internal_callee_proxy_operation_is_not_a_local_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/auth.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = "def login(user):\n    return generate_jwt(user)\n"
            source.write_text(body)
            request = _request(root, source_rel, "login", body)
            facts = _facts(_jwt())
            facts["crypto_operations"][0]["api"] = "generate_jwt"
            facts["calls"] = [{"call_id": "C1", "callee": "generate_jwt"}]

            enriched = validate_and_enrich(facts, request.function)

        self.assertEqual([], enriched["crypto_operations"])
        self.assertEqual(SAFE, classify(enriched)["verdict"])

    def test_same_kind_internal_callee_proxy_is_not_a_second_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/hashing.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = (
                "def digest(data):\n"
                "    value = hashlib.md5(data).digest()\n"
                "    return decorate(value)\n"
            )
            source.write_text("import hashlib\n\n" + body)
            request = _request(root, source_rel, "digest", body)
            direct = {
                "id": "op_1", "kind": "hash", "purpose": "unknown",
                "api": "hashlib.md5", "algorithm": "MD5",
                "evidence": "hashlib.md5(data)",
            }
            proxy = {
                "id": "op_2", "kind": "hash", "purpose": "password_storage",
                "api": "decorate", "algorithm": "unknown",
                "evidence": "decorate(value)",
            }
            facts = _facts(direct)
            facts["crypto_operations"].append(proxy)
            facts["calls"] = [{"call_id": "C1", "callee": "decorate"}]

            enriched = validate_and_enrich(facts, request.function)

        self.assertEqual(["hashlib.md5"], [op["api"] for op in enriched["crypto_operations"]])
        self.assertEqual(WEAK, classify(enriched)["verdict"])

    def test_md5_strength_comes_from_the_call_not_the_function_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/hashing.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = "def digest(data):\n    return hashlib.md5(data).digest()\n"
            source.write_text("import hashlib\n\n" + body)
            request = _request(root, source_rel, "digest", body)

            enriched = validate_and_enrich(_facts({
                "id": "op_1",
                "kind": "hash",
                "purpose": "unknown",
                "api": "hashlib.sha256",
                "algorithm": "SHA256",
                "evidence": "hashlib.md5(data)",
            }), request.function)

        self.assertEqual("MD5", enriched["crypto_operations"][0]["algorithm"])
        self.assertEqual(WEAK, classify(enriched)["verdict"])

    def test_source_rejects_an_unsupported_nonsecurity_checksum_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/hashing.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = "def transform(data):\n    return hashlib.md5(data).digest()\n"
            source.write_text("import hashlib\n\n" + body)
            request = _request(root, source_rel, "transform", body)
            operation = {
                "id": "op_1",
                "kind": "hash",
                "purpose": "checksum_nonsecurity",
                "api": "hashlib.md5",
                "algorithm": "MD5",
                "evidence": "hashlib.md5(data)",
            }

            enriched = validate_and_enrich(_facts(operation), request.function)

        self.assertEqual("unknown", enriched["crypto_operations"][0]["purpose"])
        self.assertEqual(WEAK, classify(enriched)["verdict"])

    def test_absent_weak_api_discards_a_stale_source_decidable_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/hashing.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = "def encode(data):\n    return data.hex()\n"
            source.write_text(body)
            request = _request(root, source_rel, "encode", body)
            stale = _facts({
                "id": "op_1",
                "kind": "hash",
                "purpose": "security",
                "api": "hashlib.md5",
                "algorithm": "MD5",
                "evidence": "hashlib.md5(data)",
            })

            enriched = validate_and_enrich(stale, request.function)

        self.assertEqual([], enriched["crypto_operations"])
        self.assertEqual(SAFE, classify(enriched)["verdict"])

    def test_malformed_fact_collections_fail_closed(self):
        malformed = _facts(_random("csprng"))
        malformed["verify_events"] = {"status": "checked_and_dominates_use"}

        self.assertEqual("ERROR", classify(malformed)["verdict"])

    def test_irrelevant_key_metadata_does_not_error_a_hash_operation(self):
        operation = {
            "id": "op_1",
            "kind": "hash",
            "purpose": "checksum_nonsecurity",
            "api": "hashlib.sha256",
            "algorithm": "SHA256",
            "key": {"provenance": "not_applicable"},
            "evidence": "hashlib.sha256(data)",
        }

        self.assertEqual(SAFE, classify(_facts(operation))["verdict"])

    def test_validation_does_not_mutate_dirty_llm_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_rel = "app/tokens.py"
            source = root / source_rel
            source.parent.mkdir(parents=True)
            body = "def make_code():\n    return random.choice(range(10))\n"
            source.write_text("import random\n\n" + body)
            request = _request(root, source_rel, "make_code", body)
            facts = _facts(_random("csprng"))
            original = json.loads(json.dumps(facts))

            enriched = validate_and_enrich(facts, request.function)

        self.assertEqual(original, facts)
        self.assertNotEqual(facts, enriched)


class CryptoPluginValidationTests(unittest.TestCase):
    def test_parser_rejects_non_object_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            source.write_text("def f():\n    return 1\n")
            request = _request(root, "app.py", "f", "def f():\n    return 1\n")

            parsed = CryptoPlugin().parse_abstraction_response(
                request, "[CRYPTO_JSON][][/CRYPTO_JSON]"
            )

        self.assertIsNone(parsed)

    def test_result_uses_original_source_identity_for_stock_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            source.write_text("def f():\n    return 1\n")
            request = _request(root, "app.py", "f", "def f():\n    return 1\n")
            plugin = CryptoPlugin()
            raw = "[CRYPTO_JSON]" + json.dumps(_facts({
                "id": "op_1", "kind": "hash", "purpose": "checksum_nonsecurity",
                "algorithm": "SHA256", "evidence": "hash(data)",
            })) + "[/CRYPTO_JSON]"
            facts = plugin.parse_abstraction_response(request, raw)
            verdict = plugin.check(facts, request.context)

            result = plugin.render_result(request.function, facts, verdict, request.context)

        self.assertEqual("app.py", result["rel"])
        self.assertEqual("f", result["function"])

    def test_check_revalidates_stale_cached_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tokens.py"
            body = "def make_code():\n    return secrets.choice(range(100000, 999999))\n"
            source.write_text("import secrets\n\n" + body)
            request = _request(root, "tokens.py", "make_code", body)
            stale = _facts(_random("insecure_prng"))
            facts = FactEnvelope("crypto", "crypto_v1", request.function.id, "ok", stale)

            verdict = CryptoPlugin().check(facts, request.context)

        self.assertEqual(SAFE, verdict.verdict)
        self.assertEqual("csprng", facts.payload["crypto_operations"][0]["randomness"]["source"])

    def test_llm_error_uses_complete_source_semantics_for_known_crypto(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "tokens.py"
            body = "def generate_verification_code():\n    return random.choice(range(100000, 999999))\n"
            source.write_text("import random\n\n" + body)
            request = _request(root, "tokens.py", "generate_verification_code", body)
            facts = FactEnvelope("crypto", "crypto_v1", request.function.id, "error", None)

            verdict = CryptoPlugin().check(facts, request.context)

        self.assertEqual(VULNERABLE, verdict.verdict)
        self.assertEqual("partial", facts.status)

    def test_llm_error_without_complete_source_semantics_remains_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            body = "def wrapper(value):\n    return custom_crypto(value)\n"
            source.write_text(body)
            request = _request(root, "app.py", "wrapper", body)
            facts = FactEnvelope("crypto", "crypto_v1", request.function.id, "error", None)

            verdict = CryptoPlugin().check(facts, request.context)

        self.assertEqual("ERROR", verdict.verdict)
        self.assertEqual("error", verdict.status)


if __name__ == "__main__":
    unittest.main()
