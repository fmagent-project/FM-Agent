# Authn Plugin

The authn plugin checks whether security-sensitive operations are preceded by a
genuine authentication decision and whether authentication state is established,
used, and retired safely. The LLM extracts facts; deterministic Python code makes
the verdict.

## Core Model

`src/authn_reasoner.py` treats each protected operation as a guarded Hoare-style
obligation. A genuine authentication event discharges an operation only when it
dominates every path to that operation. Events can name `protects_op_ids`; this
prevents authentication on one branch from discharging an unrelated operation.
Caller-established genuine authentication can discharge ordinary missing-auth
obligations through the plugin's top-down context pass.

The base findings are:

- `MISSING_AUTHENTICATION`, `ASSERTED_IDENTITY`, and `WEAK_AUTHENTICATION`:
  `CWE-287`.
- `SESSION_FIXATION`: `CWE-384`.
- `INSUFFICIENT_SESSION_EXPIRATION`: `CWE-613`.

Malformed facts and unknown enum values produce `ERROR`; they never become
`SAFE`.

## Boundary Contracts

`src/authn_validation.py` evaluates three contracts where the presence of an
authentication-looking operation is not enough.

### Recovery Identity

`recovery_events` distinguish account selection from credential delivery.
Account selection is accepted only when application code uses exact equality or
canonical Unicode equivalence on the requested and persisted identities. A
database's case-insensitive collation alone is not sufficient. Credential
delivery is accepted only when the recipient comes from the selected account's
persisted identity, rather than directly from request input. For Python recovery
flows, deterministic provenance follows identity aliases and message context,
and verifies that credential generation and persisted delivery refer to the same
selected account. This source proof is reapplied when cached model facts are
checked, so omitted or contradictory model labels do not change replay verdicts.

Each event must be high-confidence, fail-closed, dominate all protected paths,
and list the exact `protects_op_ids`. Otherwise the result is
`WEAK_PASSWORD_RECOVERY` / `CWE-640`.

### Credential Contract

`credential_events` model `provision`, `load`, and `verify` stages for shared
secrets and similar credentials. A stage discharges its named operations only
when representations agree, normal operation works, errors cannot become usable
credentials, and failure values are rejected before equality. Invalid, unknown,
non-dominating, or fail-open stages produce `FAIL_OPEN_AUTHENTICATION` /
`CWE-287`.

For Python file-backed authenticators, source validation can prove provisioning
without a model event when fresh secure-random material reaches a writer, the
same static path has a loader, and that loader's authenticator reaches a
comparison. Representation compatibility, loader failure sentinels or dynamic
defaults, and direct same-file ownership/permission operations are then derived
from AST provenance. Reusable provision defaults and accepted loader failures
remain fail-open.

The prompt may include functions that share a security-relevant contract symbol
such as a secret-file constant. This supplies cross-function representation and
failure context without relying on repository or function-name allowlists.

### Session-Key Retirement

`session_key_events` model session flush/logout. Clearing stored state is not
enough if the key is replaced by a shared or reusable fixed value. A retirement
is safe only when storage is cleared and the replacement is absent or freshly
random, with high-confidence all-path dominance. Other states produce
`SESSION_FIXATION` / `CWE-384`.

A bearer-token return is not automatically a server-session establishment.
Session ID regeneration applies when a server session is established or changes
privilege, avoiding false fixation findings for unrelated token issuance.

## Result Identity

The extraction pipeline stores functions under paths such as
`path/module-py/function.py`. Authn result rendering maps these back to the source
path (`path/module.py`) while retaining the deduplicated function token. This
lets pair evaluation bind findings to canonical source loci and keeps all other
results explicitly out of locus.
