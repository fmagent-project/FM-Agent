# Resource Exhaustion Plugin

The resource plugin models denial-of-service defects as a magnitude reaching a
costly operation without a hard bound. The LLM extracts facts; the deterministic
checker in `src/resource_reasoner.py` decides the verdict. Candidate bounds are
accepted only by `src/resource_validation.py`.

## Cost Model

The signature distinguishes physical and logical resource use:

- `allocation`, `collection_build`, and `unbounded_read` cover host memory and I/O.
- `expensive_call` covers request-sized parsing, hashing, encoding, database/token,
  email, or external work.
- `regex_compile` covers repeated compilation of attacker-controlled ACL/glob/regex
  rules. A stable cached evaluator with precompiled regexes has no per-request
  `regex_compile` operation.
- `logical_allocation` covers source-controlled compiler/type/storage extents and
  unchecked or precision-losing storage/offset arithmetic, even when no host buffer
  is immediately allocated.
- `regex_match`, `decompression`, `recursion`, and `loop` retain their narrower
  denial-of-service meanings.

The matching magnitude kinds include request/input size, element count, request
frequency, and `logical_size`. A concrete in-function source is attacker-controlled;
an unresolved parameter remains polymorphic until caller composition.

Model facts are accepted only when the reported operation exists in source and the
magnitude is supported by the exact argument or a simple source assignment. This
rejects invented aliases while preserving assignments such as
`clientSecret = args['client_secret']`. Non-amplifying scalar conversions are not
resource sinks. Repeated calls to one callee are composed against their matching
call-site occurrence rather than all reusing the first argument list.

## Hard Bounds

A new-format bound discharges only the exact operation when all of these hold:

- `confidence` is `high` and `dominates` is `true`.
- `placement` is `before`.
- `enforcement` is `reject`, `cap`, or `truncate`.
- `limit_origin` is `constant`, `trusted_config`, `trusted_system`, or `type_limit`.
- `protects_op_ids` contains the costly operation's exact id.
- `bound_kind` is allowed to cap the operation's magnitude kind, and `caps`
  explicitly contains that kind.

Warnings and logs are not enforcement. Checks after the costly operation are
post-hoc. An attacker-selected or unknown threshold is nominal, not a bound. Legacy
facts used `dominates=true` to mean a hard pre-operation check; they remain readable,
but explicit new metadata is validated fail-closed.

## CVE Characterization

### CVE-2021-29433 / CWE-400

The vulnerable Sydent paths pass unbounded request email/client-secret strings into
validation and downstream email/token work. The fix rejects overlong values before
those operations. The model uses `input_length -> expensive_call`; only the hard,
trusted, pre-operation length checks can produce `BOUNDED`.

### CVE-2023-45129 / CWE-770

The vulnerable Synapse ACL path iterates attacker-controlled allow/deny entries and
calls `glob_to_regex` during repeated ACL checks. This is
`element_count -> regex_compile`. The fix retrieves a cached evaluator whose regexes
were compiled once when ACL state changed. The request-facing lookup/match is not
misrepresented as a count bound or as repeated compilation.

### CVE-2023-30837 / CWE-789

Vyper source declarations control logical array and storage extents. Floating-point
rounding or unchecked slot addition is modeled as
`logical_size -> logical_allocation`. A warning for a large sequence length is not a
bound. A checked addition that rejects before assigning or reserving a slot is an
`arithmetic_limit` with hard `type_limit` provenance.

## Todo 16 Evidence

- The former v7 result remains historical evidence for the pre-fingerprint
  `securebench-pairs.v3` runner. It reported `{"passed": true, "cases": 3}` with all
  ten vulnerable loci positive and all fixed loci negative/absent, and its 447 trace
  events used only `deepseek-chat`. It is not evidence for the current analyzer.
- The current `securebench-pairs.v4` runner binds selected analyzer contents and
  secret-free model provenance into the checkpoint. V7 has no analyzer/model
  fingerprint fields and is rejected before plugin invocation; current hashes must
  not be attached to it after the fact.
- A fresh six-side DeepSeek `--clean` run is required for a current live claim after
  this runner fingerprint change. No API call was made while repairing this blocker.
- Current deterministic verification: focused resource/callgraph/pair-runner suite
  68 tests pass; full discovery 265 tests pass; deterministic crypto cross-plugin
  smoke 29 tests pass; Python 3.10 compilation passes.
- The authorized shared callgraph fix keys ordering by full `FunctionId`, excludes
  function declarations and unresolved `super().__init__` calls from call edges, and
  preserves unique-name dependencies, cycles, suffix identities, and deterministic
  order.
- The historical raw output and stages are retained unchanged at
  `/mnt/nvme/jiangzhe/opencode-runtime/tmp/opencode/todo16-resource-deepseek-final-v7.json`
  and `.../todo16-resource-deepseek-final-stages/`. Current fingerprint inputs,
  cleanup, tests, and the revised claim are under `.omo/evidence/.../plugins/resource/`.
