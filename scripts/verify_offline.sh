#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
app_root="$(cd "$script_dir/.." && pwd)"
python="$app_root/vendor/python/bin/python3"
dsh="$app_root/vendor/deepseek-harness/dsh"
codegraph="$app_root/vendor/codegraph/bin/codegraph"
patch="$app_root/config/dsh-fm-agent.patch.yml"
mode="${1:---full}"

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok() { echo "[ OK ] $*"; }

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ "$(uname -m)" == "x86_64" ]] || fail "x86_64 is required"
[[ -x "$python" && -x "$dsh" && -x "$codegraph" ]] || fail "bundled runtime is incomplete"
ok "platform Linux x86_64"

for removed in src/agent_validation_core src/cli_backend.py src/opencode_trace.py md/bug_validator.md; do
    [[ ! -e "$app_root/$removed" ]] || fail "removed backend/validator component is present: $removed"
done
if grep -R -n -E 'from src\.(agent_validation_core|cli_backend|opencode_trace)|import src\.(agent_validation_core|cli_backend|opencode_trace)' \
    "$app_root/main.py" "$app_root/src" >/dev/null; then
    fail "removed backend/validator import remains in runtime source"
fi
ok "OpenCode and dynamic validator runtime removed"

glibc_version="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
[[ -n "$glibc_version" ]] || fail "glibc could not be detected"
if ! "$python" - "$glibc_version" <<'PY'
import sys
def version(value):
    return tuple(int(part) for part in value.split(".")[:2])
raise SystemExit(0 if version(sys.argv[1]) >= (2, 34) else 1)
PY
then
    fail "glibc $glibc_version is too old; 2.34 or newer is required"
fi
ok "glibc $glibc_version"

if [[ -f "$app_root/MANIFEST.sha256" ]]; then
    (cd "$app_root" && sha256sum -c MANIFEST.sha256 --quiet) || fail "bundle checksum mismatch"
    ok "bundle manifest"
fi

"$python" - "$app_root" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
modules = (
    "dotenv", "rich", "pydantic_settings", "tree_sitter", "tree_sitter_c",
    "tree_sitter_cpp", "tree_sitter_java", "tree_sitter_javascript",
    "tree_sitter_python", "tree_sitter_go", "tree_sitter_rust",
    "tree_sitter_typescript", "tree_sitter_arkts",
)
for module in modules:
    __import__(module)
from tree_sitter import Language, Parser
import tree_sitter_arkts
tree = Parser(Language(tree_sitter_arkts.language())).parse(b"function f(): number { return 1; }")
assert not tree.root_node.has_error
import json
from src.qwen_tool_parser import parse_tool_calls
remaining, calls = parse_tool_calls(
    '<tool_call><function=read><parameter=filePath>"README.md"</parameter></function></tool_call>',
    {'read'},
)
assert remaining == '' and calls[0].name == 'read'
assert calls[0].arguments == {'filePath': 'README.md'}
variants = (
    '<tool_call><function=write</function><parameter=file_path>"x"</parameter>'
    '<parameter=content>"y"</parameter></tool_call>',
    '<tool_call>{"function":"write","arguments":{"file_path":"x","content":"y"}}'
    '</tool_call>',
    '<tool_call><function=write", "arguments": {"file_path":"x","content":"y"}'
    '}parameter=</function></tool_call>',
    '<tool_call>{"function=write", "arguments": '
    '{"file_path":"x","content":"y"}}</tool_call>',
    '<tool_call>{"function":write, "arguments": '
    '{"file_path":"x","content":"y"}}</tool_call>',
    '<tool_call><function=write">'
    '{"file_path":"x","content":"y"}</function></tool_call>',
    '<tool_call><function=write><parameter=file_path>x'
    '<parameter=content>y</tool_call>',
    '<tool_call>name: write\narguments: '
    '{"file_path":"x","content":"y"}</tool_call>',
    '<tool_call>write\n'
    '{"file_path":"x","content":"y"}</tool_call>',
)
for variant in variants:
    _, parsed = parse_tool_calls(variant, {'write'})
    assert parsed and parsed[0].name == 'write', variant
    assert parsed[0].arguments == {'file_path': 'x', 'content': 'y'}, parsed
write_schemas = {
    'write': {
        'type': 'object',
        'properties': {
            'file_path': {'type': 'string'},
            'content': {'type': 'string'},
        },
    },
}
_, parsed = parse_tool_calls(
    '<tool_call><function=write", "arguments": '
    '{"file_path":"/tmp/spec.json","content":"{\\"signature\\":\\"f()\\"}"}'
    '}</parameter></tool_call>',
    write_schemas,
)
assert parsed and parsed[0].name == 'write', parsed
assert parsed[0].arguments == {
    'file_path': '/tmp/spec.json',
    'content': '{"signature":"f()"}',
}, parsed
_, parsed = parse_tool_calls(
    '<tool_call><function=write>'
    '<parameter=file_path>/tmp/phases.json</parameter>'
    '<parameter=content>{"project":"schema-regression","phases":[]}</parameter>'
    '</function></tool_call>',
    write_schemas,
)
assert isinstance(parsed[0].arguments['content'], str), parsed
assert json.loads(parsed[0].arguments['content'])['project'] == 'schema-regression'
from src.harness_backend import AgentCommand, command_with_json_events
from src.qwen_tool_parser import prepare_upstream_payload
from src.prompts import _parse_spec_check_json
import src.prompts as prompts
try:
    _parse_spec_check_json(
        '{"verdict":"MATCH","counterexample":null,'
        '"offending_statements":null,'
        '"reason":"Input [2,2,2] violates the first-index requirement. '
        'Therefore, MISMATCH."}'
    )
except ValueError as exc:
    assert "describes a mismatch" in str(exc), exc
else:
    raise AssertionError("self-contradictory MATCH verdict was accepted")
benign = _parse_spec_check_json(
    '{"verdict":"MATCH","counterexample":null,'
    '"offending_statements":null,"reason":"No counterexample exists."}'
)
assert benign[0] is False, benign
responses = iter((
    '{"verdict":"MATCH","counterexample":null,'
    '"offending_statements":null,'
    '"reason":"A concrete counterexample violates B; therefore MISMATCH."}',
    '{"verdict":"MISMATCH","counterexample":"x=1",'
    '"offending_statements":"Line 1: return 0;",'
    '"reason":"For x=1 the returned value violates B."}',
))
original_retry_create = prompts._retry_create
prompts._retry_create = lambda *_args, **_kwargs: (next(responses), {}, None)
try:
    passed, statements, _actual, reason = prompts._check_post_implies_spec(
        "Line 1: return 0;", "return_value == 0", "return_value == x",
        "", "C",
    )
finally:
    prompts._retry_create = original_retry_create
assert passed is False and statements == "Line 1: return 0;", (passed, statements)
assert "violates B" in reason, reason
text_payload, text_tools = prepare_upstream_payload(
    {
        'messages': [{'role': 'user', 'content': 'Return JSON.'}],
        'tools': [{
            'type': 'function',
            'function': {'name': 'write', 'parameters': {'type': 'object'}},
        }],
        'stream': True,
    },
    text_only=True,
)
assert text_tools == {}, text_tools
assert 'tools' not in text_payload and text_payload['stream'] is False, text_payload
assert 'text-only structured-response turn' in text_payload['messages'][0]['content']
assert '<tools>' not in text_payload['messages'][0]['content']
command = AgentCommand(
    argv=['runner', '--', 'dsh', '--profile', 'headless', '-'],
    stdin='x',
    env={},
)
traced = command_with_json_events(command)
assert traced.argv[-2:] == ['--json', '-'], traced.argv
assert command.argv[-1] == '-' and '--json' not in command.argv, command.argv
PY
ok "$($python --version 2>&1), language parsers and Qwen tool parser"

dsh_version="$($dsh --version 2>&1)"
[[ "$dsh_version" == *"0.1.6-alpha.1"* ]] || fail "unexpected DeepSeek Harness version: $dsh_version"
ok "DeepSeek Harness $dsh_version"

codegraph_version="$($codegraph --version 2>&1)"
[[ "$codegraph_version" == "1.6.0-fmagent.1" ]] || fail "unexpected CodeGraph version: $codegraph_version"
ok "CodeGraph $codegraph_version"

main_help="$(
    PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 \
    FM_AGENT_CONFIG="$app_root/fm-agent.toml" \
    FM_AGENT_SECRET_FILE="$app_root/.no-secret-file" \
    FM_AGENT_DSH_BIN="$dsh" FM_AGENT_DSH_PATCH="$patch" \
    CODEGRAPH_BIN_DIR="$app_root/vendor/codegraph/bin" CODEGRAPH_TELEMETRY=0 \
    "$python" "$app_root/main.py" --help
)"
grep -q -- "--dashboard" <<<"$main_help" \
    || fail "FM-Agent CLI is missing the upstream-compatible --dashboard option"
ok "FM-Agent CLI import and argument parser"

if [[ "$mode" == "--quick" ]]; then
    echo "Offline runtime verification passed (quick)."
    exit 0
fi
[[ "$mode" == "--full" ]] || fail "usage: verify_offline.sh [--quick|--full]"

verify_tmp="$(mktemp -d /tmp/fm-agent-verify.XXXXXX)"
server_pid=""
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    case "$verify_tmp" in
        /tmp/fm-agent-verify.*) rm -rf -- "$verify_tmp" ;;
    esac
}
trap cleanup EXIT

"$python" "$script_dir/mock_openai_server.py" \
    --port-file "$verify_tmp/port" --request-log "$verify_tmp/request.json" &
server_pid=$!
for _ in {1..50}; do
    [[ -s "$verify_tmp/port" ]] && break
    sleep 0.1
done
[[ -s "$verify_tmp/port" ]] || fail "loopback mock model did not start"
port="$(<"$verify_tmp/port")"

export HTTP_PROXY="http://127.0.0.1:9"
export HTTPS_PROXY="http://127.0.0.1:9"
export ALL_PROXY="http://127.0.0.1:9"
export NO_PROXY="127.0.0.1,localhost"
export LLM_API_KEY="offline-verification-key"
export LLM_API_BASE_URL="http://127.0.0.1:$port/v1"
export LLM_API_STYLE="openai"
export LLM_MODEL="offline-smoke-model"
export DSH_HOME="$verify_tmp/dsh-home"
export DSH_TELEMETRY_DISABLED=1
export DSH_PERMISSION_MODE="danger-full-access"

set +e
timeout 60 "$dsh" --profile headless --patch "$patch" - \
    >"$verify_tmp/harness.stdout" 2>"$verify_tmp/harness.stderr" \
    <<<"Return exactly FM_AGENT_HARNESS_OFFLINE_OK and do not call tools."
harness_status=$?
set -e
[[ "$harness_status" -eq 0 ]] || {
    sed -n '1,120p' "$verify_tmp/harness.stderr" >&2
    fail "headless Harness smoke exited $harness_status"
}
grep -Fxq "FM_AGENT_HARNESS_OFFLINE_OK" "$verify_tmp/harness.stdout" \
    || fail "headless Harness returned unexpected output"
"$python" - "$verify_tmp/request.json" <<'PY'
import json, sys
data = json.loads(open(sys.argv[1], encoding="utf-8").read().splitlines()[0])
assert data["path"].endswith("/chat/completions"), data
assert data["authorization_present"], data
assert data["model"] == "offline-smoke-model", data
assert data["stream"] is True, data
assert "Return exactly FM_AGENT_HARNESS_OFFLINE_OK" in data["messages_text"], data
PY
ok "headless Harness reached only the loopback OpenAI-compatible endpoint"

FM_AGENT_CONFIG="$app_root/fm-agent.toml" \
FM_AGENT_SECRET_FILE="$app_root/.no-secret-file" \
FM_AGENT_DSH_BIN="$dsh" FM_AGENT_DSH_PATCH="$patch" \
"$python" - "$app_root" >"$verify_tmp/fm-wrapper.stdout" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[1])
from src.harness_backend import run_agent_for_messages
text, usage = run_agent_for_messages(
    os.environ["LLM_MODEL"],
    [{"role": "user", "content": "Return the requested verification marker."}],
)
assert text == "FM_AGENT_HARNESS_OFFLINE_OK", text
assert usage == {}, usage
print(text)
PY
grep -Fxq "FM_AGENT_HARNESS_OFFLINE_OK" "$verify_tmp/fm-wrapper.stdout" \
    || fail "FM-Agent Harness wrapper returned unexpected output"
"$python" - "$verify_tmp/request.json" <<'PY'
import json, sys
records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
assert len(records) == 2, records
assert "Return the requested verification marker." in records[1]["messages_text"], records[1]
assert records[1]["stream"] is False, records[1]
assert records[1]["tools_present"] is False, records[1]
PY
ok "FM-Agent wrapper strips server-side tools through the loopback Qwen proxy"

set +e
timeout 60 "$python" "$script_dir/run_harness_with_tool_proxy.py" -- \
    "$dsh" --profile headless --patch "$patch" - \
    >"$verify_tmp/proxy-tool.stdout" 2>"$verify_tmp/proxy-tool.stderr" <<'EOF'
Use the bash tool exactly once to run: printf FM_AGENT_PROXY_TOOL_OK
After it succeeds, return exactly FM_AGENT_PROXY_TOOL_OK and nothing else.
EOF
proxy_tool_status=$?
set -e
[[ "$proxy_tool_status" -eq 0 ]] || {
    sed -n '1,160p' "$verify_tmp/proxy-tool.stderr" >&2
    fail "Qwen text-tool Harness smoke exited $proxy_tool_status"
}
grep -Fxq "FM_AGENT_PROXY_TOOL_OK" "$verify_tmp/proxy-tool.stdout" \
    || fail "Qwen text-tool Harness smoke returned unexpected output"
"$python" - "$verify_tmp/request.json" <<'PY'
import json, sys
records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
assert len(records) == 4, records
first, second = records[2:]
assert first["tools_present"] is False and first["stream"] is False, first
assert "<tools>" in first["messages_text"], first
assert second["tools_present"] is False and second["stream"] is False, second
assert "<tool_response>" in second["messages_text"], second
PY
ok "Qwen text parser completed a real Harness -> bash -> Harness tool round trip"

set +e
timeout 60 "$python" "$script_dir/run_harness_with_tool_proxy.py" -- \
    "$dsh" --profile headless --patch "$patch" - \
    >"$verify_tmp/proxy-write.stdout" 2>"$verify_tmp/proxy-write.stderr" <<EOF
Use the write tool exactly once to create $verify_tmp/proxy-write.json with the exact JSON content {"status":"FM_AGENT_PROXY_WRITE_OK"}.
After it succeeds, return exactly FM_AGENT_PROXY_WRITE_OK and nothing else.
EOF
proxy_write_status=$?
set -e
[[ "$proxy_write_status" -eq 0 ]] || {
    sed -n '1,160p' "$verify_tmp/proxy-write.stderr" >&2
    fail "Qwen text-tool raw JSON write smoke exited $proxy_write_status"
}
grep -Fxq "FM_AGENT_PROXY_WRITE_OK" "$verify_tmp/proxy-write.stdout" \
    || fail "Qwen text-tool raw JSON write returned unexpected output"
"$python" - "$verify_tmp/proxy-write.json" "$verify_tmp/request.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    assert json.load(stream) == {"status": "FM_AGENT_PROXY_WRITE_OK"}
records = [json.loads(line) for line in open(sys.argv[2], encoding="utf-8")]
assert len(records) == 6, records
first, second = records[4:]
assert first["tools_present"] is False and "<function=write" not in first["messages_text"], first
assert second["tools_present"] is False and "<tool_response>" in second["messages_text"], second
PY
ok "Qwen text parser preserves schema-declared string content for real write calls"

set +e
timeout 60 "$python" "$script_dir/run_harness_with_tool_proxy.py" -- \
    "$dsh" --profile headless --patch "$patch" - \
    >"$verify_tmp/proxy-sidecars.stdout" 2>"$verify_tmp/proxy-sidecars.stderr" <<EOF
Use the write tool to create $verify_tmp/proxy-spec.json and $verify_tmp/proxy-info.json for FM_AGENT_PROXY_SIDECARS_OK.
After both writes succeed, return exactly FM_AGENT_PROXY_SIDECARS_OK and nothing else.
EOF
proxy_sidecars_status=$?
set -e
[[ "$proxy_sidecars_status" -eq 0 ]] || {
    sed -n '1,160p' "$verify_tmp/proxy-sidecars.stderr" >&2
    fail "Qwen malformed-hybrid sidecar smoke exited $proxy_sidecars_status"
}
grep -Fxq "FM_AGENT_PROXY_SIDECARS_OK" "$verify_tmp/proxy-sidecars.stdout" \
    || fail "Qwen malformed-hybrid sidecar smoke returned unexpected output"
"$python" - "$verify_tmp/proxy-spec.json" "$verify_tmp/proxy-info.json" \
    "$verify_tmp/request.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    spec = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    info = json.load(stream)
assert spec == {
    "signature": "f()",
    "pre_condition": "true",
    "post_condition": "result >= 0",
}, spec
assert info == {"callees": []}, info
records = [json.loads(line) for line in open(sys.argv[3], encoding="utf-8")]
assert len(records) == 8, records
assert records[6]["tools_present"] is False, records[6]
assert "<tool_response>" in records[7]["messages_text"], records[7]
PY
ok "malformed Qwen pseudo-JSON calls created both Stage-6-style JSON sidecars"

mkdir -p "$verify_tmp/pipeline-plain-project"
printf '%s\n' 'int answer(void) { return 42; }' \
    >"$verify_tmp/pipeline-plain-project/plain.c"
FM_AGENT_CONFIG="$app_root/fm-agent.toml" \
FM_AGENT_SECRET_FILE="$app_root/.no-secret-file" \
FM_AGENT_DSH_BIN="$dsh" FM_AGENT_DSH_PATCH="$patch" \
CODEGRAPH_BIN_DIR="$app_root/vendor/codegraph/bin" CODEGRAPH_TELEMETRY=0 \
AGENT_MAX_RETRIES=1 MAX_WORKERS=1 \
timeout 180 "$python" "$app_root/main.py" \
    "$verify_tmp/pipeline-plain-project" --one-phase \
    >"$verify_tmp/pipeline.stdout" 2>"$verify_tmp/pipeline.stderr" \
    || {
        sed -n '1,240p' "$verify_tmp/pipeline.stdout" >&2
        sed -n '1,240p' "$verify_tmp/pipeline.stderr" >&2
        fail "complete Stage 1-6 ordinary-directory pipeline failed"
    }
"$python" - "$verify_tmp/pipeline-plain-project" "$app_root" \
    "$verify_tmp/request.json" <<'PY'
import glob, json, os, sys
project = sys.argv[1]
sys.path.insert(0, sys.argv[2])
work = os.path.join(project, "fm_agent")
with open(os.path.join(work, "phases.json"), encoding="utf-8") as stream:
    phases = json.load(stream)
assert phases["phases"][0]["modules"][0]["source_files"] == ["plain.c"], phases
for relative in (
    "spec_prompts/domain_context/engine_overview.txt",
    "spec_prompts/domain_context/phase_01_types.txt",
    "fm_agent_file_list.json",
    "spec_prompts/phase_01_topdown_layers.json",
    "extracted_functions/plain-c/answer.c.spec.json",
    "extracted_functions/plain-c/answer.c.info.json",
    "logic_verification_results/plain-c/answer.json",
):
    assert os.path.isfile(os.path.join(work, relative)), relative
events = [
    json.loads(line)
    for line in open(os.path.join(work, "trace", "events.jsonl"), encoding="utf-8")
]
validations = [event for event in events if event.get("type") == "stage_validation"]
assert validations, events
for stage in ("stage_3", "stage_4", "stage_5", "stage_6"):
    assert any(
        event.get("stage") == stage and event.get("status") == "success"
        for event in validations
    ), (stage, validations)
assert any(
    event.get("stage") == "generate_phases_json"
    and event.get("status") == "success"
    for event in validations
), validations
assert any(
    event.get("stage") == "generate_domain_context"
    and event.get("status") == "success"
    for event in validations
), validations
logs = glob.glob(os.path.join(work, "trace", "payloads", "*_harness.log"))
assert logs and all(os.path.getsize(path) > 0 for path in logs), logs
for path in logs:
    records = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    assert records and records[0]["type"] == "session", (path, records)
proxy_logs = glob.glob(os.path.join(work, "trace", "payloads", "*_proxy.jsonl"))
assert proxy_logs and all(os.path.getsize(path) > 0 for path in proxy_logs), proxy_logs
proxy_records = [
    json.loads(line)
    for path in proxy_logs
    for line in open(path, encoding="utf-8")
    if line.strip()
]
assert any("write" in record["recognized_tool_names"] for record in proxy_records), proxy_records
assert any(record.get("text_only") is True for record in proxy_records), proxy_records
assert any(record.get("text_only") is False for record in proxy_records), proxy_records
agent_events = [event for event in events if event.get("type") == "agent_call"]
assert any(
    any(child.get("label") == "qwen-tool-proxy-upstream-responses" for child in event["children"])
    for event in agent_events
), agent_events
llm_events = [event for event in events if event.get("type") == "llm_call"]
assert llm_events and all(
    any(child.get("label") == "qwen-tool-proxy-upstream-responses" for child in event["children"])
    for event in llm_events
), llm_events
structured_requests = [
    record
    for record in (
        json.loads(line)
        for line in open(sys.argv[3], encoding="utf-8")
        if line.strip()
    )
    if (
        "Generate the post-condition" in record["messages_text"]
        or "concrete valid input" in record["messages_text"]
    )
]
assert structured_requests, structured_requests
assert all("<tools>" not in record["messages_text"] for record in structured_requests)
assert all(
    "text-only structured-response turn" in record["messages_text"]
    for record in structured_requests
)
assert all(
    record["chat_template_kwargs"] == {"enable_thinking": False}
    for record in structured_requests
)
report_path = os.path.join(work, "VERIFICATION-REPORT.json")
with open(report_path, encoding="utf-8") as stream:
    report = json.load(stream)
assert report["status"] == "complete" and report["counts"]["MATCH"] == 1, report
assert report["trace"]["latest_stage_validation"]["stage_6"]["status"] == "success", report
result_record = report["results"][0]
assert result_record["location"] == "L1-L1", result_record
assert os.path.isfile(os.path.join(work, "VERIFICATION-REPORT.md"))
html_report = os.path.join(work, "report.html")
assert os.path.isfile(html_report)
html = open(html_report, encoding="utf-8").read()
assert "FM-Agent Static Verification Report" in html
assert "static_unconfirmed" in html
for marker in ("Source files", "Expand all", "Collapse all", "Open full detail", "source-line"):
    assert marker in html, marker

# An ERROR artifact is partial, must remain pending, and must become retryable
# instead of being counted as a completed Stage-6 proof.
from src.file_utils import _get_incomplete_verification_files
from src.verification import write_static_verification_report
rel = "plain-c/answer.c"
result_path = os.path.join(work, "logic_verification_results", "plain-c", "answer.json")
with open(result_path, encoding="utf-8") as stream:
    original_result = json.load(stream)
with open(result_path, "w", encoding="utf-8") as stream:
    json.dump({"function": rel, "verdict": "ERROR", "gaps": None, "error": "test"}, stream)
assert _get_incomplete_verification_files(
    [rel],
    os.path.join(work, "extracted_functions"),
    os.path.join(work, "logic_verification_results"),
    work,
) == [rel]
partial = write_static_verification_report(
    os.path.join(work, "extracted_functions"),
    os.path.join(work, "logic_verification_results"),
    work,
    [rel],
)
assert partial["status"] == "partial" and partial["counts"]["ERROR"] == 1, partial
with open(result_path, "w", encoding="utf-8") as stream:
    json.dump(original_result, stream)
final = write_static_verification_report(
    os.path.join(work, "extracted_functions"),
    os.path.join(work, "logic_verification_results"),
    work,
    [rel],
)
assert final["status"] == "complete", final
PY
ok "complete Stage 1-6 non-Git pipeline has text-only verification, reports, and proxy traces"

kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=""
"$python" "$script_dir/mock_openai_server.py" \
    --mode reasoning-only \
    --port-file "$verify_tmp/reasoning-port" \
    --request-log "$verify_tmp/reasoning-request.json" &
server_pid=$!
for _ in {1..50}; do
    [[ -s "$verify_tmp/reasoning-port" ]] && break
    sleep 0.1
done
[[ -s "$verify_tmp/reasoning-port" ]] || fail "reasoning-only mock model did not start"
reasoning_port="$(<"$verify_tmp/reasoning-port")"
export LLM_API_BASE_URL="http://127.0.0.1:$reasoning_port/v1"
export DSH_HOME="$verify_tmp/reasoning-dsh-home"

FM_AGENT_CONFIG="$app_root/fm-agent.toml" \
FM_AGENT_SECRET_FILE="$app_root/.no-secret-file" \
FM_AGENT_DSH_BIN="$dsh" FM_AGENT_DSH_PATCH="$patch" \
timeout 90 "$python" "$script_dir/test_model_connectivity.py" \
    >"$verify_tmp/reasoning-test.stdout" 2>"$verify_tmp/reasoning-test.stderr" \
    || {
        sed -n '1,160p' "$verify_tmp/reasoning-test.stderr" >&2
        fail "reasoning-only model connectivity test failed"
    }
grep -Fxq "FM_AGENT_MODEL_CONNECTIVITY_OK" "$verify_tmp/reasoning-test.stdout" \
    || fail "reasoning-only connectivity marker is missing"
grep -Fxq "FM_AGENT_MODEL_TOOL_OK" "$verify_tmp/reasoning-test.stdout" \
    || fail "reasoning-only tool marker is missing"
"$python" - "$verify_tmp/reasoning-request.json" <<'PY'
import json, sys
records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
assert len(records) == 5, records
assert all(record["tools_present"] is False for record in records), records
assert all(
    record["chat_template_kwargs"] == {"enable_thinking": False}
    for record in records
), records
assert all("/no_think" in record["messages_text"] for record in records), records
assert "<tool_response>" in records[2]["messages_text"], records[2]
assert "<tool_response>" in records[4]["messages_text"], records[4]
PY
ok "Qwen Agent requests disable thinking before Bash and JSON write proofs"

kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=""
"$python" "$script_dir/mock_openai_server.py" \
    --mode always-reasoning \
    --port-file "$verify_tmp/always-reasoning-port" \
    --request-log "$verify_tmp/always-reasoning-request.json" &
server_pid=$!
for _ in {1..50}; do
    [[ -s "$verify_tmp/always-reasoning-port" ]] && break
    sleep 0.1
done
[[ -s "$verify_tmp/always-reasoning-port" ]] \
    || fail "always-reasoning mock model did not start"
always_reasoning_port="$(<"$verify_tmp/always-reasoning-port")"
export LLM_API_BASE_URL="http://127.0.0.1:$always_reasoning_port/v1"
export DSH_HOME="$verify_tmp/always-reasoning-dsh-home"

set +e
timeout 60 "$python" "$script_dir/run_harness_with_tool_proxy.py" -- \
    "$dsh" --profile headless --patch "$patch" --json - \
    >"$verify_tmp/always-reasoning.stdout" \
    2>"$verify_tmp/always-reasoning.stderr" <<'EOF'
Use the write tool to create /tmp/fm-agent-should-not-exist with content failure.
EOF
always_reasoning_status=$?
set -e
[[ "$always_reasoning_status" -ne 0 ]] \
    || fail "unresolved reasoning-only response incorrectly exited zero"
[[ -s "$verify_tmp/always-reasoning.stdout" ]] \
    || fail "Harness JSON event trace is empty for an unresolved reasoning response"
"$python" - "$verify_tmp/always-reasoning.stdout" \
    "$verify_tmp/always-reasoning-request.json" <<'PY'
import json, sys
events = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
assert events and events[0]["type"] == "session", events
records = [json.loads(line) for line in open(sys.argv[2], encoding="utf-8")]
assert records, records
assert all(record["tools_present"] is False for record in records), records
assert all(
    record["chat_template_kwargs"] == {"enable_thinking": False}
    for record in records
), records
PY
ok "unresolved reasoning-only responses fail explicitly with a non-empty JSON trace"

kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=""
"$python" "$script_dir/mock_openai_server.py" \
    --mode unparsed \
    --port-file "$verify_tmp/unparsed-port" \
    --request-log "$verify_tmp/unparsed-request.json" &
server_pid=$!
for _ in {1..50}; do
    [[ -s "$verify_tmp/unparsed-port" ]] && break
    sleep 0.1
done
[[ -s "$verify_tmp/unparsed-port" ]] || fail "unparsed-call mock model did not start"
unparsed_port="$(<"$verify_tmp/unparsed-port")"
export LLM_API_BASE_URL="http://127.0.0.1:$unparsed_port/v1"
export DSH_HOME="$verify_tmp/unparsed-dsh-home"

set +e
FM_AGENT_TOOL_PROXY_TRACE_PATH="$verify_tmp/unparsed-proxy.jsonl" \
timeout 60 "$python" "$script_dir/run_harness_with_tool_proxy.py" -- \
    "$dsh" --profile headless --patch "$patch" --json - \
    >"$verify_tmp/unparsed.stdout" 2>"$verify_tmp/unparsed.stderr" <<'EOF'
Use the write tool to create /tmp/fm-agent-should-not-exist with content failure.
EOF
unparsed_status=$?
set -e
[[ "$unparsed_status" -ne 0 ]] \
    || fail "unadvertised tool call incorrectly exited zero"
[[ -s "$verify_tmp/unparsed-proxy.jsonl" ]] \
    || fail "unparsed tool response was not written to the proxy audit log"
"$python" - "$verify_tmp/unparsed-proxy.jsonl" <<'PY'
import json, sys
records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
assert records, records
record = records[0]
assert record["unparsed_tool_syntax"] is True, record
assert "not_advertised" in record["content"], record
assert record["recognized_tool_names"] == [], record
assert record["detected_tool_name_hints"] == ["not_advertised"], record
assert record["parser_decision"] == "rejected_unparsed_tool_syntax", record
assert "not_advertised" not in record["allowed_tools"], record
PY
ok "unparsed tool calls fail safely while preserving the raw upstream response"

mkdir -p "$verify_tmp/plain-project" "$verify_tmp/empty-path"
printf '%s\n' 'int answer(void) { return 42; }' > "$verify_tmp/plain-project/plain.c"
FM_AGENT_CONFIG="$app_root/fm-agent.toml" \
FM_AGENT_SECRET_FILE="$app_root/.no-secret-file" \
FM_AGENT_DSH_BIN="$dsh" FM_AGENT_DSH_PATCH="$patch" \
"$python" - "$app_root" "$verify_tmp/plain-project" "$verify_tmp/empty-path" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[1])
from src.git import _get_head_commit, _is_git_repo, frozen_worktree
import src.pipeline_setup as pipeline_setup
project, empty_path = sys.argv[2:]
os.environ["PATH"] = empty_path
assert not _is_git_repo(project)
assert _get_head_commit(project) is None
work = os.path.join(project, "fm_agent")
assert pipeline_setup._write_fallback_phase_plan(project, work)
assert not pipeline_setup._phase_plan_schema_errors(os.path.join(work, "phases.json"))
fallback_work = os.path.join(project, "fallback-work")
os.makedirs(fallback_work)
pipeline_setup.AGENT_MAX_RETRIES = 1
pipeline_setup.run_agent_traced = lambda **_kwargs: None
pipeline_setup._run_generate_phases(project, fallback_work, sys.argv[1])
assert not pipeline_setup._phase_plan_schema_errors(
    os.path.join(fallback_work, "phases.json")
)
with frozen_worktree(project) as snapshot:
    assert open(os.path.join(snapshot, "plain.c"), encoding="utf-8").read().strip()
PY
ok "ordinary non-Git directory works even when git is unavailable"
echo "Offline runtime verification passed (full)."
