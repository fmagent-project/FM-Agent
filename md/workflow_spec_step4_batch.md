# Spec Generation — Process One Batch

You are given a single batch prompt file path in the prompt. Your ONLY job is to generate behavioral specs for the functions listed in that batch. Do NOT run any other scripts or orchestrate anything — just read, generate, and write.

---

## Instructions

1. Read the batch prompt `.txt` file specified in the prompt — it lists the functions to spec and provides caller expectations
2. Read `fm_agent/spec_prompts/system_prompt.md` for mandatory spec format rules
3. Read any domain context files mentioned in the batch prompt (e.g., `engine_overview.txt`, `phase_NN_types.txt`, and user-provided Markdown files under `user_knowledge/`)
4. For EACH function listed in the batch prompt:
   a. Read the extracted function file
   b. If layer > 0, read earlier-layer caller specs mentioned in the batch prompt
   c. Generate a behavioral spec and write it to `<function-file>.spec.json` in the same directory
   d. Generate callee expectations and write them to `<function-file>.info.json` in the same directory
   e. Do NOT modify the original function source file

---

## Spec Format

For each extracted function file (for example, `calculate_average.py`), write TWO
separate JSON files in the SAME directory. Do NOT modify the original function
source file.

**`<function-file>.spec.json`** — the function's own behavioral specification:

```json
{
  "signature": "<FunctionName>(<params>) -> <ReturnType>",
  "pre_condition": "<what must hold before the call>",
  "post_condition": "<what the function guarantees after return>"
}
```

**`<function-file>.info.json`** — the expected specs of the function's callees:

```json
{
  "callees": [
    {
      "name": "<callee_name>",
      "signature": "<callee_name>(<params>) -> <ReturnType>",
      "pre_condition": "<what the caller guarantees before calling>",
      "post_condition": "<what the caller expects after the call>"
    }
  ]
}
```

If a function has no callees, write `{"callees": []}` to the `.info.json` file.

---

## Rules

| ✅ Do | ❌ Do Not |
|------|----------|
| Describe data invariants: lengths, types, encoding, valid ranges | Name internal helper functions called |
| Describe sort order and output format contracts | Describe loop structure or branch choices |
| Describe error contract: what throws and under what exact condition | Enumerate switch cases or dispatch entries by name |
| Use verifiable, falsifiable claims | Use vague terms: "correctly handles", "processes", "manages" |
| Describe the governing invariant across all code paths | Name specific set members "as examples" |

```
MUST NOT modify source code — write spec and info to separate JSON files
MUST follow system_prompt.md rules: behavioral specs, not implementation descriptions
MUST process ALL functions in the batch — do not stop early
```

**You MUST complete ALL functions in the batch before exiting.**

---

## IMPORTANT: Tool Usage

- Use the **Read** tool to read files. Do NOT output raw JSON tool calls like `[tool_use: read, input: {...}]` — that is plain text and will NOT execute.
- Use the **Write** tool to save files. Do NOT output raw JSON tool calls like `[tool_use: write, input: {...}]`.
- If a file read or write does not produce a tool response, you used the wrong format. Stop and retry with the correct tool.
