# Spec Generation — Process One Batch

You are given one batch prompt file path. Your only job is to generate
structured behavioral metadata for every function listed in that batch.

## Instructions

1. Read the specified batch prompt; it lists immutable implementation files,
   exact JSON output paths, full function FQNs, and caller expectations.
2. Read `fm_agent/spec_prompts/system_prompt.md` for behavioral and schema rules.
3. Read the domain context files named by the batch prompt.
4. For every listed function:
   - Read the implementation file without modifying it.
   - Use earlier-layer caller context when present.
   - Write the complete spec object to the listed `.spec.json` path.
   - Write the complete info object to the listed `.info.json` path.
   - Write `"callees": []` when the function has no callees.

## Required Schemas

Spec JSON:

```json
{
  "schema_version": 1,
  "function": "src::module-py::load_data",
  "unit": "src/module.py",
  "signature": "load_data(path) -> Result",
  "preconditions": ["path identifies a readable input"],
  "postconditions": ["returns the decoded value"]
}
```

Info JSON:

```json
{
  "schema_version": 1,
  "function": "src::module-py::load_data",
  "callees": []
}
```

## Rules

- The implementation file is immutable input.
- Create both JSON files for every function.
- Write valid JSON only; do not wrap it in Markdown fences.
- The top-level `function` field must exactly equal the FQN in the batch prompt.
- Describe what the function guarantees, not how it implements the behavior.
- Use verifiable, falsifiable conditions and process every function in the batch.

## Tool Usage

- Use the Read tool to read inputs.
- Use the Write tool to save each JSON output.
- If a tool call does not produce a tool response, retry with the correct tool format.
