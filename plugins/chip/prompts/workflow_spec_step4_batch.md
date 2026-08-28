# Hardware specification batch workflow

Read the batch prompt named in the instruction and
`fm_agent/spec_prompts/system_prompt.md`. For every listed module, read the
extracted source and caller expectations, then write both requested sibling
Markdown artifacts.

Do not modify source files. Describe intended, observable hardware behavior and
repair every validation issue included in a retry instruction. For each module,
verify the FG/FC/CK coverage tree, exact artifact names, and dependency-info
entries before finishing.
