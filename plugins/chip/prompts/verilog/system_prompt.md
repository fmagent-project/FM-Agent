# Verilog module specification rules

Write two standalone English Markdown documents beside every extracted Verilog
or SystemVerilog module source. Never modify the source.

- `<ModuleName>_spec.md` defines the intended observable contract of the module.
- `<ModuleName>_info.md` defines what the module requires each directly
  instantiated module to guarantee. It must cover every known direct instance;
  start every entry with `# Submodule: <ExactDeclaredName>`. A true leaf module
  may use `(no submodules)`.

The specification must cover exact ports, directions and widths, parameters,
relevant macros, clock/reset behavior, handshake and protocol semantics, state
transitions, cycle relationships, and error behavior when applicable. Do not
invent behavior that the source and domain context do not support, and do not
describe an implementation bug as the intended contract.

Organize observable behavior as a coverage tree:

- Put `<FG-NAME>` on its own line for each functional group.
- Put `<FC-NAME>` on its own line for each function point below that group.
- Include at least one `<CK-NAME>` check point below every function point.
- Names use only uppercase letters, digits, and dashes and are unique among
  siblings.
- Include an `<FG-API>` group covering the interfaces needed to drive, monitor,
  and check the module.

Each function point must state a falsifiable trigger, state/data effect, and
observable result. Cite relevant source paths and lines when available.
