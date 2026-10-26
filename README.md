# FM-Agent · DeepSeek Harness offline bundle

This Ubuntu 22.04 x86_64 delivery is based on the user-supplied latest
`FM-Agent-release.zip`. Every model call is routed through the bundled DeepSeek
Harness. OpenCode, Bun, oh-my-openagent, Pi Agent Validator, runtime probes,
dynamic instrumentation, automated repair, and dynamic bug confirmation are not
included.

Python 3.12, DeepSeek Harness, CodeGraph, Python dependencies, and parser
extensions are bundled. Installation and local verification perform no downloads.
Inference still requires a reachable OpenAI-compatible or Anthropic-compatible
model endpoint. DashScope therefore needs outbound connectivity; an air-gapped
deployment must use an internal endpoint.

The default Qwen text-tool proxy strips server-side tool fields before requests
reach an upstream configured with an incompatible Mistral parser, then validates
and restores textual Qwen tool calls for Harness. Use
`tool_compat_mode = "native"` only with a correctly configured upstream parser.

See [INSTALL_zh.md](INSTALL_zh.md) for the complete Chinese installation guide and
[docs/FM-Agent-release-change-analysis_zh.md](docs/FM-Agent-release-change-analysis_zh.md)
for the source-change analysis. The complete three-way conformance matrix is in
[docs/UPSTREAM-CONFORMANCE-ANALYSIS_zh.md](docs/UPSTREAM-CONFORMANCE-ANALYSIS_zh.md),
and the implementation change report is in
[docs/V0.3.0-MODIFICATION-REPORT_zh.md](docs/V0.3.0-MODIFICATION-REPORT_zh.md).
The shorter audit summary is in
[docs/COMPATIBILITY-AUDIT_zh.md](docs/COMPATIBILITY-AUDIT_zh.md). Test evidence is summarized in
[VALIDATION-REPORT_zh.md](VALIDATION-REPORT_zh.md).

## Quick start

```bash
sha256sum -c FM-Agent-release-deepseek-harness-offline-ubuntu22-x86_64-v0.3.0-dsh.1.tar.gz.sha256
tar -xzf FM-Agent-release-deepseek-harness-offline-ubuntu22-x86_64-v0.3.0-dsh.1.tar.gz
cd FM-Agent-release-deepseek-harness-offline-ubuntu22-x86_64-v0.3.0-dsh.1
./install.sh
export PATH="$HOME/.local/bin:$PATH"
fm-agent configure
fm-agent test-model
fm-agent /absolute/path/to/project --one-phase
```

Ordinary local directories work without `.git`, including with `--isolate`.
Only `--incremental INTENT_FILE` requires a Git repository with a commit.

Results are written below `<project>/fm_agent/`. `--all-bugs` collects every
static mismatch candidate; it does not dynamically confirm those candidates.

Useful commands:

```bash
fm-agent version
fm-agent configure show
fm-agent verify-install --full
fm-agent test-model
fm-agent /path/to/project --resume --one-phase
fm-agent /path/to/project --isolate --one-phase
fm-agent /path/to/project --dashboard --one-phase
fm-agent dashboard /path/to/project
fm-agent report /path/to/project
```

Each completed static run writes `VERIFICATION-REPORT.md`,
`VERIFICATION-REPORT.json`, and a self-contained searchable `report.html`.

Target: Ubuntu 22.04 x86_64; bundled ELF files require glibc 2.34 or newer.
Licenses and third-party notices are in `LICENSE` and `licenses/`.
