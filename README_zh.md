# FM-Agent · DeepSeek Harness 离线版

这是基于用户提供的最新版 `FM-Agent-release.zip` 制作的 Ubuntu 22.04
x86_64 交付版。所有模型调用均经由随包提供的 DeepSeek Harness；不包含
OpenCode、Bun、oh-my-openagent 或 Pi Agent Validator，也不包含动态插装、运行时
探针、自动修复和动态 Bug 确认流程。

离线包内含 Python 3.12、DeepSeek Harness、CodeGraph、Python 依赖和语法解析器。
安装、校验和启动不下载任何内容。模型推理仍需一个可达的 OpenAI-compatible
或 Anthropic-compatible 接口：使用 DashScope 时服务器需要访问 DashScope；完全
隔离网络应改为内网模型服务。

默认使用 `native`，将 OpenAI `tools` 字段原样发送给模型服务。如上游 Qwen 服务的
工具解析器不兼容，可显式设置 `tool_compat_mode = "qwen-text"`，通过本地代理验证并
还原文本工具调用。

完整安装与运维步骤见 [INSTALL_zh.md](INSTALL_zh.md)，最新版源码差异见
[docs/FM-Agent-release-change-analysis_zh.md](docs/FM-Agent-release-change-analysis_zh.md)，
完整三方符合性矩阵见
[docs/UPSTREAM-CONFORMANCE-ANALYSIS_zh.md](docs/UPSTREAM-CONFORMANCE-ANALYSIS_zh.md)，
本版本修改报告见
[docs/V0.3.0-MODIFICATION-REPORT_zh.md](docs/V0.3.0-MODIFICATION-REPORT_zh.md)，兼容摘要见
[docs/COMPATIBILITY-AUDIT_zh.md](docs/COMPATIBILITY-AUDIT_zh.md)，
实测结果见 [VALIDATION-REPORT_zh.md](VALIDATION-REPORT_zh.md)。

## 最短使用路径

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

普通本地目录无需 `.git` 即可执行完整分析，也可加 `--isolate` 在文件系统快照中
运行。只有 `--incremental INTENT_FILE` 需要带至少一个提交的 Git 仓库。

## 常用命令

```bash
fm-agent version
fm-agent configure show
fm-agent verify-install --full
fm-agent test-model
fm-agent /path/to/project --one-phase
fm-agent /path/to/project --resume --one-phase
fm-agent /path/to/project --isolate --one-phase
fm-agent /path/to/project --all-bugs --one-phase
fm-agent /path/to/project --dashboard --one-phase
fm-agent dashboard /path/to/project
fm-agent report /path/to/project
```

分析结果写入目标项目的 `fm_agent/`：

- `phases.json`：模块/阶段规划；
- `extracted_functions/`：函数源码和 `.spec.json`、`.info.json`；
- `logic_verification_results/`：静态推理结果；
- `VERIFICATION-REPORT.md/json`：人类/机器可读的终态汇总；
- `report.html`：静态分析结束立即生成的自包含交互报告；
- `trace/events.jsonl`、`trace/payloads/`：Harness 调用与结构化调用轨迹；
- `*.log`：运行日志。

`--all-bugs` 表示继续收集所有静态不一致候选，不表示已经通过动态测试确认。

## 支持范围

- 目标平台：Ubuntu 22.04 x86_64，glibc 2.35；随包二进制最低要求 glibc 2.34。
- 模型后端：仅 `deepseek-harness`。
- 默认模型：`qwen3.6-35b-a3b`；可通过配置或 `LLM_MODEL` 覆盖。
- 工具兼容：默认 `native`；可通过 `FM_AGENT_TOOL_COMPAT_MODE` 配置为 `qwen-text`。
- CodeGraph：`1.6.0-fmagent.1`。
- DeepSeek Harness：`0.1.6-alpha.1`。

许可证与第三方声明位于 `LICENSE` 和 `licenses/`。
