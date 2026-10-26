# Qwen3.6 自建 vLLM 工具解析器变更手册

文档版本：1.0\
适用模型：`qwen3.6-35b-a3b` / `Qwen/Qwen3.6-35B-A3B`\
适用客户端：FM-Agent DeepSeek Harness 离线版\
变更目标：让 vLLM 原生接收 OpenAI `tools`，并返回标准
`message.tool_calls`

## 1. 变更结论

把错误的：

```bash
--tool-call-parser mistral
```

替换为：

```bash
--reasoning-parser qwen3 \
--enable-auto-tool-choice \
--tool-call-parser qwen3_coder
```

同时删除所有 Mistral 专用 tokenizer、格式和 chat template 参数。完成修改后必须
完整重启 vLLM；这些启动参数不能热更新。

Qwen 官方模型卡建议 Qwen3.6 使用 vLLM 0.19.0 或更新版本，并为工具调用配置
`qwen3_coder`。vLLM 针对 `Qwen3.6-35B-A3B` 的模型配方也采用相同配置：

- <https://huggingface.co/Qwen/Qwen3.6-35B-A3B>
- <https://github.com/vllm-project/recipes/blob/main/models/Qwen/Qwen3.6-35B-A3B.yaml>

## 2. 影响范围和停机窗口

本次变更仅影响 vLLM 服务启动参数，不修改模型权重和 FM-Agent 工程数据。重启
期间 OpenAI-compatible 接口不可用，正在运行的 FM-Agent 分析会失败，应先停止
提交新任务并等待现有请求结束。

变更后：

- vLLM 原生解析 Qwen3.6 工具调用；
- 旧版 FM-Agent `0.2.0-dsh.1` 可以直接使用；
- 新版 FM-Agent `0.3.0-dsh.1` 可以切换为 `native`，不再经过本地文本工具代理；
- 普通文本请求仍使用同一 `/v1/chat/completions` 接口。

## 3. 变更前检查

### 3.1 记录版本

在 vLLM 服务器执行：

```bash
vllm --version
python3 -c 'import vllm; print(vllm.__version__)'
```

建议版本：

```text
vLLM >= 0.19.0
```

如果使用容器：

```bash
docker inspect <vllm容器名> \
  --format '{{.Config.Image}} {{json .Config.Cmd}} {{json .Config.Entrypoint}}'
```

### 3.2 保存当前启动参数

裸进程：

```bash
ps -efww | grep '[v]llm serve'
```

systemd：

```bash
sudo systemctl cat vllm
sudo systemctl show vllm -p ExecStart
```

Docker Compose：

```bash
docker compose config > /var/tmp/vllm-compose.before-change.yaml
```

Kubernetes：

```bash
kubectl -n <命名空间> get deployment <部署名> -o yaml \
  > /var/tmp/vllm-deployment.before-change.yaml
```

不要把 API key 或包含密钥的环境变量文件复制到工单或日志中。

### 3.3 检查冲突参数

以下参数不应继续用于 Qwen3.6：

```text
--tool-call-parser mistral
--tokenizer-mode mistral
--config-format mistral
--load-format mistral
--chat-template <任何 Mistral 模板>
```

如果配置了自定义 `--chat-template`，优先删除，让 vLLM 使用 Qwen3.6 模型目录内置
的模板。只有经过独立验证的 Qwen3.6 专用模板才应保留。

## 4. 标准启动参数

下面是基准示例。GPU 数量、量化、显存利用率、并发、KV cache、模型路径等参数
应保留现场原值，不要直接照抄示例值。

```bash
vllm serve /models/Qwen3.6-35B-A3B \
  --served-model-name qwen3.6-35b-a3b \
  --host 0.0.0.0 \
  --port 8000 \
  --tensor-parallel-size 2 \
  --max-model-len 262144 \
  --trust-remote-code \
  --reasoning-parser qwen3 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_coder
```

实际变更的最小差异应为：

```diff
- --tool-call-parser mistral
+ --reasoning-parser qwen3
+ --enable-auto-tool-choice
+ --tool-call-parser qwen3_coder
```

如果已有 `--reasoning-parser qwen3` 或 `--enable-auto-tool-choice`，只保留一次。

## 5. 不同部署方式的修改方法

### 5.1 裸命令或启动脚本

打开实际启动脚本，将 parser 参数替换为第 4 节的最小差异。执行语法检查：

```bash
bash -n /实际路径/start-vllm.sh
```

停止旧进程后再使用原有进程管理方式启动。不要同时运行两个监听相同端口的实例。

### 5.2 systemd

先执行：

```bash
sudo systemctl cat vllm
```

复制完整 `ExecStart`，只修改 parser 部分。使用 drop-in 覆盖时，必须先用空的
`ExecStart=` 清除原值：

```bash
sudo systemctl edit vllm
```

示例内容：

```ini
[Service]
ExecStart=
ExecStart=/实际路径/vllm serve /models/Qwen3.6-35B-A3B --served-model-name qwen3.6-35b-a3b --host 0.0.0.0 --port 8000 --tensor-parallel-size 2 --max-model-len 262144 --trust-remote-code --reasoning-parser qwen3 --enable-auto-tool-choice --tool-call-parser qwen3_coder
```

注意：示例中的 `ExecStart` 必须补齐现场原有的所有非 parser 参数。

应用并检查：

```bash
sudo systemctl daemon-reload
sudo systemctl restart vllm
sudo systemctl status vllm --no-pager
sudo journalctl -u vllm -n 200 --no-pager
```

### 5.3 Docker Compose

修改 Compose 中的 `command`：

```yaml
services:
  vllm:
    image: vllm/vllm-openai:<已验证版本>
    command:
      - Qwen/Qwen3.6-35B-A3B
      - --served-model-name
      - qwen3.6-35b-a3b
      - --reasoning-parser
      - qwen3
      - --enable-auto-tool-choice
      - --tool-call-parser
      - qwen3_coder
```

保留原有 GPU、volume、端口、共享内存和其他参数，然后执行：

```bash
docker compose config
docker compose up -d --force-recreate vllm
docker compose logs --tail=200 vllm
```

### 5.4 Kubernetes

在 Deployment/StatefulSet 的容器 `args` 中替换：

```yaml
args:
  - --served-model-name
  - qwen3.6-35b-a3b
  - --reasoning-parser
  - qwen3
  - --enable-auto-tool-choice
  - --tool-call-parser
  - qwen3_coder
```

应用后等待滚动更新：

```bash
kubectl -n <命名空间> apply -f <清单文件>
kubectl -n <命名空间> rollout status deployment/<部署名> --timeout=30m
kubectl -n <命名空间> logs deployment/<部署名> --tail=200
```

## 6. 服务启动验收

### 6.1 检查模型列表

```bash
export VLLM_BASE_URL='http://127.0.0.1:8000/v1'
read -rsp 'API key: ' VLLM_API_KEY
export VLLM_API_KEY
printf '\n'

curl -fsS "$VLLM_BASE_URL/models" \
  -H "Authorization: Bearer $VLLM_API_KEY"
```

返回的模型 ID 应与 FM-Agent 中配置的模型名一致，例如：

```text
qwen3.6-35b-a3b
```

### 6.2 原生 Function Calling 验收

```bash
curl -fsS "$VLLM_BASE_URL/chat/completions" \
  -H "Authorization: Bearer $VLLM_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{
    "model": "qwen3.6-35b-a3b",
    "messages": [
      {
        "role": "user",
        "content": "必须调用 echo_marker，参数 marker 为 FM_AGENT_TOOL_OK，不要直接回答。"
      }
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "echo_marker",
          "description": "Return a test marker",
          "parameters": {
            "type": "object",
            "properties": {
              "marker": {"type": "string"}
            },
            "required": ["marker"],
            "additionalProperties": false
          }
        }
      }
    ],
    "tool_choice": "auto",
    "stream": false
  }'
```

合格响应必须同时满足：

```text
choices[0].finish_reason == "tool_calls"
choices[0].message.tool_calls[0].function.name == "echo_marker"
```

参数中应包含：

```json
{"marker":"FM_AGENT_TOOL_OK"}
```

如果模型返回普通文本而没有 `tool_calls`，检查启动日志、chat template、模型路径和
parser 名称。不要改回 `mistral`。

## 7. FM-Agent 配置

### 7.1 旧版 `0.2.0-dsh.1`

旧版原生发送 OpenAI `tools`，不包含 `tool_compat_mode`。vLLM 修改正确后无需更改
FM-Agent 程序，只需确认：

```text
Model: qwen3.6-35b-a3b
Base URL: http://vLLM服务器地址:8000/v1
API style: openai
```

然后执行：

```bash
fm-agent configure show
fm-agent test-model
```

旧版成功标记为：

```text
FM_AGENT_MODEL_CONNECTIVITY_OK
```

### 7.2 新版 `0.3.0-dsh.1`

新版默认使用客户端 `qwen-text` 兼容层。服务端 parser 修正后，切换为原生模式：

```bash
fm-agent configure set --tool-compat-mode native
fm-agent configure show
fm-agent test-model
```

配置文件中的等价内容为：

```toml
[llm]
tool_compat_mode = "native"
```

新版验收应输出：

```text
FM_AGENT_MODEL_CONNECTIVITY_OK
FM_AGENT_MODEL_TOOL_OK
```

## 8. 常见故障

### `qwen3_coder` 未注册

现象：vLLM 启动时提示 unknown/invalid tool parser。

处理：

1. 核对 `vllm --version`；
2. 升级到支持 Qwen3.6 的版本，建议至少 0.19.0；
3. 确认启动命令使用的 Python/容器确实是刚检查的版本；
4. 不要因为名称不可用就退回 `mistral`。

### 仍出现 Mistral token 错误

说明实际生效的命令仍包含 Mistral 配置。重点检查：

```bash
ps -efww | grep '[v]llm serve'
sudo systemctl show vllm -p ExecStart
docker inspect <容器名> --format '{{json .Config.Cmd}}'
```

### 工具调用出现在 `content` 而不是 `tool_calls`

通常是 parser、chat template 或 vLLM 版本不匹配。确认使用模型内置模板，并检查
日志中是否真正加载 `qwen3_coder`。在修复前，新版 FM-Agent 可暂时继续使用：

```toml
tool_compat_mode = "qwen-text"
```

### 思考模式下强制工具选择报错

验收请求使用：

```json
"tool_choice": "auto"
```

不要首先使用对象形式的强制工具选择。FM-Agent/Harness 的正常 Agent 流程使用
自动工具选择即可。

## 9. 回滚

如果原生工具验收失败，可按以下顺序回滚：

1. 恢复变更前保存的 vLLM 启动配置；
2. 重启 vLLM；
3. 新版 FM-Agent 恢复客户端兼容模式：

```bash
fm-agent configure set --tool-compat-mode qwen-text
fm-agent test-model
```

旧版 FM-Agent 没有客户端兼容模式；若服务端回滚到错误的 Mistral parser，应暂时
改用 `0.3.0-dsh.1`，否则旧版仍会在包含 `tools` 的请求上失败。`0.2.0-dsh.2`
修复了 Qwen 只返回思考内容、最终 `content` 为空时 `test-model` 误报
`unexpected text: ''` 的问题；`0.2.0-dsh.3` 进一步修复 JSON 文本被错误转换为
对象、导致 `write.content` 参数校验失败和 `phases.json` 缺失的问题；
`0.2.0-dsh.4` 继续修复带无效 XML 尾部的畸形混合 `write` 调用，并完成 Stage
1～6 的真实模型回归；`0.2.0-dsh.5` 增加畸形伪 JSON、首次请求关闭 thinking、
非空 NDJSON trace 和六阶段产物级状态校验。
`0.2.0-dsh.6` 将模型首选工具格式收紧为 `<tool_call>` 内严格 JSON，扩展对未引用
函数名、直接 JSON 正文和不完整 XML 参数标签的恢复，并新增 `*_proxy.jsonl` 原始
上游响应审计。遇到 `fm_agent_unparsed_tool_call` 时，应查看与报错
`*_harness.log` 同前缀的代理日志，而不是只根据 Harness 的退出码判断。
`0.2.0-dsh.7` 进一步把 post-condition/implication verification 改成 Harness
text-only 调用，不向模型展示工具；并为每个 `llm_call` 保存、关联独立代理原文。
因此 verification 不应再因模型尝试工具调用而触发 422。
`0.3.0-dsh.1` 在此基础上拒绝 `verdict=MATCH` 但理由明确给出反例或
`MISMATCH` 结论的自相矛盾 JSON，并通过原有格式重试请求模型纠正。

## 10. 变更完成判定

以下项目全部满足才算完成：

- vLLM 启动命令不存在任何 Mistral parser/template 配置；
- vLLM 版本满足 Qwen3.6 要求；
- `/v1/models` 返回正确模型 ID；
- Function Calling 验收返回结构化 `message.tool_calls`；
- `fm-agent test-model` 成功；
- 使用一个测试工程完成至少一次实际 Harness 工具调用；
- vLLM 日志中没有 tokenizer/tool parser 初始化错误。
