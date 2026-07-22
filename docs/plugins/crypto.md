# Crypto 插件：加密 API 误用

> 插件索引：[./README.md](./README.md)
> SPI 架构：[../plugin_architecture.md](../plugin_architecture.md)

Crypto 采用 CrySL 风格的“操作 + 材料来源 + 时序”模型。LLM 提取逐函数 crypto signature，`src/crypto_reasoner.py` 用确定性规则表裁决；`src/crypto_validation.py` 对一小组 Python API 重验源码可判定事实。它不是通用密码学证明器，也不是 source-to-sink 污点分析：加密操作本身是 locus，verify-before-trust 是顺序/typestate 属性。

## 1. 理论与 Finding Taxonomy

CrySL 风格规则关注三类约束：

1. 算法和参数：弱/废弃算法、ECB、key size、KDF cost。
2. 材料 provenance：key、IV/nonce、salt、随机数来自 literal、参数、配置、KDF 还是 CSPRNG。
3. 调用顺序：验证结果是否被检查并支配对数据的信任。

当前 reasoner 的 finding 如下：

| Finding | CWE | 典型 verdict |
|---|---|---|
| `weak_algorithm` | CWE-327 | `WEAK` |
| `broken_or_deprecated_cipher` | CWE-327 | `VULNERABLE` |
| `ecb_mode` | CWE-327 | `VULNERABLE` |
| `hardcoded_key_or_secret` | CWE-321/CWE-798 | `VULNERABLE` |
| `static_or_reused_iv_nonce` | CWE-329/CWE-323 | `VULNERABLE` |
| `predictable_randomness` | CWE-338 | `VULNERABLE` |
| `insufficient_key_size` | CWE-326 | `WEAK`，但 AES <128 或 RSA <1024 时为 `VULNERABLE` |
| `password_fast_hash` | CWE-916 | `VULNERABLE` |
| `weak_kdf_parameters` | CWE-916 | `WEAK` |
| `missing_password_salt` | CWE-759 | `VULNERABLE` |
| `verify_not_checked` | CWE-347 | `VULNERABLE` |
| `missing_ciphertext_authentication` | CWE-345/CWE-353 | encrypt-side CBC/CTR/CFB/OFB 明确无认证时为 `WEAK`；信任未认证解密明文时为 `VULNERABLE` |
| `tls_verification_disabled` | CWE-295 | `VULNERABLE` |
| `jwt_none_or_signature_disabled` | CWE-347 | `VULNERABLE` |
| `unknown_crypto_semantics` | 无 | `NEEDS_REVIEW` |
| `parametric_crypto_material` | 无 | `POLYMORPHIC` |
| `exported_crypto_material` | 无 | `POLYMORPHIC` |

最终 verdict 按以下优先级取函数中最高一档：

```text
ERROR > VULNERABLE > WEAK > POLYMORPHIC > NEEDS_REVIEW > SAFE
```

### 最小例子

```python
def encrypt_bad(data):
    key = b"0123456789abcdef"
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(data)

def encrypt_good(data):
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)
```

若 signature 准确记录这些操作，前者会因 ECB 和 hardcoded key 为 `VULNERABLE`；后者的 GCM、CSPRNG key 和 fresh nonce 不触发规则。这里的“若”很重要：当前 Python source validator 不独立解析一般 AES/Cipher 调用，主要依赖模型为这类 API 建立 operation facts。

## 2. Model Facts Schema

提示词要求 `[CRYPTO_JSON] ... [/CRYPTO_JSON]`：

```json
{
  "schema_version": "crypto_v1",
  "function": {"name": "encrypt", "params": ["data"], "language": "python"},
  "calls": [],
  "returns": [],
  "crypto_operations": [
    {"id": "op_1", "kind": "encrypt", "purpose": "security",
     "library": "cryptography", "api": "AESGCM.encrypt", "algorithm": "AES", "mode": "GCM",
     "key": {"provenance": "from_csprng", "length_bits": 256, "source": {"kind": "csprng"}},
     "iv_nonce": {"provenance": "fresh_random_per_call", "randomness_source": "csprng"},
     "authenticity": {"provided_by": "aead"}, "evidence": "AESGCM(key).encrypt(...)"}
  ],
  "verify_events": [],
  "red_flags": [],
  "notes": []
}
```

reasoner 严格校验集合形状、operation kind、相关 operation 上已提供的 key/IV provenance，以及已提供的 verify status：

- operation kind：`hash|encrypt|decrypt|sign|verify|mac|key_generation|key_derivation|random|tls_config|jwt_decode|password_hash`。
- key provenance：`hardcoded_literal|from_csprng|from_kdf|from_password_no_kdf|from_param|from_config_or_env|unknown`。
- IV/nonce provenance：`fresh_random_per_call|constant_or_literal|reused_across_calls|counter|from_param|unknown|not_applicable`。
- randomness source：schema 提示为 `csprng|insecure_prng|unknown|not_applicable`，但 `validate()` 当前没有统一校验此字段。
- verify status：`checked_and_dominates_use|checked_but_does_not_dominate_use|not_checked|ignored_or_swallowed|unknown`。

schema 是宽松的：`schema_version` 的值、function/purpose/source 子字段以及许多缺失字段不会被 `validate()` 拒绝；`CryptoPlugin.check()` 也不比较 envelope schema 或 payload schema。缺失字段不总会生成 `NEEDS_REVIEW`。例如没有 key provenance、非安全用途的 random、以及某些没有足够字段的 operation 可能不触发 finding。因此“unknown 会在对应规则分支保守处理”是准确说法，“任何未知或缺失都绝不 SAFE”则不是当前实现保证。

## 3. Model 与 Python Source Validation 的边界

### 模型仍然负责什么

模型负责一般 crypto API 识别、算法/模式、purpose、nonce freshness、KDF 参数、TLS 配置、AEAD trust 时序、自定义 wrapper 语义和跨语言事实。reasoner 只按收到的结构裁决，不回读源码证明这些一般事实。

`from_config_or_env` 在规则表中是“可接受 provenance”，只表示不是仓库内 literal；它不证明运行时 secret 足够随机、未使用默认值或安全存储。类似地，现代 API 名称不会覆盖已知 hardcoded provenance。

### Python validator 实际识别的 API

`validate_and_enrich` 只在 language 为 Python 时运行 AST source correction，范围主要是：

- 标准/常见随机 API：`os.urandom`、`secrets.*`、`get_random_bytes`、`uuid.uuid4` 和 `random.SystemRandom()` 归为 CSPRNG；模块级 `random.choice/random/randint/...` 归为 insecure PRNG。
- 显式 `hashlib` 调用：识别 MD2/MD4/MD5/SHA 系列、SHA3 和 BLAKE2，并以调用表达式覆盖模型 algorithm。`checksum_nonsecurity` 或 `password_storage` purpose 只有在函数名/源码存在相应语义词时保留，否则改为 `unknown`。
- PyJWT 风格 `jwt.encode`/`jwt.decode`：读取显式 algorithm(s)，沿本地赋值、同模块常量、项目内 `from ... import ...` 常量、对象属性赋值、配置/环境读取和 `.hex()` 编码追踪 key provenance。

它不会独立验证一般 AES/DES/RSA/TLS/KDF API，也不会为所有语言提供同等 source proof。源码定位还依赖 `fm_agent_crypto/extracted_functions` 的目录约定；无法定位原始模块时，跨模块常量与 import provenance 不可用。

### correction 的具体行为

- validator 深拷贝 payload，不修改调用者传入的原始 dict。
- 同函数多个已识别 call 优先按完整 API、再按 terminal method、最后按同 kind 的首个未使用 operation 配对。该匹配是启发式，不是稳定的 source location identity。
- 对 random/hash/JWT 这类 source-decidable operation，源码不存在的旧记录会删除；识别到的 hash/JWT 可补建 operation，security/token 语义明确的 random 也可补建。
- Python payload 的 `red_flags` 总是清空，structured operation rules 才拥有 verdict，避免模型 red flag 覆盖源码 correction。非 Python payload 不做这一步，模型 red flags 仍会被 reasoner 接受。
- internal callee proxy operation 若只是复述 `calls[]` 中的调用且没有对应已识别源码 API，会被删除，避免把 callee 操作重复算作 caller 本地操作。
- 没检测到 JWT decode 时，所有 model `verify_events` 会被清空；检测到 JWT decode 时，现有 verify events 才会保留。validator 不独立证明任意 signature/MAC/certificate verify event 的控制流支配关系。

与 authz 不同，crypto facts 没有 source digest、validator version marker 或 stale-schema 拒绝。`check()` 会在每次 replay 重新运行 source correction，所以已识别 Python API 的旧 facts 可被改正；validator 范围外的陈旧 model facts仍可能保留。

## 4. Reasoner 规则的实际边界

### Key 与 nonce provenance

- hardcoded key -> `VULNERABLE`；password without KDF -> `VULNERABLE`；parameter -> `POLYMORPHIC`；显式 `unknown` -> `NEEDS_REVIEW`。
- fresh nonce 还要求 randomness source 不是 insecure/unknown；counter 必须有 `uniqueness_guarantee=true`；parameter nonce -> `POLYMORPHIC`。
- `not_applicable` 只适合不需要 nonce 的情况。对 AEAD 或 CBC/CTR/CFB/OFB encrypt，如果 provenance 缺失/unknown 会进入 `NEEDS_REVIEW`。

### Hash、KDF 与参数

MD5/SHA1 等弱 hash：明确 `checksum_nonsecurity` 时豁免；security purpose 为 `WEAK`；当前 hash checker 对 unknown purpose 也会给 `WEAK`，因为没有非安全用途证据。password storage 使用 fast hash 为 `VULNERABLE`。

PBKDF2 iteration <100000、bcrypt cost <10 为 `WEAK`；参数缺失时相关分支为 `NEEDS_REVIEW`。这些是当前硬编码阈值，不是动态标准或库版本策略。

### Verify-before-trust

`checked_and_dominates_use` 放行；not checked、ignored/swallowed 或不支配 trusted use 为 `VULNERABLE`；显式 unknown 为 `NEEDS_REVIEW`。但该结论依赖保留下来的 model verify event，Python validator 目前只用 JWT decode 是否存在作为保留门槛，不执行通用 CFG dominance proof。

## 5. Bottom-up Composition

Crypto 不运行 top-down pass。`compose_calls` 只处理 caller operation 的 `key` 或 `iv_nonce`，且 material `source.kind == "call_return"` 的情况：

1. 从 resolved callee 的 `returns[]` 取得第一个同 material kind 的记录；没有同 kind 时会退到第一个 return。
2. 非 `from_param` provenance 直接返回；`from_param` 依据 `calls[].actual_args[].source_kind` 映射 literal、param、config/env，否则为 unknown。
3. key provenance 直接写回。IV 只接受 IV vocabulary；hardcoded key-style provenance 映射为 `constant_or_literal`，其他不在 IV vocabulary 的值变成 `unknown`。

helper 仅返回 hardcoded key-shaped material时，本地是 `exported_crypto_material / POLYMORPHIC`；caller 真正把它作为 key 使用后才变为 `hardcoded_key_or_secret / VULNERABLE`。当前组合不处理 arbitrary field、random-token use、多个同名 callee 的精确区分或复杂表达式数据流，且 callee 解析存在“唯一 callee”fallback，因此只能称为窄的 return-provenance 实例化。

## 6. Fallback、ERROR 与 NEEDS_REVIEW

driver 对不可解析 JSON 或 validation 返回 `None` 的响应重试；调用异常或重试耗尽生成 `status="error"` facts。

Crypto 的 `check()` 有一个 authn/authz 不具备的 source-only fallback：

- 仅对 validator 能从 Python source 自行补出的已识别 random/hash/JWT operation 构造 `crypto_v1` facts。
- 只有 source-derived classification 既不是 `ERROR` 也不是 `NEEDS_REVIEW` 才采用，并把 facts status 改为 `partial`。因此一个明确的 insecure random 可在 LLM 失败后仍为 `VULNERABLE`，一个明确的 CSPRNG token 或可判定安全 hash 也可能为 `SAFE`。
- 没有已识别 operation，或 source-only facts 仍需要 review 时，保持 `ERROR`。

正常 facts 在 `check()` 边界也会重做 Python correction。结构/enum malformed 会成为 `ERROR`；规则分支中的显式 unknown 通常成为 `NEEDS_REVIEW`；参数化材料成为 `POLYMORPHIC`。评测 registry 把 `VULNERABLE` 和 `WEAK` 计入 positive，`POLYMORPHIC`、`NEEDS_REVIEW`、`ERROR` 仍按 fail-closed flagged 处理，只有 `SAFE` 属于 negative。

## 7. Focused Tests 与 CVE 示例

`tests/test_crypto_validation_guards.py` 覆盖当前实现边界：

- insecure/CSPRNG random correction、多个随机调用配对和 red-flag 清空；
- imported/module/config/env/object-attribute/CSPRNG-encoding 的 JWT key provenance；
- modern signing API 不豁免 hardcoded key，JWT decode 也检查 key provenance；
- `hashlib.md5` 从调用而非函数名识别，unsupported checksum claim 被纠正，源码已删除的 stale operation 被移除；
- malformed collections -> `ERROR`，cache replay 重新 correction；
- LLM error 在 source semantics 足够时采用 partial fallback，不足时保持 `ERROR`。

`eval/securebench_corpus.json` 当前声明：

- `CVE-2023-48224 / CWE-338`：`generate_id_verification_code`。
- `CVE-2025-55449 / CWE-321`：`generate_jwt` 与 `auth_middleware`。
- `CVE-2021-39182 / CWE-326`：`MD5`，fixed expectation 为 absent。

focused tests 还固定了语义 CWE 与官方评测标签可以不同：MD5 finding 仍是 `CWE-327`，evaluation metadata 不覆盖 reasoner finding；pair runner 可按 CWE family 和 locus 规则评分。以上只说明 manifest、reasoner 和 runner 的当前契约，不宣称单个测试证明完整 CVE exploit 或所有修复版本。

## 8. 适用边界

Crypto 适合对多语言代码做加密误用初筛，并对 Python `random`/`secrets`、`hashlib` 和 PyJWT 的若干事实增加源码约束。它不适合作为合规级 sound proof，也不能用 `SAFE` 断言仓库没有密码学缺陷。一般 cipher mode、nonce lifetime、自定义 wrapper、verify dominance 和 purpose 仍高度依赖模型 facts；纯句法问题通常应同时使用更便宜、更完整的 linter 或专用 crypto analyzer。
