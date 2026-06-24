# Crypto 插件：加密误用检测（Cryptographic API Misuse）

> 插件总览见 [./README.md](./README.md)。
> 同底座的其它插件：完整性污点 [./taint.md](./taint.md)、机密性信息流 [./ifc.md](./ifc.md)、访问控制 [./authz.md](./authz.md)。
> 插件 SPI 架构见 [../plugin_architecture.md](../plugin_architecture.md)。

Crypto 是 FM-Agent 多理论分析底座上的**第四个**插件，风格上承袭 **CrySL**（一种加密 API 使用
规约语言）。它复用了与前三个插件相同的通用技术：

> **LLM 产出模块化的、逐函数的自然语言抽象 →（一个不带 LLM 的）确定性纯 Python 检查器在该
> 抽象上做裁决 → 结果自底向上跨函数组合。**

但它面向的属性和前三个插件都不同：污点 / IFC 关注「数据从哪里流到哪里」，访问控制关注「调用前
是否建立了守卫义务」，而 **加密误用关注的是「这一次加密操作本身用对了吗」**——算法选对了没？密钥
从哪来？IV/nonce 每次都新鲜吗？验签结果在信任数据之前真的被检查了吗？

本文档假定你已大致了解 SPI（`src/plugins/base.py`）与通用驱动（`src/plugins/driver.py`）。涉及
的源码：

- `src/crypto_prompts.py` —— LLM 抽象提示词，产出 `[CRYPTO_JSON] ... [/CRYPTO_JSON]`。
- `src/crypto_reasoner.py` —— 确定性检查器：算法表、provenance 枚举、逐操作决策表、verify-before-trust、组合实例化。
- `src/plugins/crypto.py` —— SPI 适配器：自底向上的 return-provenance 解析、`check`。

---

## 1. 面向的攻击：它检测什么

加密误用不是「算法被数学攻破」，而是「**程序员用错了原本正确的算法**」。检查器在
`src/crypto_reasoner.py:75` 的 `FINDING_KINDS` 表里直接给出了它覆盖的问题类型与 CWE：

| finding kind                       | 问题                                  | CWE              | 默认判级       |
| ---------------------------------- | ------------------------------------- | ---------------- | -------------- |
| `weak_algorithm`                   | 弱算法（MD5/SHA1 用于安全用途）       | CWE-327          | WEAK           |
| `broken_or_deprecated_cipher`      | 已破/废弃密码（DES/3DES/RC4/RC2）     | CWE-327          | VULNERABLE     |
| `ecb_mode`                         | ECB 模式                              | CWE-327          | VULNERABLE     |
| `hardcoded_key_or_secret`          | 硬编码密钥/密钥字面量                 | CWE-321/CWE-798  | VULNERABLE     |
| `static_or_reused_iv_nonce`        | 静态 / 复用的 IV/nonce                | CWE-329/CWE-323  | VULNERABLE     |
| `predictable_randomness`           | 用不安全 PRNG 产生安全材料            | CWE-338          | VULNERABLE     |
| `insufficient_key_size`            | 密钥长度不足                          | CWE-326          | WEAK           |
| `password_fast_hash`               | 用快哈希存口令（而非慢 KDF）          | CWE-916          | VULNERABLE     |
| `weak_kdf_parameters`              | KDF 迭代/cost 太低                    | CWE-916          | WEAK           |
| `missing_password_salt`            | 口令哈希缺盐 / 盐复用                  | CWE-759          | VULNERABLE     |
| `verify_not_checked`               | 签名/MAC/证书验证结果未被检查         | CWE-347          | VULNERABLE     |
| `missing_ciphertext_authentication`| 密文缺认证（未认证就信任明文）        | CWE-345/CWE-353  | VULNERABLE     |
| `tls_verification_disabled`        | 关闭 TLS 证书/主机名校验              | CWE-295          | VULNERABLE     |
| `jwt_none_or_signature_disabled`   | JWT `alg=none` / 关闭签名校验         | CWE-347          | VULNERABLE     |
| `unknown_crypto_semantics`         | 语义未知（fail-closed 兜底）          | （无）           | NEEDS_REVIEW   |
| `parametric_crypto_material`       | 材料来自参数（调用者决定）            | （无）           | POLYMORPHIC    |
| `exported_crypto_material`         | 导出了密钥形材料（在调用点兑现）      | （无）           | POLYMORPHIC    |

### 一个最小的真实案例：AES-ECB + 硬编码密钥 vs AES-GCM

```python
# 易受攻击：ECB 模式 + 硬编码密钥 + 静态 IV
def encrypt_bad(data: bytes) -> bytes:
    key = b"0123456789abcdef"                      # 硬编码字面量密钥
    cipher = Cipher(algorithms.AES(key), modes.ECB())  # ECB:相同明文块→相同密文块
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()

# 安全：AES-GCM + CSPRNG 密钥 + 每次新鲜的 nonce
def encrypt_good(data: bytes) -> bytes:
    key = AESGCM.generate_key(bit_length=256)      # 来自 CSPRNG
    nonce = os.urandom(12)                          # 每次调用新鲜随机
    return nonce + AESGCM(key).encrypt(nonce, data, None)
```

- `encrypt_bad` 命中 `ecb_mode`（VULNERABLE）和 `hardcoded_key_or_secret`（VULNERABLE）。
- `encrypt_good` 用 AEAD 模式（GCM）、密钥来自 CSPRNG、nonce 每次新鲜随机 → SAFE。

### 句法子类 vs 语义子类：本插件价值的分水岭

注意上面两类发现的**确定性程度完全不同**，这条分界线在第 4 节会再次出现：

- **句法子类（high-confidence pattern catch）**：ECB 模式、`alg=none`、`DES(...)` 这类。
  它们几乎只看「调用了什么 API / 传了什么常量」，一个普通 linter / 正则就能高准确地抓到。
  在 `_RED_FLAG_TO_FINDING`（`src/crypto_reasoner.py:455`）里，LLM 直接以 `red_flags` 标出这些
  句法命中。
- **语义子类（需要理解来源 / 时序）**：
  - **IV/nonce 是否新鲜？**——同一个 `os.urandom(12)` 放在循环外（复用）还是循环内（每次新鲜）
    含义截然相反。
  - **密钥来自 CSPRNG 还是字面量？**——要追踪 `key` 这个变量到底从哪来。
  - **验签结果在信任数据前被检查了吗？**——这是一个**时序 / typestate** 性质，不是看一行代码
    能定的。

LLM 的真正增量在**语义子类**；句法子类是「顺手也能报」，但并非它的核心价值。

---

## 2. 理论原理：CrySL 风格的「操作 + provenance + 时序」

### 2.1 CrySL：一条加密规则由三部分组成

理论来源是 **CrySL**（Krüger et al., *CrySL: An Extensible Approach to Validating the Correct
Usage of Cryptographic APIs*, ECOOP 2018）。一条 CrySL 规则刻画一个加密对象的**正确用法**，包含：

1. **算法 / 模式约束（CONSTRAINTS）**：例如「AES 模式不得为 ECB」「RSA 密钥 ≥ 2048 位」。
2. **顺序 typestate（ORDER）**：例如「`verify()` 必须在使用被验数据**之前**返回真」——这是一个
   对操作**调用次序**的约束。
3. **材料来源（PROVENANCE）**：例如「密钥必须来自 `generate_key()`，不能是字面量」。

### 2.2 加密没有「sink」：操作本身就是 locus

这是 Crypto 插件与 Taint 的关键区别（`crypto_prompts.py:6` 与 `crypto_reasoner.py:13` 都强调
了这点）：**污点分析有「source → sink」的数据流**，漏洞在 sink 处兑现；而加密误用**没有**这种
流——**加密操作本身就是判定的位点（the operation is the locus）**。一次 `AES(key).encrypt(...)`
是对是错，取决于这次操作的算法、模式、密钥来源、nonce 来源，而不取决于密文「流到了哪」。

verify-before-trust 则是一个**顺序 / typestate 性质**：不是「数据流到了危险的地方」，而是
「验证这个动作有没有在信任之前发生、且其结果支配（dominate）了后续使用」。

### 2.3 provenance 格（lattice）

LLM 不猜，只**按代码证据**标注材料来源。检查器据此裁决。三个核心 provenance 枚举
（`crypto_reasoner.py:43-55`）：

**密钥 `KEY_PROVENANCE`：**

| provenance              | 含义                                       | 检查器态度        |
| ----------------------- | ------------------------------------------ | ----------------- |
| `hardcoded_literal`     | 字面量密钥（`b"..."`）                     | VULNERABLE        |
| `from_csprng`           | 来自 `os.urandom` / `secrets` / `generate_key` | 可接受        |
| `from_kdf`              | 经 PBKDF2/scrypt/bcrypt/argon2/HKDF 派生   | 可接受            |
| `from_password_no_kdf`  | 口令直接当密钥（无 KDF）                    | VULNERABLE        |
| `from_param`            | 来自函数参数（调用者决定）                  | POLYMORPHIC       |
| `from_config_or_env`    | 来自 `os.environ` / 配置                   | 可接受            |
| `unknown`               | 看不出来                                   | NEEDS_REVIEW      |

**IV/nonce `IV_NONCE_PROVENANCE`：**

| provenance              | 含义                         | 检查器态度          |
| ----------------------- | ---------------------------- | ------------------- |
| `fresh_random_per_call` | 每次调用新鲜随机             | 可接受（需 CSPRNG） |
| `constant_or_literal`   | 常量 / 字面量                | VULNERABLE          |
| `reused_across_calls`   | 跨调用复用                   | VULNERABLE          |
| `counter`               | 计数器                       | 需 `uniqueness_guarantee=true` 否则 NEEDS_REVIEW |
| `from_param`            | 来自参数                     | POLYMORPHIC         |
| `unknown`               | 看不出来                     | NEEDS_REVIEW        |

**随机性来源 `RANDOMNESS_SOURCE`：** `csprng`（`secrets`/`os.urandom`）vs `insecure_prng`
（`random.*`/`Math.random`/`java.util.Random`）vs `unknown` / `not_applicable`。

### 2.4 POLYMORPHIC 从何而来

当密钥或 IV 的 provenance 是 `from_param` 时，这个函数**自身无法定论**——安不安全取决于调用者传
进来什么。检查器此时既不报 VULNERABLE 也不报 SAFE，而是判 **POLYMORPHIC**（`_check_key`
`crypto_reasoner.py:203`，`_check_nonce_required` `:229`）：它是「参数化」的，真正的裁决推迟到
调用点。这与 Taint 插件里参数化 sink 的 POLYMORPHIC 是同一个设计思想。

### 2.5 Fail-closed：未知即保守

凡是 LLM 标了 `unknown`（算法未知、provenance 未知、verify 支配关系未知），检查器一律判
**NEEDS_REVIEW**，**绝不**默默判 SAFE（`crypto_prompts.py:104` 的 FAIL-CLOSED 指令 +
检查器里大量 `unknown_crypto_semantics` 分支）。LLM 抽象失败、JSON 解析失败、枚举越界，则直接
`ERROR`（`validate()` `crypto_reasoner.py:110`，`make_error_facts` `crypto.py:114`）。

### 2.6 WEAK 与 VULNERABLE 的区别

- **VULNERABLE**：实践中可被利用的明确误用——ECB、硬编码密钥、静态/复用 nonce、口令快哈希、
  验签未检查、TLS 关校验、JWT none。
- **WEAK**：弱但不一定即刻可利用——例如 MD5/SHA1 用于一般「安全」用途（非口令存储）、RSA 密钥
  在 1024~2048 之间、PBKDF2 迭代数 < 100000、bcrypt cost < 10。

裁决取**优先级最高**的那一档（`_PRECEDENCE` `crypto_reasoner.py:34`）：

```
ERROR > VULNERABLE > WEAK > POLYMORPHIC > NEEDS_REVIEW > SAFE
```

---

## 3. 插件运行流程（与 SPI 集成）

### 3.1 LLM 抽象步：产出 `[CRYPTO_JSON]`

`build_abstraction_prompt`（`crypto.py:86`）给每行源码编号，拼上系统提示词
（`_system_prompt`）与用户提示词（`_user_prompt`），并把已分析的 callee 摘要注入
`callee_context`。LLM 返回一个包在 `[CRYPTO_JSON] ... [/CRYPTO_JSON]` 里的 JSON 对象，由
`_extract_crypto_json`（`crypto_prompts.py:40`）抽出。其骨架（`crypto_prompts.py:128` schema）：

```json
{
  "schema_version": "crypto_v1",
  "crypto_operations": [
    {"id": "op_1", "kind": "encrypt", "purpose": "security",
     "algorithm": "AES", "mode": "ECB",
     "key": {"provenance": "hardcoded_literal", "length_bits": 128,
             "source": {"kind": "literal"}, "evidence": "key = b'0123...'"},
     "iv_nonce": {"provenance": "constant_or_literal", "randomness_source": "not_applicable"},
     "evidence": "Cipher(algorithms.AES(key), modes.ECB())"}
  ],
  "verify_events": [
    {"id": "verify_1", "verify_kind": "signature",
     "status": "not_checked", "evidence": "sig = sign(...); use(payload)"}
  ],
  "returns": [
    {"id": "ret_1", "material_kind": "key", "provenance": "hardcoded_literal",
     "source": {"kind": "literal"}, "evidence": "return b'0123...'"}
  ],
  "red_flags": [
    {"kind": "ecb_mode", "operation_id": "op_1", "evidence": "modes.ECB()", "reason": "ECB"}
  ]
}
```

提示词关键约束：LLM **只报事实与证据，不下判决**；按**代码证据**（不是变量名）认 provenance；
看不出来的一律写 `unknown`（`crypto_prompts.py:104`）。

### 3.2 `check`：表驱动逐操作规则 + verify-before-trust

`check`（`crypto.py:212`）把 payload 交给 `classify`（`crypto_reasoner.py:471`），后者：

1. 对每个 `crypto_operation`，按 `kind` 走 `_OP_DISPATCH`（`crypto_reasoner.py:437`）分派到对应
   检查器：`_check_encrypt` / `_check_decrypt` / `_check_hash` / `_check_password_hash` /
   `_check_key_derivation` / `_check_random` / `_check_sign_or_mac` / `_check_tls_config` /
   `_check_jwt_decode` / `_check_key`。算法名先经 `_norm`（`:96`）规范化（大写、去库前缀、去
   标点，`AES.MODE_GCM → GCM`），再查 `BROKEN_CIPHERS` / `WEAK_HASHES` / `AEAD_MODES` /
   `DENIED_MODES` 等表。
2. 对每个 `verify_event` 调 `_check_verify_event`（`:425`）：只有 `checked_and_dominates_use`
   放行；`not_checked` / `ignored_or_swallowed` / `checked_but_does_not_dominate_use` 一律
   `verify_not_checked`（VULNERABLE）；`unknown` → NEEDS_REVIEW。
3. 处理 `returns` 中导出的密钥形材料（POLYMORPHIC，见 3.3）。
4. 收编 LLM 直接给出的 `red_flags`（去重后补进发现）。
5. 按 `_PRECEDENCE` 取最高档作为裁决。

### 3.3 `compose_calls`：自底向上把 callee 的 return-provenance 兑现到调用者

加密事实大多是**操作局部**的，唯一的跨函数情形是：**密钥/IV 材料经一个辅助函数的返回值流进
调用者**。这就是 `compose_calls`（`crypto.py:132`）要解决的。

辅助函数 `make_key()` 若返回一个硬编码密钥，它**自身**只是 POLYMORPHIC（它只是「导出了密钥形
材料」，并没有在本地把它当密钥用——见 `classify` 里对 `returns` 的处理 `crypto_reasoner.py:493`
和提示词末尾 `crypto_prompts.py:188` 的明确要求）。但**一旦调用者把这个返回值当密钥用**，调用者
就该是 VULNERABLE。

机制：调用者的 `op.key`（或 `op.iv_nonce`）若 `source.kind == "call_return"`，
`compose_calls` 会：

1. 从 `resolved_calls` 收集每个 callee 的 `returns[]`（仅 status=ok 的）。
2. 找到对应 callee 的返回材料，调 `instantiate_return_material`（`crypto_reasoner.py:527`）把
   callee 的 return-provenance 解析进调用者的材料：
   - `hardcoded_literal` / `from_csprng` / `from_kdf` 等**直接透传**；
   - 若 callee 返回的是 `from_param`，再顺着调用者实参（`actual_args`）的 `source_kind` 继续
     解析（`literal → hardcoded_literal`，`param → from_param`，`config_or_env →
     from_config_or_env`，否则 `unknown`）。
3. 对 `iv_nonce` 还要把「密钥风格」的 provenance 词汇映射到 IV 词汇（`hardcoded_literal →
   constant_or_literal`，`crypto.py:189`）。

解析后的材料写回 `op`，调用者再跑 `check` 时就会基于**真实来源**判级。

### 3.4 端到端示例

把几类典型函数串起来看（编号与 issue 描述对齐）：

```python
# f1: AES-ECB —— VULNERABLE / ecb_mode
def f1(data, key):
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(data)

# f2: 硬编码密钥 —— VULNERABLE / hardcoded_key_or_secret
def f2(data):
    key = b"0123456789abcdef"
    nonce = os.urandom(12)
    return AESGCM(key).encrypt(nonce, data, None)

# f5: 用 MD5 存口令 —— VULNERABLE / password_fast_hash
def f5(password):
    return hashlib.md5(password.encode()).hexdigest()

# f6: AES-GCM + 新鲜 nonce + CSPRNG 密钥 —— SAFE
def f6(data):
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return AESGCM(key).encrypt(nonce, data, None)

# f8a: 辅助函数返回硬编码密钥 —— 自身 POLYMORPHIC
def f8a():
    return b"0123456789abcdef"

# f8b: 用 f8a 的返回值当密钥 —— 经组合后 VULNERABLE
def f8b(data):
    key = f8a()
    nonce = os.urandom(12)
    return AESGCM(key).encrypt(nonce, data, None)
```

- **f1 VULNERABLE**：`_check_encrypt` 见 `mode == ECB ∈ DENIED_MODES` → `ecb_mode`。
  （`key` 来自参数会另报 POLYMORPHIC，但 VULNERABLE 优先级更高，裁决 = VULNERABLE。）
- **f2 VULNERABLE**：`key.provenance = hardcoded_literal` → `hardcoded_key_or_secret`。
- **f5 VULNERABLE**：`kind=hash` 且 `purpose=password_storage`，`MD5 ∈ FAST_PASSWORD_HASHES`
  → `password_fast_hash`（`_check_hash` `crypto_reasoner.py:293`）。
- **f6 SAFE**：GCM ∈ `AEAD_MODES`，nonce `fresh_random_per_call` + CSPRNG，密钥
  `from_csprng` → 无发现 → SAFE。
- **f8a POLYMORPHIC**：它只在 `returns` 里导出了 `material_kind=key, provenance=hardcoded_literal`，
  本地没把它当密钥用 → `exported_crypto_material`（POLYMORPHIC）。它的 callee 摘要形如：

  ```json
  {"returns": [{"id": "ret_1", "material_kind": "key",
                "provenance": "hardcoded_literal", "source": {"kind": "literal"}}]}
  ```

- **f8b VULNERABLE（经组合）**：分析 f8b 时，它的 `op.key.source.kind == "call_return"`（指向
  f8a）。`compose_calls` 取出 f8a 的 `returns`，`instantiate_return_material` 把
  `hardcoded_literal` 透传进 f8b 的 `key.provenance`。f8b 再跑 `check` →
  `hardcoded_key_or_secret`（VULNERABLE）。硬编码密钥的危害在**调用点兑现**，组合发生在调用边上。

---

## 4. 我们的方案 vs 传统（非 LLM）方案

传统加密误用 / 密钥泄露检测的代表：

- **CrySL / CogniCrypt_SAST**：把 CrySL 规则**编译**成一个流敏感的 typestate 分析（底层用
  IDEal 求解器），按规则检查算法约束、调用顺序、材料来源。
- **CryptoGuard**：针对 Java 的一组数据流 slice 规则，专攻硬编码密钥、ECB、静态 IV 等。
- **Semgrep crypto rules**：句法 / 轻量数据流的规则集。
- **密钥扫描器（GitGuardian / TruffleHog）**：用熵 + 正则专扫硬编码 secret。

### 我们的优势

- **语义识别 provenance，无需手写 CrySL 规则**。「这个 IV 是不是复用了？这个密钥是不是来自
  CSPRNG？」——LLM 直接按代码语义判断，不必为每条规则写 CrySL `ENSURES`/`REQUIRES`。
- **天然处理 verify-before-trust 的时序**。「验签结果在使用被验数据之前被检查并支配了吗」本是
  典型的 typestate 性质，LLM 读代码即可识别非支配情形（结果被忽略、异常被吞、失败路径继续往下
  走），无需把它编码成显式 typestate 自动机。
- **跨库 / 跨框架，无需逐 API 规约**。不依赖针对每个加密库手写的 API 模型，自研封装也能读懂。
- **模块化组合**：逐函数抽象 + 自底向上 return-provenance 实例化，天然跨函数复用 callee 事实。

### 我们的劣势（需诚实对待）

- **句法命中其实 linter 更划算**。ECB、`alg=none`、`DES(...)` 这类**句法子类**，一个正则 /
  Semgrep 规则又快又准，LLM 在这里只是**徒增成本**——本插件的真正增量在语义子类（见 §1）。
- **provenance 藏在封装背后 → NEEDS_REVIEW**。若密钥/IV 经过多层 wrapper、动态分发、配置注入，
  LLM 看不穿来源就只能 fail-closed 判 NEEDS_REVIEW，需要人工接力。
- **KDF 参数充分性依赖库默认值**。PBKDF2 迭代数、bcrypt cost 若没写在代码里（用了库默认），LLM
  未必看得到，检查器只能判 NEEDS_REVIEW（`_check_password_hash` 里 `iterations is None` 的分支）。
- **用途歧义（purpose ambiguity）**。MD5 用作 ETag / 去重键并非漏洞。检查器靠 `purpose`
  字段区分（`checksum_nonsecurity` 不报；`unknown` 转 NEEDS_REVIEW），但这个用途判断本身落在
  LLM 身上——它若误判用途，结论也会随之偏。
- **不可靠（unsound）**：基于 LLM 抽象，没有可靠性保证，会漏报。

**句法 vs 语义的价值切分要说清楚**：在句法子类上，传统 linter 更便宜、更可靠；本插件的价值集中
在**语义子类**（来源追踪、新鲜性、验签时序）和**跨函数组合**上。

---

## 5. 局限与适用场景

- **适用**：在大型 / 陌生 / 多语言混杂代码库上做加密误用的**广撒网式初筛**；识别 POLYMORPHIC
  的「密钥/IV 工厂」辅助函数，提示「调用点才是危险所在」；确认 AEAD + 新鲜 nonce + CSPRNG 密钥
  这类**正向安全事实**（SAFE 是可被肯定的）。
- **不适用 / 慎用**：作为合规级别的 sound 证明；依赖它的「无报告」断言代码加密无误（unsound，
  会漏）；判断 KDF 参数是否够强（依赖看不见的库默认值）；以及在纯句法误用上替代更便宜的 linter。

把 Crypto 插件当作一个**会读语义、能跨函数组合、失败即保守**的加密误用探针——它的结论是有用的
线索与正向佐证，但句法层面交给 linter 更划算，最终安全结论仍需人工复核。
