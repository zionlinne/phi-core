# 可信边界与安全限制

本文件说明 phi-core **能**保证什么、**不能**保证什么。任何超出下述范围的声明都不成立。

## 1. 库能保证的（并有测试）

| 保证 | 机制 | 测试 |
| --- | --- | --- |
| 只有 TRUE 放行；FALSE/UNKNOWN 时受支持入口不调用动作 | `PhiGate.guard`、`GateSession`、`GatedRunner`、`phi gate-exec` | `test_T_*`、`test_J_*`、`test_K_*`、`test_gate_exec_runs_only_on_true` |
| 动作前使用最新 S/E 重新评估，不复用旧裁决 | provider 在评估时调用；`authorize` 重新评估并比对 hash | `test_N_*`、`test_guard_uses_latest_inputs_from_providers`、`test_S_*` |
| 伪造的 TRUE 决策对象无效 | 决策令牌 = 每个 gate 独有密钥上的 HMAC | `test_O_agent_bypass_attempts` |
| 调用方自报 `verification_status` 不被信任 | 只记录为 `claimed_status` | `test_caller_claimed_status_is_never_trusted`、`test_F_*` |
| 调用方自算 hash 不被信任 | 文件验证器自行重新计算 | `test_file_verifier_recomputes_hash`、`test_L_*`、`test_K_*` |
| 无注册验证器的证据不可信 | UNVERIFIABLE | `test_F_*` |
| 不执行任意代码/自然语言 | 无 eval/exec；不可执行谓词 → UNKNOWN | `test_G_*`、`test_no_fbs_llm_or_cloud_imports_in_package` |
| 契约中途被改 → 不放行 | 会话钉扎 + 可选自哈希 | `test_M_*` |
| 验收基线被生产者修改/删需求 → 不 PASS | 独立锚（可签名） | `test_P_*`、`test_Q_*` |
| 审计记录被编辑/删除/插入/重排 → 可检测（相对已知头哈希） | SHA-256 链 + 快照 hash | `test_tamper_detection`、`test_snapshot_tamper_*` |

## 2. 库不能保证的（明确的边界）

### 2.1 进程内门禁 ≠ OS 级隔离

phi-core 是 Python 库。它**无法阻止**不经过它的代码：同进程的其他代码、其他线程、其他进程、
拥有文件写权限的用户或 Agent，都可以直接写文件或执行命令。`test_O_boundary_direct_write_outside_library_is_not_prevented`
明确演示了这一点：直接写入成功；库能做的只是在**下一个受支持的检查点**重新观测并发现不合规结果
（例如 COMMIT 时输出不符合 Schema → FALSE）。若产出内容恰好合规，绕过行为本身无法被库发现。

要获得真正的强制，宿主必须在 OS 层面隔离：例如 Agent 只能在沙箱/容器中运行，而唯一能产生副作用的通道是
宿主进程里经 `PhiGate.guard` 或 `phi gate-exec` 启动的动作；Agent 无权修改 phi-core、TrustStore、
审计日志与验收锚。

### 2.2 HMAC 签名的含义

`hmac_attestation` 只证明"签名者持有 TrustStore 中该共享密钥"。它**不**证明人的身份或作者身份；
任何拿到密钥的人（包括验证方本身，因为 HMAC 是对称的）都能产生有效签名；拥有宿主权限者可以读取密钥并伪造。
密钥必须经带外方式发放给宿主，绝不能放进证据或交给被检查的 Agent。`examples/trust.demo.json` 是公开演示密钥。

### 2.3 普通 hash 的含义

SHA-256 只检测"内容与某个已知 hash 是否一致"。它不证明作者，不防止拥有写权限的人同时改内容和 hash。
因此：契约 `integrity.contract_hash` 只能检测天真修改（能改契约的人也能重算它）；真正的防护来自
`GateSession` 在 preflight 时钉扎、由宿主持有的 hash。验收基线 hash 同理，真正的参照是**由验收方单独保管**的锚，
可加 HMAC 签名。

### 2.4 审计日志：防篡改证据，不是不可篡改

链式 hash 能检测相对于"已知可信头哈希"的任何修改。若没有外部锚，能写整个文件的人可以重写全部记录并重算整条链，
内部校验仍会通过（`test_full_rewrite_needs_external_anchor` 演示）。要防止这一点，需定期把 `phi audit head`
的输出保存到写入者无法修改的位置，并用 `phi audit verify --anchor-seq --anchor-hash` 校验。

### 2.5 状态 S 被信任

`S`（任务状态、资源、能力、文件归属、`now`）由宿主调度器提供，引擎把它当作事实。若宿主本身被攻破或提供了错误状态，
Φ 的结论随之错误。`now` 也是宿主提供的；库不访问墙钟，因此也无法发现宿主伪造时间。

### 2.6 能验证什么

phi-core 只验证**已注册谓词和验证器覆盖的内容**：文件存在/hash、JSON Schema 兼容、依赖状态、归属、资源、能力、
时间边界、HMAC 签名的声明值、以及宿主注册的确定性验证器。它不能验证任意现实世界事实，也不能判断"测试是否有意义"
等语义问题。无法确定性验证的约束一律 UNKNOWN。

### 2.7 验收命令的执行

`command` 方法会在工作区中执行**基线中冻结的** argv（不经 shell，环境只保留 PATH）。基线由验收方定义并锚定，
生产者无法改动；但命令本身运行在生产者产出的工作区上，宿主应在隔离环境中运行验收。

### 2.8 并发

`AuditLog.append` 使用线程锁和 POSIX `fcntl.flock`。多线程并发已测试；多进程并发写同一文件**未测试**；
非 POSIX 平台没有文件锁。
