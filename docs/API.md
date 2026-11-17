# API

## Python SDK

```python
from phi_core import (
    evaluate, PhiEngine, Verdict,                     # Φ
    PhiGate, GateSession, GatedRunner, HarnessAdapter, Step,
    GateBlocked, GateNeedsEvidence, DecisionInvalid, GateSequenceError, EvidenceProviderError,
    TrustStore, make_evidence, sign_evidence, observe_files, verify_evidence,
    PredicateRegistry, FunctionPredicate, StatePredicate, EvidencePredicate, default_predicate_registry,
    VerifierRegistry, default_verifier_registry,
    AuditLog, replay_record, replay_log, compare_versions, trace_evidence, reconstruct_state_history,
    run_acceptance, make_anchor_entry, new_revision, baseline_hash,
    validate_contract, seal_contract, contract_hash, compile_constraints,
)
```

### Φ

```python
r = evaluate(contract, state, evidence, checkpoint="DISPATCH",
             workspace="path/to/ws", trust_store=TrustStore.load("trust.json"))
r.verdict            # Verdict.TRUE | FALSE | UNKNOWN
r.release            # True only for TRUE
r.action             # PROCEED | BLOCK | PAUSE_REQUEST_EVIDENCE
r.reason_codes       # sorted tuple of codes
r.constraint_results # per hard constraint: status, reason_codes, evidence_refs, detail
r.soft_results       # reported only
r.missing_evidence   # hard constraints that need (more/fresh/consistent) evidence
r.to_dict()          # JSON-serialisable

engine = PhiEngine(predicates=my_registry, verifiers=my_verifiers)
vres = engine.verify(state, evidence, workspace=ws, trust_store=trust)  # impure stage
r = engine.judge(contract, state, vres, checkpoint="COMMIT")            # pure stage
plan = engine.evaluate_plan([c1, c2, c3], state, evidence, workspace=ws)
```

### 门禁

```python
gate = PhiGate(workspace=ws, trust_store=trust, audit_log=AuditLog("audit.jsonl"))
decision = gate.check("STEP", contract, state, evidence)           # evaluate + audit
decision, value = gate.guard("STEP", contract, state_fn, evidence_fn, action)  # action only on TRUE
gate.authorize(decision, contract, state, evidence)                # re-evaluates; raises DecisionInvalid if stale/forged

session = GateSession(gate, contract_or_fn)
session.preflight(state_fn, evidence_fn, action=None)   # PLAN then DISPATCH; pins contract hash
session.step(state_fn, evidence_fn, action)             # requires released preflight
session.commit(state_fn, evidence_fn, action)
```

`state_fn` / `evidence_fn` 可以是可调用对象，门禁在评估时才调用，保证使用最新输入。`evidence_fn` 只要**能**接收检查点就会收到它，
与参数是否有默认值无关：

| provider 签名 | 调用方式 |
| --- | --- |
| 有任一位置参数（必需或有默认值，含仅位置参数）或 `*args` | `evidence_fn(checkpoint)` |
| 只有关键字参数且其中有 `checkpoint`（必需或有默认值），或有 `**kwargs` | `evidence_fn(checkpoint=checkpoint)` |
| 无任何参数 | `evidence_fn()`（兼容旧 provider） |
| 只有其他名字的仅关键字参数，或签名无法检查 | 抛出 `EvidenceProviderError`（`TypeError` 子类），不放行 |

可调用对象按其 `__call__` 签名、`functools.partial` 按剩余参数判断。provider 抛出的异常原样传播，当前及后续动作都不执行。

### Harness Adapter

```python
class MyAdapter(HarnessAdapter):
    def load_contract(self): ...
    def observe_state(self): ...
    def collect_evidence(self, checkpoint): ...
    def plan_steps(self): return [Step("build", build_fn), Step("test", test_fn)]   # 宿主决定分解
    def commit(self): ...

report = GatedRunner(gate, MyAdapter()).run()   # status: COMPLETED | BLOCKED | PAUSED
```

`GatedRunner` 在 PLAN、DISPATCH、每个 STEP、COMMIT 分别调用 `collect_evidence(checkpoint)`。

完整可运行示例：`examples/minimal_harness/harness.py`。

## CLI

| 命令 | 说明 | 退出码 |
| --- | --- | --- |
| `phi validate FILE [--kind contract\|state\|evidence\|baseline\|anchor\|delivery]` | 结构验证 | 0 合法 / 1 不合法 / 2 读取错误 |
| `phi hash FILE [--kind contract\|baseline\|json]` | 规范 SHA-256 | 0 |
| `phi seal FILE [-o OUT]` | 写入 `integrity.contract_hash` | 0 |
| `phi evaluate (--request R \| --contract --state --evidence) [--checkpoint] [--workspace] [--trust] [--audit] [--output]` | Φ 裁决，JSON 输出到 stdout | 0 TRUE / 10 FALSE / 20 UNKNOWN / 2 用法错误 |
| `phi plan --contracts C... --state S --evidence E [--workspace] [--trust]` | 计划级裁决 | 同上 |
| `phi gate-exec <evaluate 输入> -- CMD ...` | 仅 TRUE 时执行 CMD（不经 shell）；裁决 JSON 输出到 stderr | 执行时为 CMD 退出码，否则 10/20 |
| `phi audit verify LOG [--anchor-seq N --anchor-hash H]` | 链校验 | 0 / 1 |
| `phi audit replay LOG [--reverify --workspace --trust]` | 重放全部评估记录（先校验链） | 0 全部一致 / 1 |
| `phi audit trace LOG EVIDENCE_ID` / `states LOG [--task-id]` / `head LOG` | 证据追踪 / 状态重建 / 头哈希 | 0 |
| `phi accept --baseline --anchor --delivery --workspace --now [--trust] [--require-signed-anchor] [--audit] [--output]` | 独立验收 | 0 PASS / 30 FAIL / 40 INCONCLUSIVE |
| `phi evidence observe --contract --workspace --now [--checkpoint]` / `sign FILE --trust --key-id` | 生成绑定到契约任务（可选再绑定检查点）的文件证据声明 / HMAC 签名 | 0 |

## JSON 协议

请求（`--request`，或 `-` 从 stdin 读取）：

```json
{"protocol": "phi-core/1.0", "checkpoint": "DISPATCH",
 "contract": {...}, "state": {...}, "evidence": [...], "workspace": "optional/path"}
```

响应：`{"protocol": "phi-core/1.0", "verdict": "...", "release": bool, "action": "...", ...}`，
字段见 [SPECIFICATION.md §6](../SPECIFICATION.md)。任何语言都可以通过子进程 + JSON 调用。

## Acceptance

```python
report = run_acceptance(baseline, anchor, delivery, workspace=ws, now="2026-11-17T00:00:00Z",
                        trust_store=trust, require_signed_anchor=True)
report["status"]              # PASS | FAIL | INCONCLUSIVE
report["requirement_results"] # 追踪矩阵：requirement_id, method, delivered_artifacts, status, reason_codes, detail
report["design_deviation"]    # denominator, deviated, unknown, rate_lower, rate_upper
report["phi_verdict_consulted"]  # always False
```

验证方法（只在冻结基线中定义）：

| method | 行为 | 结果 |
| --- | --- | --- |
| `file` | 工作区文件存在，可选 sha256 | PASS / FAIL |
| `command` | `argv`（不经 shell，`{python}` 替换为当前解释器），超时；`pinned_files[{path, sha256}]` 是标准文件，工作区内被执行的程序必须在其中；`artifacts[relpath]` 只豁免 `{python}` 程序的数据参数；命令在工作区外的私有快照中运行，标准文件写入的是已核对的字节（见安全边界 2.7） | 期望退出码 PASS / 其他 FAIL / 冻结文件缺失或被改（运行前、运行中、快照中）FAIL / 程序未冻结、数据参数未冻结也未声明、路径逃逸或别名 INCONCLUSIVE / 超时或无法运行 INCONCLUSIVE |
| `json_schema` | 工作区 JSON 符合**冻结**的工作区 Schema（`schema_sha256`，引用文件 `schema_refs`），引用解析不访问网络或工作区外 | PASS / 不符合或冻结字节被改 FAIL / 未冻结、引用不可解析、Schema 缺失 INCONCLUSIVE |
| `evidence` | 交付报告中的证据经 Evidence Verifier 验证，`binding.baseline_id` 为本基线（可选 `baseline_revision` / `requirement_id`），值与 `expected` 相等 | PASS / FAIL / 缺失、未绑定、绑定到其他基线或冲突 INCONCLUSIVE |
| `manual`, `llm_judgment` | 不可自动判定 | 永远 INCONCLUSIVE |

需求变更：`new_revision(old, requirements=..., summary=..., frozen_at=...)` 生成新修订（记录增删改），
必须由验收方用 `make_anchor_entry` 追加到锚中后才有效；旧修订随即 `BASELINE_REVISION_SUPERSEDED`。

锚条目只接受具有 `baseline-anchor` 用途的密钥签名（`TrustStore.add_key(..., purposes=["baseline-anchor"])`，
trust JSON 中 `"purposes": ["baseline-anchor"]`）。用途缺省为 `["evidence"]`，因此证据密钥不能批准需求变更。

## 1.0.1 协议变化（不兼容）

1.0.1 修复独立测试（963d12b）报告的 6 个缺陷。以下变化会让按 1.0.0 写法的输入得到不同结果；
都是有意的收紧，结果只会从 TRUE/PASS 变为 UNKNOWN/INCONCLUSIVE/FALSE/FAIL，不会反向。

| 变化 | 1.0.0 行为 | 1.0.1 行为 | 迁移 |
| --- | --- | --- | --- |
| 输出 Schema 必须冻结 | 工作区 Schema 当时的内容即标准 | 无 `schema_sha256` → UNKNOWN `SCHEMA_CRITERION_NOT_PINNED`；字节变化 → FALSE `SCHEMA_CRITERION_MODIFIED` | 契约 `outputs[].schema_sha256`（引用文件加 `schema_refs`） |
| 验收 Schema 必须冻结 | 同上 | 无 `schema_sha256` → INCONCLUSIVE；字节变化 → FAIL | 基线 `verification.schema_sha256` / `schema_refs` |
| `$ref` 解析 | jsonschema 默认可经网络或 `file://` 取回；坏 https 在验收中抛异常 | 只解析片段、工作区相对文件与本地元 Schema；其他 → UNKNOWN/INCONCLUSIVE `SCHEMA_REF_UNRESOLVABLE`，不抛异常 | 把被引用 Schema 放进工作区并冻结 |
| 验收命令引用工作区文件 | 只冻结 argv 文本 | argv 中的工作区文件必须在 `pinned_files` 或 `artifacts` 中，否则 INCONCLUSIVE；冻结文件缺失/被改 → FAIL | 在基线中列出 `pinned_files`（脚本、配置），被检交付物列入 `artifacts` |
| 锚签名密钥 | 任何已登记密钥 | 仅 `baseline-anchor` 用途；缺省用途为 `evidence` | trust JSON 为验收权威密钥加 `"purposes": ["baseline-anchor"]` |
| 签名证明需绑定 | 只校验签名 | 无 `binding` → UNKNOWN `EVIDENCE_NOT_BOUND_TO_TASK`；绑定其他任务/契约/检查点 → 不使用 | `make_evidence(..., binding={"task_id": ...})` 后再签名；验收证据用 `{"baseline_id": ...}` |
| `observe_files` | 无绑定 | 自动 `binding={"task_id": contract.task_id}`，可加 `checkpoint=` | 无需改动 |
| 证据 provider | 预检时只用 DISPATCH 证据 | 接受参数的 provider 按检查点调用 | 无需改动；需要区分检查点的适配器可直接使用参数 |
| 版本号 | `phi-core/1.0.0` | `phi-core/1.0.1`、`phi-core-acceptance/1.0.1` | 回放 1.0.0 审计记录时 `replayed_evaluator_version` 会不同 |

新增导出：`check_document`、`pin_issue`、`SchemaCheck`、`PURPOSE_EVIDENCE`、`PURPOSE_BASELINE_ANCHOR`。
自定义验证器若其观测值完全由验证器在工作区重新计算，可声明类属性 `reobserves = True`，其证据无需绑定；否则必须绑定。

## 1.0.2 协议变化（不兼容）

1.0.2 修复独立复测（6bca32e）报告的 4 个缺陷。结果只会从 PASS/COMPLETED 变为 INCONCLUSIVE/FAIL/BLOCKED，或使 provider 收到之前漏传的检查点。

| 变化 | 1.0.1 行为 | 1.0.2 行为 | 迁移 |
| --- | --- | --- | --- |
| 程序与数据分角色 | `artifacts` 覆盖到的任何 argv 文件都免冻结，包括被执行的脚本本身 | 工作区内被执行的程序（`{python}` 脚本/目录、`-m` 可加载的模块文件及其包 `__init__`/`__main__`、无扩展名或已编译模块、工作区内的 `argv[0]`）必须在 `pinned_files` 中，`artifacts` 不豁免；`artifacts` 只豁免 `{python}` 程序的数据参数；非 `{python}` 程序的 argv 中所有工作区文件都必须冻结 | 把检查脚本/模块列入 `pinned_files`；非 Python 工具的被检数据改由冻结的 `{python}` 包装脚本读取 |
| 路径失败即关闭 | 解析到工作区外的符号链接被当作非工作区参数放行 | argv/`-m`/`--opt=` 中经符号链接或目录链接解析到工作区外、悬空或循环的链接、相对 `..` 逃逸 → INCONCLUSIVE `COMMAND_PATH_ESCAPES_WORKSPACE`；指向工作区的绝对路径（含工作区外指回来的别名、逐级解析时经过工作区的宿主路径）→ INCONCLUSIVE `COMMAND_ABSOLUTE_WORKSPACE_PATH`；不读取外部目标内容 | 在 argv 中使用工作区相对路径 |
| 快照复核与模块遮蔽 | 无 | 角色在快照上复核（复制期间新增 → `COMMAND_WORKSPACE_FILE_NOT_PINNED`，`changed_while_snapshotting`）；`sys.path` 首目录中未冻结且遮蔽标准库/已安装模块的文件或包 → INCONCLUSIVE `COMMAND_WORKSPACE_SHADOWS_MODULE`（`-I`/`-P` 时不检查） | 冻结确需提供的同名模块，或用 `-I` 运行 |
| PATH | 宿主 PATH 原样传入 | 删除空项、相对项以及位于工作区内的项；裸程序名在清理后的 PATH 上解析为绝对路径，解析到工作区内 → INCONCLUSIVE `COMMAND_PROGRAM_IN_WORKSPACE`；解释器在工作区内 → `COMMAND_INTERPRETER_IN_WORKSPACE` | 无 |
| 执行位置 | cwd = 工作区，运行前后比较 hash | cwd = 工作区外的私有快照（0700 临时目录）：工作区副本（不含 `__pycache__`、不含离开工作区的链接）+ 已核对的标准字节；运行后核对快照与工作区；命令新建或修改的非标准文件不跟随链接地写回工作区；stdin 为空 | 依赖在工作区写文件的检查器无需改动；依赖从工作区读取被排除内容（`__pycache__`、外链）的检查器需调整 |
| provider 检查点 | 只看必需位置参数个数，`checkpoint="DISPATCH"` 之类的默认参数永远拿到默认值 | 见上文 provider 签名表；签名不可判定 → `EvidenceProviderError` | 无需改动 |
| 版本号 | `phi-core/1.0.1` | `phi-core/1.0.2`、`phi-core-acceptance/1.0.2` | 回放旧记录时 `replayed_evaluator_version` 不同 |

新增：模块 `phi_core.command`（验收命令协议），导出 `EvidenceProviderError`。`command` 结果 `detail` 新增 `execution`
（`cwd`、`program`、`argv_roles`、`files_copied`、`omitted_links_leaving_workspace`、`skipped`、`outputs_written_back`、
`outputs_not_written_back`）；`COMMAND_WORKSPACE_FILE_NOT_PINNED` 的 `detail` 新增 `program_not_pinned`、`data_not_pinned_or_declared`。
