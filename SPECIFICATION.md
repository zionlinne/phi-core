# phi-core 规格说明 v1.0

本文件描述 `phi-core 1.0.0`（`evaluator_version = "phi-core/1.0.0"`）**实际实现**的行为。
JSON Schema 位于 `schemas/`，是结构的规范来源。

## 1. 算子定义

```
Φ(T, S, E, checkpoint) → TRUE | FALSE | UNKNOWN
```

设 `H` 为契约 `T` 编译后、适用于 `checkpoint` 的**硬约束**集合，每个 `h ∈ H` 得到状态
`SATISFIED | VIOLATED | UNRESOLVED`。另有契约级前置条件 `G`（见 1.2）。

1. ∃h∈H: VIOLATED → **FALSE**（reason `VERIFIED_HARD_VIOLATION` + 具体原因）
2. 否则 ∃h∈H: UNRESOLVED，或 G 中任一项未满足 → **UNKNOWN**（reason `UNRESOLVED_REQUIRED` + 具体原因）
3. 否则 → **TRUE**（`ALL_REQUIRED_SATISFIED`；若 H 为空且范围显式完整，另加 `NO_APPLICABLE_HARD_CONSTRAINTS_SCOPE_DECLARED_COMPLETE`）

无加权、无概率、无模型调用。软约束（`kind: soft`）单独计算，放在 `soft_results`，不进入 H。
`release = (verdict == TRUE)`；`action`：TRUE→`PROCEED`，FALSE→`BLOCK`，UNKNOWN→`PAUSE_REQUEST_EVIDENCE`。

### 1.1 短路为 UNKNOWN 的输入问题（不评估约束）

| reason code | 条件 |
| --- | --- |
| `CONTRACT_SCHEMA_INVALID` | T 不是对象 / 版本不是 `1.0` / 不符合 v1 Schema |
| `CONTRACT_VERSION_UNSUPPORTED` | T 是旧的 `0.1-draft` |
| `CONTRACT_SEMANTIC_INVALID` | 自依赖、重复路径、重复约束 ID 等 |
| `CONTRACT_INTEGRITY_MISMATCH` | `integrity.contract_hash` 与重算值不符 |
| `STATE_SCHEMA_INVALID` | S 不符合 state v1 Schema（含 `now` 缺失或非法） |
| `CONTRACT_PIN_MISMATCH` | `S.contract_pins[task_id]` 存在且与当前契约 hash 不符 |
| `EVIDENCE_PAYLOAD_INVALID` | E 不是数组 |

这些情况下 T/S/E 本身不可信或不可解释，因此不给出 FALSE（FALSE 只表示已验证的硬约束违反）。

### 1.2 契约级前置条件 G（参与优先级，FALSE 仍优先）

- `TASK_NOT_IN_STATE`：`S.tasks` 中没有 `T.task_id`
- `SCOPE_NOT_DECLARED_COMPLETE`：`constraint_scope.complete` 不是 `true`。**未声明完整永不 TRUE**；显式声明完整的空集合可 TRUE。

## 2. 任务契约 T（`schemas/task_contract.v1.schema.json`）

字段：`contract_version="1.0"`、`task_id`、`title`、`objective`、`parent_task_id`、`subtasks`、
`dependencies`、`inputs[{path, sha256?}]`、`outputs[{path, owner?, sha256?, schema?}]`、
`capabilities`、`resources[{name, amount}]`、`time_bounds{not_before?, deadline?}`、
`constraints[]`、`constraint_scope{complete, declared_by?}`、`evidence_policy`、
`acceptance{baseline_id, ...}`（只是对独立验收基线的引用，Φ 不读取）、`integrity{contract_hash}`、`metadata`。

路径必须是工作区内相对路径（Schema 禁止绝对路径与 `..`；Verifier 再次解析并拒绝符号链接逃逸）。

### 2.1 约束编译（`contracts.compile_constraints`）

| 来源字段 | 约束 ID | 谓词 | 检查点 |
| --- | --- | --- | --- |
| dependencies[d] | `dep:<d>` | dependency_completed | DISPATCH, STEP, COMMIT |
| inputs[p] | `input:<p>:exists` | input_exists | DISPATCH, STEP, COMMIT |
| inputs[p].sha256 | `input:<p>:sha256` | file_hash | DISPATCH, STEP, COMMIT |
| outputs[p] | `output:<p>:ownership` | ownership（owner 默认 task_id） | DISPATCH, STEP, COMMIT |
| outputs[p] | `output:<p>:exists` | output_exists | COMMIT |
| outputs[p].sha256 | `output:<p>:sha256` | file_hash | COMMIT |
| outputs[p].schema | `output:<p>:schema` | schema_compatible | COMMIT |
| capabilities[c] | `capability:<c>` | capability | PLAN, DISPATCH |
| resources[r] | `resource:<r>` | resource_available | DISPATCH |
| time_bounds.deadline | `time:deadline` | deadline | DISPATCH, STEP, COMMIT |
| time_bounds.not_before | `time:not_before` | not_before | DISPATCH |
| constraints[i] | 自定义 ID | `predicate.type` | `checkpoints`（默认全部） |

### 2.2 内置谓词（`predicates.py`）

状态谓词（读取 S 的只读冻结视图）：

| 类型 | SATISFIED | VIOLATED | UNRESOLVED |
| --- | --- | --- | --- |
| dependency_completed | status=completed | failed / cancelled | 其他状态或缺失 |
| ownership | file_owners[path]=owner | 属于其他任务 | 未登记 |
| resource_available | 可用量 ≥ 需求 | 可用量 < 需求 | 未登记 |
| capability | 在 capabilities 中 | 不在且 capabilities_complete=true | 其他 |
| deadline | now ≤ deadline | now > deadline | — |
| not_before | now ≥ not_before | — | now < not_before |

证据谓词（只使用 VERIFIED 的验证器观测值）：

| 类型 | 默认验证器 | 判定 |
| --- | --- | --- |
| input_exists / output_exists | file_sha256 | 观测 exists=true / false |
| file_hash | file_sha256 | 观测 sha256 = 期望 / 不同或文件缺失 |
| schema_compatible | json_schema | 观测 valid=true / false 或文件缺失 |
| attested_value | hmac_attestation | 观测值与 `expected` 结构相等 / 不等 |

未注册类型 → UNRESOLVED `PREDICATE_NOT_EXECUTABLE`。`natural_language`、`llm`、`llm_judgment`、`free_text`
是保留的不可执行类型，不能被注册。参数不合法 → `PREDICATE_PARAMS_INVALID`；谓词抛异常或返回非 `Outcome` →
`PREDICATE_ERROR` / `PREDICATE_RESULT_INVALID`。任何字符串都不会被 eval/exec。

## 3. 状态 S（`schemas/state.v1.schema.json`）

`state_version="1.0"`、`now`（RFC 3339，**必须**带时区；引擎唯一时间来源）、`tasks{id:{status}}`、
`resources`、`capabilities`、`capabilities_complete`、`file_owners`、`contract_pins`、`extensions`。
S 由宿主维护并被引擎**信任**（见安全边界）。

## 4. 证据 E 与 Evidence Verifier

每条证据（`schemas/evidence.v1.schema.json`）：`evidence_id, constraint_id, source, verifier_id,
observed_value, verification_status, timestamp, artifact_hash, provenance`。

`verify_evidence` 独立判定每条证据为 `VERIFIED | REJECTED | UNVERIFIABLE`：

- 调用方的 `verification_status` 只记录为 `claimed_status`，**从不使用**。
- 格式错误 → REJECTED `MALFORMED_EVIDENCE`；重复 `evidence_id` → 全部 REJECTED。
- 时间戳晚于 `S.now` → REJECTED `TIMESTAMP_IN_FUTURE`；无可信时间 → UNVERIFIABLE。
- `verifier_id` 未注册 → UNVERIFIABLE `NO_REGISTERED_VERIFIER`；验证器异常/返回非法 → UNVERIFIABLE。
- `file_sha256`：在工作区内**重新读取并计算**文件 hash；调用方声明的 hash 不符 → REJECTED `ARTIFACT_HASH_MISMATCH`。
- `json_schema`：重新用工作区 Schema 校验工作区 JSON；声明与观测矛盾 → REJECTED。
- `hmac_attestation`：要求 TrustStore 中的密钥、该密钥被授权的 `source`、对除 `verification_status` 与
  `provenance.signature` 外全部字段的 HMAC-SHA256 签名；可选 `provenance.artifact_path` 重新 hash。

引擎在每个证据约束上再检查：验证器在允许列表（`constraint.evidence.verifiers` 或谓词默认）、
时效（`max_age_seconds`，默认 `evidence_policy.default_max_age_seconds`，再默认 3600）、
主体匹配（如路径一致）、数量（`min_items`，默认 1）。无可用证据 → `EVIDENCE_MISSING`。

**冲突**：同一约束的可用证据给出不同结论 → 默认 UNRESOLVED `EVIDENCE_CONFLICT`。唯一允许的裁决规则是契约中
预先声明的 `conflict_resolution: {type: "source_precedence", order: [...]}`：只看排名最高的来源；
该来源内部仍冲突则 UNRESOLVED。时间先后**从不**用于裁决（无 last-write-wins）。

## 5. 检查点与门禁

检查点：`PLAN`、`DISPATCH`、`STEP`、`COMMIT`。`PhiGate.guard` / `GateSession` 在每次动作前用**最新**
的 T/S/E 重新评估（含重新验证证据），只有 TRUE 才调用动作；FALSE 抛 `GateBlocked`，UNKNOWN 抛
`GateNeedsEvidence`。`GateSession.preflight` 依次检查 PLAN 与 DISPATCH，并把当时的契约 hash 钉扎到后续
检查点的 S 副本中。`Decision.token` 是对 (checkpoint, task, 三个 hash, verdict, 版本) 的 HMAC；
`authorize` 校验令牌并**重新评估**，任何 hash 或结论变化都拒绝（`STALE_DECISION`）。

计划级（`PhiEngine.evaluate_plan` / `phi plan`）：重复任务 ID、依赖环、父子不一致、多个任务声明同一输出
→ FALSE；未声明的依赖/父/子任务、空计划、契约无效 → UNKNOWN；再对每个任务做 PLAN 裁决。

Φ 只裁决，不替代宿主调度，不拆分任务，不调用模型。

## 6. 输出协议

`EvaluationResult.to_dict()`（CLI 输出另加 `"protocol": "phi-core/1.0"`）：
`verdict, release, action, checkpoint, task_id, contract_hash, state_hash, evidence_hash,
evaluator_version, reason_codes, constraint_results[], soft_results[], evidence_results[],
missing_evidence[], unmatched_evidence[]`。每个约束结果含 `status, reason_codes, evidence_refs, detail`。

哈希：`contract_hash` = 去掉 `integrity` 后的规范 JSON 的 SHA-256；`state_hash`、`evidence_hash` =
原始 S、E 的规范 JSON SHA-256。规范 JSON：键排序、无空白、UTF-8、禁止 NaN。

## 7. 审计日志（`audit.py`）

JSONL，每行一条，`record_hash = SHA256(规范JSON(记录去掉 record_hash))`，`previous_record_hash` 链接上一条，
首条为 64 个 0。评估记录字段：`record_type, seq, task_id, checkpoint, contract_hash, state_hash,
evidence_hash, individual_constraint_results, soft_constraint_results, evidence_results, verdict, release,
reason_codes, evaluator_version, timestamp, snapshot{contract, state, evidence}, previous_record_hash, record_hash`。
完整输入快照 + 验证器结果使历史裁决可重放。

## 8. 验收（`acceptance.py`）

见 [docs/API.md](docs/API.md#acceptance) 与 [docs/SECURITY_BOUNDARIES.md](docs/SECURITY_BOUNDARIES.md)。
要点：需求只来自冻结基线；基线 hash 必须等于独立锚（可 HMAC 签名）中当前修订；设计文档 hash 必须一致；
每条需求按 `file / command / json_schema / evidence` 自动验证，`manual / llm_judgment` 只能 INCONCLUSIVE；
追踪矩阵缺项 → FAIL；任一 FAIL → FAIL；否则任一 INCONCLUSIVE 或无需求 → INCONCLUSIVE；否则 PASS。
DDR：分母 = 锚定基线修订的全部需求数；`rate_lower = FAIL/N`，`rate_upper = (FAIL+INCONCLUSIVE)/N`。

## 9. 仍未确定 / 有意不做

- 非对称签名（如 Ed25519）未实现：需要额外依赖；当前只有 HMAC 共享密钥。
- 外部可信时间与外部审计锚服务未内置：库提供 `audit head` 与 `--anchor-*` 校验，但存放位置由宿主决定。
- 软约束只报告，不定义任何"软分数"。
- 状态 S 的真实性由宿主负责，库不验证调度器自身。
