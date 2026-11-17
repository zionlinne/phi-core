# API

## Python SDK

```python
from phi_core import (
    evaluate, PhiEngine, Verdict,                     # Φ
    PhiGate, GateSession, GatedRunner, HarnessAdapter, Step,
    GateBlocked, GateNeedsEvidence, DecisionInvalid, GateSequenceError,
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

`state_fn` / `evidence_fn` 可以是可调用对象，门禁在评估时才调用，保证使用最新输入。

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
| `phi evidence observe --contract --workspace --now` / `sign FILE --trust --key-id` | 生成文件证据声明 / HMAC 签名 | 0 |

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
| `command` | `argv`（不经 shell，`{python}` 替换为当前解释器），工作区为 cwd，超时 | 期望退出码 PASS / 其他 FAIL / 超时或无法运行 INCONCLUSIVE |
| `json_schema` | 工作区 JSON 符合工作区 Schema | PASS / FAIL / Schema 缺失 INCONCLUSIVE |
| `evidence` | 交付报告中的证据经 Evidence Verifier 验证，值与 `expected` 相等 | PASS / FAIL / 缺失或冲突 INCONCLUSIVE |
| `manual`, `llm_judgment` | 不可自动判定 | 永远 INCONCLUSIVE |

需求变更：`new_revision(old, requirements=..., summary=..., frozen_at=...)` 生成新修订（记录增删改），
必须由验收方用 `make_anchor_entry` 追加到锚中后才有效；旧修订随即 `BASELINE_REVISION_SUPERSEDED`。
