# 架构

```
            host / harness (owns decomposition, scheduling, state S, side effects)
                 │  T, S, E                                   ▲ Decision / exception
                 ▼                                            │
 ┌──────────────────────────── phi_core ────────────────────────────────────────┐
 │ cli.py ── JSON protocol ──┐                                                   │
 │                           ▼                                                   │
 │ gate.py   PhiGate.check/guard/authorize, GateSession, GatedRunner,            │
 │           HarnessAdapter  ──────────────► audit.py  (JSONL SHA-256 chain)     │
 │                           │                                                   │
 │                           ▼                                                   │
 │ evaluator.py  PhiEngine.evaluate = verify (impure: workspace, S.now)          │
 │                                   + judge  (pure)                             │
 │        │                    │                          │                     │
 │        ▼                    ▼                          ▼                     │
 │ contracts.py          evidence.py                predicates.py               │
 │ schema, hash,         EvidenceItem, TrustStore,  Predicate Registry,         │
 │ compile_constraints   VerifierRegistry,          state/evidence predicates   │
 │                       verify_evidence                                         │
 │                                                                               │
 │ acceptance.py  run_acceptance  (imports only canonical/evidence/schemas/      │
 │                safeschema; never evaluator/gate/predicates/audit)             │
 │ safeschema.py  workspace-only $ref resolution, schema closure + pin check     │
 │ canonical.py   canonical JSON, SHA-256, RFC 3339, freeze                      │
 │ schemas.py     packaged JSON Schemas                                          │
 └───────────────────────────────────────────────────────────────────────────────┘
```

## 数据流

1. 宿主提供 `T`（契约）、`S`（最新状态，含 `now`）、`E`（证据声明）和 `checkpoint`。
2. `verify`：每条证据交给其 `verifier_id` 对应的已注册验证器。文件类验证器读取工作区（显式输入），
   HMAC 验证器使用宿主提供的 TrustStore。输出 `VerificationResult`（状态由验证器决定）。
3. `judge`（纯函数）：校验 T、S → 编译约束 → 过滤适用于检查点的约束 → 每个约束经谓词得到三态 →
   三值组合。不访问文件系统、时钟、随机数或网络；输入先深拷贝，状态以只读冻结视图交给谓词。
4. `gate` 只在 TRUE 时执行动作，每次动作前重新调用 1–3；可选写入审计链。
5. `acceptance` 独立运行，读取冻结基线、独立锚、生产者交付报告和工作区，输出 PASS/FAIL/INCONCLUSIVE。

## 确定性

- `judge(T, S, verification_results, checkpoint)` 对相同输入产出相同 `to_dict()`（测试：
  `test_judge_is_pure_and_repeatable`、属性测试 `test_deterministic_order_invariant_and_non_mutating`）。
- 唯一时间来源是 `S.now`；证据顺序不影响结果（冲突规则不依赖顺序或时间先后）。
- `PhiGate` 的随机密钥只用于决策令牌 MAC，不影响裁决。
- `evaluate` 包含对工作区的观测；把工作区视为显式输入。审计记录保存观测结果，历史重放不依赖当前文件。

## 扩展点

- `PredicateRegistry.register(name, Predicate)`：`StatePredicate` / `EvidencePredicate` / `FunctionPredicate`。
- `VerifierRegistry.register(verifier)`：实现 `verifier_id` 与 `verify(item, ctx) -> VerificationResult`；
  只有观测值完全由验证器在工作区重新计算时才可声明 `reobserves = True`（其证据可不绑定任务）。
- `HarnessAdapter`：`load_contract / observe_state / collect_evidence(checkpoint) / plan_steps / commit`；
  `collect_evidence` 在 PLAN、DISPATCH、每个 STEP、COMMIT 分别以对应检查点调用。
- `PhiEngine(evaluator_version=...)`：配合 `audit.compare_versions` 比较不同版本裁决。
