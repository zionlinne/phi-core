# 需求 → 代码 → 测试 追踪矩阵

状态含义：**实现+测试** = 有代码且有直接测试；**部分** = 实现了但有明确限制；**未覆盖** = 未实现或未测试。
"测试通过"指作者本地运行与 CI 运行结果（见 PR 中的日志与 run 链接），不代表独立第三方测试。

## 1. 核心算子

| 需求 | 代码 | 测试 | 状态 |
| --- | --- | --- | --- |
| Φ(T,S,E)→TRUE/FALSE/UNKNOWN，原始乘积的三值扩展，无加权/概率/LLM | `evaluator.PhiEngine.judge` | `test_verdict_matches_independent_oracle`（属性，300 例，与独立 oracle 比对） | 实现+测试 |
| 优先级 VIOLATED > UNRESOLVED > SATISFIED | `judge` 组合段 | `test_priority_violation_beats_unresolved`、`test_violation_beats_incomplete_scope` | 实现+测试 |
| TRUE 需全部必要硬约束确定性满足 + 范围完整 | 同上 | 属性测试中 `TRUE ⇒ all SATISFIED ∧ complete ∧ task_in_state` | 实现+测试 |
| UNKNOWN/FALSE 永不放行 | `EvaluationResult.release`、`gate` | `test_T_unknown_is_never_released`、`test_T_harness_*` | 实现+测试 |
| 未声明完整不可默认 TRUE；显式完整空集合可 TRUE | `SCOPE_NOT_DECLARED_COMPLETE` | `test_H_*`、`test_I_*` | 实现+测试 |
| 软约束单独报告，不参与硬裁决 | `soft_results` | `test_soft_constraints_reported_separately_and_never_decide`、`test_soft_constraints_never_influence_verdict`（属性） | 实现+测试 |

## 2. 版本化 Task Contract Schema 与谓词

| 需求 | 代码 | 测试 | 状态 |
| --- | --- | --- | --- |
| 身份目标、父子、依赖、输入输出、所有权、能力资源、时间、硬/软约束、证据要求、验收引用、版本与完整性 hash | `schemas/task_contract.v1.schema.json`、`contracts.py` | `test_v1_example_is_valid_and_sealed`、`test_v1_invalid_contracts_rejected`、`test_seal_and_hash_exclude_integrity_block` | 实现+测试 |
| "必要前置" | 用 `constraints[].category="precondition"` + `checkpoints` 表达 | `test_checkpoint_applicability` | 部分：没有单独的 `preconditions` 字段 |
| "独立最终验收标准" | 契约只存 `acceptance.baseline_id/revision/hash` 引用；标准本身在独立基线中 | `test_acceptance_*` | 实现+测试（刻意分离） |
| 类型化谓词：输入/输出存在、依赖完成、文件 hash、所有权、Schema 兼容、资源、截止时间、能力 | `predicates.py` 11 个内置 | `test_dependency_predicate`、`test_resource_capability_time_predicates`、`test_ownership_predicate`、`test_checkpoint_applicability`、`test_json_schema_verifier` | 实现+测试 |
| 接口兼容 | `schema_compatible`（JSON Schema） | 同上 | 部分：仅 JSON Schema，不含 OpenAPI/函数签名 |
| 可注册确定性验证器/谓词 | `PredicateRegistry`、`FunctionPredicate`、`VerifierRegistry` | `test_custom_registered_predicate`、`test_custom_deterministic_verifier_registration` | 实现+测试 |
| 禁止 eval/exec 与自然语言执行；不可验证 → UNKNOWN | 保留类型、无 eval | `test_G_*`、`test_reserved_natural_language_types_cannot_be_registered`、`test_no_fbs_llm_or_cloud_imports_in_package`（AST 扫描） | 实现+测试 |

## 3. Evidence Verifier

| 需求 | 代码 | 测试 | 状态 |
| --- | --- | --- | --- |
| 9 个必需字段 | `schemas/evidence.v1.schema.json`、`EvidenceItem` | `test_evidence_model_requires_all_v1_fields`、`test_malformed_items_rejected` | 实现+测试 |
| 约束匹配 | 引擎按 constraint_id、验证器允许列表、主体匹配过滤 | `test_evidence_verifier_allowlist`、`test_subject_mismatch_is_not_used`、`test_unmatched_evidence_reported` | 实现+测试 |
| 来源完整性 | HMAC + 密钥-来源授权 | `test_hmac_attestation`、`test_hmac_detects_tampering_of_any_signed_field` | 实现+测试 |
| 时效 | `max_age_seconds`，未来时间戳拒绝 | `test_E_*`、`test_future_timestamp_rejected` | 实现+测试 |
| 缺失 | `EVIDENCE_MISSING` / `min_items` | `test_C_*`、`test_min_items` | 实现+测试 |
| 冲突默认 UNKNOWN；仅预声明可复现优先规则；禁止 last-write-wins | `source_precedence` | `test_D_*`、`test_no_last_write_wins`、`test_source_precedence_rule_is_explicit_and_reproducible` | 实现+测试 |
| 拒绝伪造/篡改/无法验证 | 验证器重算、签名校验 | `test_L_*`、`test_K_*`、`test_F_*`、`test_hmac_artifact_binding`、路径逃逸/符号链接测试 | 实现+测试 |
| 无注册 verifier 不可信；自报状态/自算 hash 不自动可信 | `verify_evidence` | `test_caller_claimed_status_is_never_trusted`、`test_crashing_or_lying_custom_verifier_gains_no_trust` | 实现+测试 |
| 可信边界说明（hash 不证明作者，宿主权限者可伪造） | `docs/SECURITY_BOUNDARIES.md` §2.2–2.3 | — | 文档 |

## 4. 确定性引擎

| 需求 | 代码 | 测试 | 状态 |
| --- | --- | --- | --- |
| 无隐式模型调用 | 无网络/LLM 依赖 | AST 导入扫描测试 | 实现+测试 |
| 不修改输入 | 深拷贝 + 冻结只读状态 | `test_engine_does_not_mutate_inputs`、`test_predicate_cannot_mutate_state_seen_by_other_constraints`、属性测试 | 实现+测试 |
| 相同输入同结果；显式时间 | `S.now`；`judge` 纯函数 | `test_judge_is_pure_and_repeatable`、`test_deterministic_order_invariant_and_non_mutating` | 实现+测试 |
| 逐项理由与完整证据引用 | `ConstraintResult.reason_codes/evidence_refs`、`evidence_results` | `test_result_serialises_with_full_references` | 实现+测试 |
| 父子任务与依赖契约 | `evaluate_plan` | `test_plan_true_for_consistent_tree`、`test_plan_issues`（8 种） | 实现+测试 |
| 执行前用最新状态重算，不复用过期裁决 | `gate.guard`、`authorize` | `test_N_*`、`test_S_*`、`test_runner_stops_mid_steps_when_state_changes` | 实现+测试 |
| PLAN/DISPATCH/STEP/COMMIT | `CHECKPOINTS`、`GateSession` | `test_A_*`、`test_checkpoint_applicability`、`test_session_order_enforced` | 实现+测试 |
| 只裁决，不调度、不拆任务 | `HarnessAdapter.plan_steps` 由宿主实现 | 设计约束 | 实现 |

## 5. 外部调用与 Adapter

| 需求 | 代码 | 测试 | 状态 |
| --- | --- | --- | --- |
| Python SDK | `phi_core/__init__.py` | 全部单测 | 实现+测试 |
| CLI / JSON 协议 / stdin | `cli.py` | `test_cli.py` 全部 | 实现+测试 |
| 外部命令门禁 | `phi gate-exec` | `test_gate_exec_runs_only_on_true`、`test_T_unknown_is_never_released`、CI smoke | 实现+测试 |
| 通用 Harness Adapter + 统一 preflight/step/commit | `gate.HarnessAdapter`、`GatedRunner`、`GateSession` | `test_gate_adapter.py` | 实现+测试 |
| 真实可运行最小 Harness，门禁真实阻止副作用 | `examples/minimal_harness/harness.py` | `test_T_harness_blocked_actions_never_run_and_completion_not_committed`、CI harness 步骤 | 实现+测试；在预检被阻止时无输出；之后被阻止时已放行步骤的输出保留（不回滚） |
| 进程内门禁与 OS 级隔离边界 | `docs/SECURITY_BOUNDARIES.md` §2.1 | `test_O_boundary_direct_write_outside_library_is_not_prevented` | 文档+边界测试（**不防御**） |

## 6. 独立 Acceptance

| 需求 | 代码 | 测试 | 状态 |
| --- | --- | --- | --- |
| 原始需求冻结 + 独立可信锚 | `requirements_baseline` / `baseline_anchor` Schema、`_verify_anchor` | `test_P_*`、`test_Q_*`、`test_no_anchor_inconclusive`、`test_unsigned_anchor_when_signature_required`、`test_anchor_chain_must_be_consistent` | 实现+测试 |
| 原始设计版本与 hash | `design.sha256` | `test_R_self_reported_success_but_design_deviation` | 实现+测试 |
| 需求-交付追踪矩阵；遗漏检测 | `requirement_results`、`TRACE_MISSING_OMITTED_REQUIREMENT` | `test_Q_*`、`test_untraced_extras_reported` | 实现+测试 |
| 自动化测试、输出文件/接口验证、必要证据 | `command` / `file` / `json_schema` / `evidence` | `test_example_passes`、`test_command_timeout_inconclusive`、`test_evidence_value_mismatch_and_conflict` | 实现+测试 |
| PASS/FAIL/INCONCLUSIVE；无法验证不得 PASS；LLM 不能单独 PASS | `run_acceptance` | `test_acceptance_llm_and_manual_cannot_pass`、`test_empty_requirement_set_is_not_pass` | 实现+测试 |
| Agent 自称完成不是验收；自改标准不能通过 | `claimed_status` 忽略；基线锚 | `test_P_*`、`test_R_*` | 实现+测试 |
| 需求变更需新版本 | `new_revision`、锚修订链 | `test_Q_*`（新修订未锚定 → FAIL；锚定后旧修订 SUPERSEDED） | 实现+测试 |
| DDR：明确分母与未知项 | `design_deviation` | `test_R_*`、`test_acceptance_llm_and_manual_cannot_pass` | 实现+测试 |
| Φ TRUE ≠ PASS，分别运行记录 | 模块不导入引擎；`append_acceptance` 独立记录 | `test_R_phi_true_does_not_imply_acceptance_pass`、`test_acceptance_module_does_not_import_phi_engine`、`test_acceptance_records_in_separate_log` | 实现+测试 |

## 7. 审计

| 需求 | 代码 | 测试 | 状态 |
| --- | --- | --- | --- |
| 必需字段 + SHA-256 链 | `audit.AuditLog.append_evaluation` | `test_records_have_required_fields_and_chain` | 实现+测试 |
| 历史重放（保存完整快照） | `replay_record` | `test_replay_matches_history`、`test_audit_replay_reproduces_every_recorded_verdict`（属性） | 实现+测试 |
| 篡改检测 | `verify_chain` | `test_tamper_detection`（5 种）、`test_snapshot_tamper_with_recomputed_record_hash_detected` | 实现+测试 |
| 版本裁决比较 | `compare_versions` | `test_compare_versions` | 实现+测试 |
| 证据来源追踪、状态变化重建 | `trace_evidence`、`reconstruct_state_history` | `test_trace_evidence_and_state_history` | 实现+测试 |
| 无外部锚可整链重写的边界 | 文档 §2.4；`--anchor-*` | `test_full_rewrite_needs_external_anchor` | 实现+边界测试 |

## 8. 对抗与其他测试（全部在 `tests/test_adversarial.py`，函数名以字母开头）

| 场景 | 测试 | 期望 |
| --- | --- | --- |
| A 全必要满足 | `test_A_all_required_satisfied_true` | 四个检查点均 TRUE |
| B 有效硬违反 | `test_B_valid_hard_violation_false` | FALSE |
| C 缺证 | `test_C_missing_evidence_unknown` | UNKNOWN，`missing_evidence` 列出约束 |
| D 冲突 | `test_D_conflicting_evidence_unknown` | UNKNOWN `EVIDENCE_CONFLICT` |
| E 过期 | `test_E_stale_evidence_unknown` | UNKNOWN `EVIDENCE_STALE` |
| F 来源无法验证 | `test_F_unverifiable_source_unknown` | UNKNOWN（未知密钥、无签名、`llm_judgment` 验证器） |
| G 无法转换为可执行谓词 | `test_G_non_executable_predicate_unknown_and_never_executed` | UNKNOWN，注入代码未执行 |
| H 未声明完整的空集合 | `test_H_empty_set_without_complete_declaration_is_not_true` | 非 TRUE |
| I 显式完整空集合 | `test_I_explicit_complete_empty_set_true` | TRUE |
| J 依赖未完成 | `test_J_dependency_incomplete_blocks_execution` | UNKNOWN，动作未执行 |
| K 文件篡改 | `test_K_file_tampering` | 旧声明 UNKNOWN / 新观测 FALSE，动作未执行 |
| L 伪造证据 | `test_L_forged_evidence_is_not_trusted` | 不可信；不能把 FALSE 翻成 TRUE |
| M 契约修改 | `test_M_contract_modification` | UNKNOWN `CONTRACT_PIN_MISMATCH` / `CONTRACT_INTEGRITY_MISMATCH` |
| N 旧裁决重用 | `test_N_stale_verdict_cannot_be_reused` | `DecisionInvalid` |
| O Agent 绕门禁 | `test_O_agent_bypass_attempts`、`test_O_boundary_direct_write_outside_library_is_not_prevented` | 受支持入口全部阻止；库外直接写**不被阻止**（边界），下一检查点检测到不合规结果 |
| P Agent 改验收标准 | `test_P_agent_changes_acceptance_criteria` | FAIL / 非 PASS |
| Q 删除原始需求声称通过 | `test_Q_deleting_original_requirement_and_claiming_pass` | FAIL |
| R 自报成功但偏离设计 | `test_R_self_reported_success_but_design_deviation`、`test_R_phi_true_does_not_imply_acceptance_pass` | FAIL，DDR>0 |
| S 多子任务并发状态变化 | `test_S_concurrent_subtasks_with_state_changes` | 只有未受影响子任务提交；审计链完整 |
| T UNKNOWN 错误放行 | `test_T_unknown_is_never_released`、`test_T_harness_blocked_actions_never_run_and_completion_not_committed` | 永不放行；被拒动作无副作用（已放行步骤不回滚） |
| 属性/模糊 | `tests/test_properties.py`（8 项，Hypothesis derandomize） | 通过 |
| 集成 | 示例 Harness 子进程、CLI 子进程、审计 CLI | 通过 |
| 性能 | `tests/test_performance.py`、`benchmarks/bench_phi.py` | 记录数值；宽松上限 |

## 9–10. 交付与限制

| 需求 | 状态 |
| --- | --- |
| 包、CLI、SDK、Adapter、Schema、示例、文档、pytest、CI | 实现+测试 |
| 无 FBS / 特定 LLM / Harness / 云端依赖 | `test_no_fbs_runtime_dependency`、`test_no_fbs_llm_or_cloud_imports_in_package` |
| License 不选、不授权 | `LICENSE` 未改变 |

## 11. 独立测试（963d12b）缺陷修复映射（1.0.1）

原始失败证据与原样 probe 输出保存在交付 ZIP 的 `phi-core-v1-round2/01-repro-963d12b/`。回归测试使用与 probe 相同的最小输入。

| 缺陷 | 修复 | 代码 | 测试 |
| --- | --- | --- | --- |
| 1 SCHEMA-CRITERION-MUTABLE | 契约 `outputs[].schema_sha256/schema_refs`、基线 `schema_sha256/schema_refs` 冻结 Schema 闭包；未冻结 UNKNOWN/INCONCLUSIVE，字节变化 FALSE/FAIL；示例与 Harness 已冻结 | `safeschema.pin_issue`、`predicates.SchemaCompatible`、`acceptance._check_json_schema`、`contracts.compile_constraints` | `test_1_*`、`test_replay_reproduces_binding_and_schema_decisions`、Harness `schema_swap` |
| 2 SCHEMA-REF-FETCH | 受控 `referencing.Registry`：片段、工作区相对文件、本地元 Schema；其余不可解析；结构化错误码；验收方法异常 → INCONCLUSIVE | `safeschema.check_document`、`evidence.JsonSchemaVerifier`、`acceptance.run_acceptance` | `test_2_*`（含 HTTP 计数服务器、socket 禁用、hypothesis 随机 `$ref`） |
| 3 ACCEPT-COMMAND-UNPINNED-SCRIPT | `pinned_files` 运行前后 hash、`artifacts` 声明、argv 未冻结工作区文件 → INCONCLUSIVE（1.0.2 起由 `phi_core.command` 实现，见 §12） | `acceptance._check_command`、`command.run_command` | `test_3_*` |
| 4 ANCHOR-KEY-SOURCES-IGNORED | 密钥用途域（`evidence` / `baseline-anchor`，缺省 `evidence`）；签名后不得出现未签名修订 | `evidence.TrustStore`、`acceptance._verify_anchor` | `test_4_*` |
| 5 RUNNER-PLAN-USES-DISPATCH-EVIDENCE | provider 按检查点调用；`GatedRunner` 传入 `collect_evidence` | `gate._resolve_evidence`、`GatedRunner.run` | `test_5_*` |
| 6 EVIDENCE-NOT-BOUND-TO-TASK | 签名覆盖的 `binding`；Φ 核对任务/契约/检查点，验收核对基线/修订/需求；未绑定证明不使用 | `evaluator._binding_problem`、`acceptance._check_evidence`、`evidence.EvidenceItem` | `test_6_*`、`test_concurrent_tasks_never_share_attestations` |

既有测试的适配（未改断言语义）：`tests/conftest.py` 的 `attest` 默认绑定测试任务；`tests/test_adversarial.py` 的夹具冻结
Schema、为验收权威密钥加 `baseline-anchor` 用途；`tests/test_acceptance.py` 的两条验收证据绑定 `report-req`；
`tests/test_engine.py` 的版本断言改为 `phi-core/1.0.1`；`benchmarks/bench_phi.py` 的证明绑定 `bench` 任务。

## 12. 独立复测（6bca32e）缺陷修复映射（1.0.2）

原始失败输入/输出、原样 probe 输出及"新回归在 6bca32e 上失败"的记录保存在交付 ZIP 的 `phi-core-v1-round3/01-repro-6bca32e/`。

| 缺陷 | 修复 | 代码 | 测试 |
| --- | --- | --- | --- |
| N1 COMMAND-ARTIFACT-EXEMPTS-CRITERION | 程序/数据分角色：工作区程序（脚本/目录程序、`-m` 可加载的每个文件、工作区 `argv[0]`）必须冻结，`artifacts` 只豁免 `{python}` 程序的数据参数；非 `{python}` 程序 argv 中的工作区文件全部必须冻结；角色在快照上复核；遮蔽受信任模块的未冻结工作区模块拒绝 | `command._plan_python`、`_module_candidates`、`_plan_external`、`_role_problem`、`_shadowing`、`_run` | `test_n1_*`（14 种别名 × 回归与正例、模块遮蔽、复制窗口竞态）、`test_property_unpinned_or_escaping_program_never_passes` |
| N2 COMMAND-SYMLINK-SKIPS-UNPINNED-GUARD | 路径先字面检查再严格解析；逃逸、悬空、循环、`..`、绝对别名、逐级解析经过工作区的宿主路径 → INCONCLUSIVE；`O_NOFOLLOW` 读取；PATH 清理；解释器/程序在工作区内拒绝；无关外链不跟随不复制 | `command._Paths`、`_visited`、`_read_nofollow`、`_clean_path`、`_copy_workspace` | `test_n2_*`（含外部 FIFO 证明未读取） |
| N3 RUNNER-DEFAULTED-CHECKPOINT-IGNORED | provider 只要能接收检查点就收到：任一位置参数（含默认值）、`*args`、kw-only `checkpoint`、`**kwargs`；零参兼容；签名不可判定或只有其他 kw-only 参数 → `EvidenceProviderError`；provider 异常传播 | `gate._checkpoint_call`、`_resolve_evidence` | `test_n3_*`（9 种签名 × 每阶段取证 × 四个检查点各自 FALSE） |
| N4 COMMAND-PIN-RESTORE-DURING-RUN | 命令在工作区外私有快照中运行，标准文件写入已核对的内存字节；运行后核对快照与工作区；输出不跟随链接写回 | `command._run`、`_write_back` | `test_n4_*`（确定性竞态：改—读—还原 → FAIL；正确产物 → PASS） |

既有测试未改动断言；`tests/test_engine.py` 的版本断言改为 `phi-core/1.0.2`。

## 明确未覆盖 / 限制

1. **OS 级恶意宿主或库外代码**：不防御（§2.1）。只能在受支持检查点重新观测。
2. **HMAC 为对称密钥**：验证方也能签名；无非对称签名验证器。
3. **审计无内置外部锚**：需宿主保存 head hash。
4. **状态 S 被信任**；`now` 由宿主提供。
5. **任意谓词/现实事实**：只覆盖已注册谓词与验证器；接口兼容仅限 JSON Schema。
6. **多进程并发写审计**：有 `fcntl` 锁但未测试；非 POSIX 无锁。
7. **平台**：仅在 Linux（本地 + GitHub Actions ubuntu）上运行过。
8. **不回滚**：已放行 STEP 的副作用在后续检查点失败时保留（§2.1）；原子提升需宿主实现。
9. **独立第三方测试**：对 963d12b 的独立测试报告了 6 项缺陷（§11）；对 6bca32e 的独立复测确认其中 5 项已修复，并报告
   命令冻结仍未修复及 3 项新缺陷（§12）。对 1.0.2 的独立复测尚未进行，本文件不声称其通过。
10. **验收命令依赖**：只从 argv 识别程序与数据；程序内部 import 或打开、但未冻结的工作区文件以运行开始时的副本出现在快照中，
    不受冻结保护；冻结检查器执行被测代码时结果只达到检查器自身的隔离程度；快照不防同一 OS 账号的恶意进程（安全边界 §2.7）。
11. **Schema 闭包惰性**：只检查本次校验实际加载的引用文件（安全边界 §2.9）。
