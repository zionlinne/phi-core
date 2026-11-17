# phi-core

Independent reusable three-valued feasibility operator.

**中文优先。** phi-core 是一个可本地运行、确定性的三值可行性算子库：

```
Φ(T, S, E) → TRUE | FALSE | UNKNOWN
```

- `T`：任务 / 执行计划契约（Task Contract v1.0）
- `S`：最新执行与调度状态（含显式时间 `now`）
- `E`：可验证证据（由独立 Evidence Verifier 判定可信与否）

它是原始 `Φ(p,σ) = ∏ I[C_i(p,σ)]` 的三值扩展，不使用加权、概率或模型判断：

1. 存在以有效证据/状态确定的**必要硬约束违反** → `FALSE`
2. 否则存在**未解决的必要项**（证据缺失、过期、冲突、不匹配、无法验证、谓词不可执行、未声明约束范围完整……）→ `UNKNOWN`
3. 否则**全部必要硬约束确定性满足**（空集合仅在显式声明范围完整时）→ `TRUE`

**只有 TRUE 放行。** FALSE 阻止，UNKNOWN 暂停并要求补证。软约束单独报告，永不参与裁决。

## 两道独立门禁

| 门禁 | 模块 | 结果 | 作用 |
| --- | --- | --- | --- |
| Φ 可行性 | `phi_core.evaluator` / `gate` | TRUE / FALSE / UNKNOWN | 执行前/中/提交时是否满足必要执行条件 |
| 最终验收 | `phi_core.acceptance` | PASS / FAIL / INCONCLUSIVE | 交付是否满足**冻结的原始需求与设计** |

`Φ(T,S,E) = TRUE` **不能**推出 `Acceptance(T) = PASS`。两者分别运行、分别记录；验收模块不导入、不读取 Φ 的结果（有测试强制）。

## 安装

要求 Python ≥ 3.11。唯一运行依赖：`jsonschema`。无云端服务、无 LLM、无 FBS 依赖。

```bash
git clone https://github.com/zionlinne/phi-core.git
cd phi-core
python -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install ".[test]"          # 开发模式: pip install -e ".[test]"
python -m pytest -v
```

## 快速开始

```bash
# 结构验证（只说明格式合法，不是可行性或验收结论）
phi validate examples/v1/contract.json

# Φ 裁决：JSON 输入 → JSON 输出；退出码 0=TRUE 10=FALSE 20=UNKNOWN
phi evaluate --request examples/v1/request.json --checkpoint DISPATCH --trust examples/trust.demo.json
phi evaluate --contract T.json --state S.json --evidence E.json --checkpoint COMMIT --workspace ws/ --audit audit.jsonl

# 外部命令门禁：只有 TRUE 才执行命令
phi gate-exec --request examples/v1/request.json --trust examples/trust.demo.json -- make build

# 审计：链校验 / 历史重放 / 证据追踪 / 状态重建
phi audit verify audit.jsonl ; phi audit replay audit.jsonl

# 独立验收：退出码 0=PASS 30=FAIL 40=INCONCLUSIVE
phi accept --baseline examples/acceptance/baseline.json --anchor examples/acceptance/anchor.json \
  --delivery examples/acceptance/delivery.json --workspace examples/v1/workspace \
  --now 2026-11-17T00:00:00Z --trust examples/trust.demo.json --require-signed-anchor

# 真实门禁的最小示例 Harness（场景: ok / tampered_input / dependency_pending / bad_output / ownership_conflict / contract_edit_midrun）
python examples/minimal_harness/harness.py --workspace /tmp/phi-demo --scenario ok
```

Python SDK：

```python
from phi_core import evaluate, PhiGate, GateSession, TrustStore

result = evaluate(contract, state, evidence, checkpoint="DISPATCH", workspace="ws", trust_store=trust)
result.verdict, result.release, result.reason_codes, result.constraint_results

gate = PhiGate(workspace="ws", trust_store=trust, audit_log=AuditLog("audit.jsonl"))
gate.guard("STEP", contract, latest_state_fn, latest_evidence_fn, action)   # 只有 TRUE 才调用 action
```

`examples/trust.demo.json` 中的密钥是**公开演示密钥**，不得用于真实部署。

## 当前状态（严格区分）

| 类别 | 内容 |
| --- | --- |
| 已实现 | Task Contract v1.0 Schema 与约束编译；Predicate Registry（11 个内置确定性谓词 + 可注册）；Evidence Verifier（file_sha256 / json_schema / hmac_attestation + 可注册）；确定性引擎（单任务 + 计划级）；PLAN/DISPATCH/STEP/COMMIT 门禁、会话契约钉扎、决策令牌；通用 HarnessAdapter + GatedRunner + 最小示例 Harness；JSONL SHA-256 审计链（重放/版本比较/证据追踪/状态重建）；独立 Acceptance（基线锚、设计 hash、追踪矩阵、DDR）；CLI 与 JSON 协议 |
| 已测试 / 已通过（本地） | 209 项 pytest，含 A–T 对抗场景、Hypothesis 属性/模糊测试、集成、绕过、重放、性能测试。远端 CI 结果见 PR |
| 未验证 | 非 Linux 平台；Python 3.11/3.12/3.13 以外版本；大规模真实工作负载；多进程同时写同一审计文件（已加 `fcntl` 锁，但仅测试了多线程） |
| 已知限制 | 见 [docs/SECURITY_BOUNDARIES.md](docs/SECURITY_BOUNDARIES.md)：进程内库无法阻止不经过它的代码；HMAC 只证明持有共享密钥；审计链无外部锚时可被整链重写；状态 `S` 由宿主提供并被信任；无法验证任意现实世界事实，只能验证已注册谓词/验证器所覆盖的内容 |

## 文档

- [SPECIFICATION.md](SPECIFICATION.md)：Φ 正式定义、输入、裁决规则、证据规则、协议
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)：模块与数据流
- [docs/API.md](docs/API.md)：Python SDK、CLI、JSON 协议、Adapter
- [docs/SECURITY_BOUNDARIES.md](docs/SECURITY_BOUNDARIES.md)：可信边界与不能防御的内容
- [docs/TRACEABILITY.md](docs/TRACEABILITY.md)：需求 → 代码 → 测试追踪矩阵（含未覆盖项）
- [ROADMAP.md](ROADMAP.md)

## 许可证

许可证待定，目前不授予任何使用、修改或再分发许可。见 [LICENSE](LICENSE)。
