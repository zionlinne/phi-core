# phi-core 规格说明（草案）

> 状态：**草案，未冻结**。本文件描述待实现接口与待确定问题。
> 文中所有字段、类型、枚举均为工程协议 `0.1-draft`，随时可能变更。

## 1. 核心算子（待实现）

```
Φ(T, E) → {TRUE, FALSE, UNKNOWN}
```

| 结果 | 目标语义 |
| --- | --- |
| `TRUE` | 满足必要执行条件 |
| `FALSE` | 存在**已验证**的硬约束违反 |
| `UNKNOWN` | 证据不足，暂缓执行 |

### 1.1 Python 接口（已定义形状，未实现）

```python
# phi_core/evaluator.py
class Verdict(str, Enum):
    TRUE = "TRUE"; FALSE = "FALSE"; UNKNOWN = "UNKNOWN"

def evaluate(contract: TaskContract, evidence: EvidenceSet) -> Verdict:
    raise NotImplementedError
```

当前实现：调用 `evaluate` **总是**抛出 `NotImplementedError`。
CLI `phi evaluate` 总是输出 `NOT_IMPLEMENTED` 并以退出码 `3` 失败，不输出任何三值结果。

### 1.2 与验收门禁的关系

- Φ 是**可行性**门禁，Acceptance 是**最终交付验收**门禁；
- `Φ(T, E) = TRUE` ⇏ `Acceptance(T) = PASS`；
- 两者不得合并；本仓库不实现 Acceptance，不提供通用 Harness 控制能力。

## 2. 任务契约 T（已实现结构验证；字段未冻结）

JSON Schema：`schemas/task_contract.schema.json`（Draft 2020-12）。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `contract_version` | `"0.1-draft"` | 是 | 草案协议版本 |
| `task_id` | string，`[A-Za-z0-9._:-]+` | 是 | |
| `objective` | 非空 string | 是 | 任务目标描述 |
| `constraints` | 非空数组 | 是 | 每项：`constraint_id`、`kind`（`hard`/`soft`）、`statement` |
| `required_evidence` | string 数组（唯一） | 否 | 语义未定 |
| `metadata` | object | 否 | 非规范性附加信息 |

不允许额外字段（`additionalProperties: false`）。

**结构有效 ≠ 可行 ≠ 验收通过。**

## 3. 证据 E（已实现数据模型；字段未冻结）

`EvidenceItem`：`evidence_id`、`kind`、`source`（必填非空字符串），`payload`（object）、
`constraint_id`、`collected_at`（可选，未解析）。`EvidenceSet` 是条目集合。

本阶段**不**验证证据真实性，**不**判断证据与约束的匹配，**不**做冲突裁决。
尚无证据的 JSON Schema。

## 4. 待确定问题

1. 契约字段是否足够表达"必要执行条件"；是否需要前置条件 / 环境需求等结构化字段。
2. `hard` / `soft` 的确切语义；`soft` 约束是否影响 Φ 结果。
3. 约束优先级是否存在、如何表示。
4. "已验证"的定义：何种证据足以确认硬约束违反。
5. 证据充分性标准：何时 `UNKNOWN` 转为 `TRUE`。
6. 证据冲突（同一约束有相互矛盾的证据）的裁决规则。
7. 证据的时效性（`collected_at`）与可信来源（`source`）如何参与判断。
8. 证据格式是否需要独立 JSON Schema，以及与契约的引用方式。
9. Φ 输出是否需要附带理由 / 追溯信息（例如每条约束的状态）。
10. 版本演进与兼容策略（`contract_version` 规则）。
11. 许可证选择（当前：待定，不授予许可）。

以上问题在本阶段**均未决定**，现有代码不得被视为对其中任一问题的回答。
