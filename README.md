# phi-core

Independent reusable three-valued feasibility operator.

> **当前状态：工程脚手架阶段（bootstrap）。Φ 核心逻辑尚未实现。**

## 项目定位

`phi-core` 的目标是提供一个独立、可复用的三值可行性算子：

```
Φ(T, E) → {TRUE, FALSE, UNKNOWN}
```

- `T`：任务契约（task contract）
- `E`：证据集合（evidence）
- `TRUE`：满足必要执行条件
- `FALSE`：存在已验证的硬约束违反
- `UNKNOWN`：证据不足，暂缓执行

上述语义是目标定义，**本阶段没有任何代码实现它**。

### 两道独立门禁

Φ 可行性判断与最终交付验收（Acceptance）是**不同的门禁**：

- `Φ(T, E) = TRUE` **不能**推出 `Acceptance(T) = PASS`；
- 两者不得合并为一个判断；
- 本仓库不提供、也不声称提供通用 Harness 控制能力。

### 契约"格式有效"的含义

`phi validate` 通过只说明契约文档**结构合法**（符合 JSON Schema），
**不代表**任务可行，也**不代表**最终验收通过。

## 安装

要求 Python ≥ 3.11。

```bash
git clone https://github.com/zionlinne/phi-core.git
cd phi-core
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install ".[test]"      # 或开发模式: pip install -e ".[test]"
```

运行依赖仅有 `jsonschema`。本项目不依赖 feasibility-scheduler（FBS）。

## 使用

```bash
phi --help
phi validate examples/sample_task.json      # 退出码 0 = 结构合法
phi evaluate examples/sample_task.json      # 输出 NOT_IMPLEMENTED，退出码 3
python -m pytest -v
```

退出码：`0` 结构合法；`1` 结构不合法；`2` 用法错误 / 文件不可读 / JSON 损坏；`3` NOT_IMPLEMENTED。

Python 调用：

```python
from phi_core import TaskContract, EvidenceSet, validate_contract, evaluate

result = validate_contract(data)          # ValidationResult(valid, errors)，仅结构检查
contract = TaskContract.from_dict(data)   # 不合法时抛 ContractFormatError
evaluate(contract, EvidenceSet())         # 总是抛 NotImplementedError
```

## 当前能力

| 类别 | 内容 |
| --- | --- |
| 已实现 | 包结构与 `phi` 命令行入口；任务契约数据模型（`contracts.py`）；证据数据模型（`evidence.py`）；JSON Schema（`schemas/task_contract.schema.json`）；契约结构验证；pytest 单元测试；GitHub Actions CI |
| 未实现 | Φ 三值判断；约束优先级；证据验证与证据冲突裁决；Acceptance 验收；Harness / Adapter；与 FBS 的任何集成 |
| 未确定 | 契约与证据字段（当前为 `0.1-draft` 工程协议，**未冻结**）；`hard`/`soft` 的语义；证据充分性标准；见 [SPECIFICATION.md](SPECIFICATION.md) |

后续阶段见 [ROADMAP.md](ROADMAP.md)。

## 许可证

许可证待定，目前不授予任何使用、修改或再分发许可。见 [LICENSE](LICENSE)。
