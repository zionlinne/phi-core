# phi-core 路线图

> 阶段划分为计划，不构成承诺；每个阶段需单独授权后才开始。

## 阶段 0：工程脚手架（本阶段）

- [x] Python 包结构、`pyproject.toml`、`phi` 命令行入口
- [x] 任务契约 / 证据数据模型（`0.1-draft`，未冻结）
- [x] 任务契约 JSON Schema 与结构验证
- [x] `evaluator.evaluate` 接口占位（抛 `NotImplementedError`）
- [x] `phi evaluate` 返回 `NOT_IMPLEMENTED`（非零退出）
- [x] pytest 单元测试、GitHub Actions CI
- [ ] Φ 核心逻辑 —— **本阶段明确不做**

## 阶段 1：规格确定（未开始）

- 逐项回答 [SPECIFICATION.md](SPECIFICATION.md) 第 4 节的待确定问题
- 冻结契约与证据协议的首个正式版本；补充证据 JSON Schema

## 阶段 2：Φ 核心实现（未开始）

- 实现三值判断，覆盖 TRUE / FALSE / UNKNOWN 的判定条件
- 约束分类、证据验证、证据冲突处理（按阶段 1 决定的规则）
- 针对三值语义的系统测试

## 阶段 3：集成接口（未开始）

- 面向外部调度器 / Harness 的稳定调用接口与适配层（Adapter）
- 是否以及如何与 feasibility-scheduler 对接另行决定；phi-core 保持独立，不以其为运行依赖

## 始终独立的事项

- 最终交付验收（Acceptance）是独立门禁，不并入 Φ
- 许可证待定，需仓库所有者决定
