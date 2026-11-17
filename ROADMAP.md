# phi-core 路线图

> 每个后续阶段需单独授权后才开始。

## 阶段 0：工程脚手架 —— 已完成

包结构、草案契约 0.1、CLI、pytest、CI。（Φ 当时刻意未实现。）

## 阶段 1：Φ Core v1.0 完整实现 —— 本阶段（PR #1）

- [x] 正式 Φ(T,S,E) 三值引擎与计划级检查
- [x] Task Contract v1.0、State v1.0、Evidence v1.0 Schema
- [x] Predicate Registry、Evidence Verifier、TrustStore
- [x] PLAN/DISPATCH/STEP/COMMIT 门禁、HarnessAdapter、最小示例 Harness、`phi gate-exec`
- [x] JSONL 审计链：重放、篡改检测、版本比较、证据追踪、状态重建
- [x] 独立 Acceptance：冻结基线 + 独立锚、设计 hash、追踪矩阵、DDR
- [x] A–T 对抗测试、属性/模糊、集成、性能测试；CI
- [ ] 独立第三方测试 —— 由用户安排，不在本阶段宣布

## 可能的后续阶段（未开始、未承诺）

- 非对称签名验证器（Ed25519 等），使证据签发者与验证者不必共享密钥
- 外部审计锚 / 可信时间的可插拔接口（仍保持核心本地运行）
- 更多内置确定性谓词（如 API 契约 / OpenAPI 兼容性）
- OS 级隔离参考集成（容器/沙箱中只允许经 `phi gate-exec` 启动的命令）
- 是否以及如何与 feasibility-scheduler 对接另行决定；phi-core 保持独立

## 始终独立

- 最终交付验收（Acceptance）是独立门禁，不并入 Φ
- 许可证待定，需仓库所有者决定
