# 可信边界与安全限制

本文件说明 phi-core **能**保证什么、**不能**保证什么。任何超出下述范围的声明都不成立。

## 1. 库能保证的（并有测试）

| 保证 | 机制 | 测试 |
| --- | --- | --- |
| 只有 TRUE 放行；FALSE/UNKNOWN 时受支持入口不调用动作 | `PhiGate.guard`、`GateSession`、`GatedRunner`、`phi gate-exec` | `test_T_*`、`test_J_*`、`test_K_*`、`test_gate_exec_runs_only_on_true` |
| 动作前使用最新 S/E 重新评估，不复用旧裁决 | provider 在评估时调用；`authorize` 重新评估并比对 hash | `test_N_*`、`test_guard_uses_latest_inputs_from_providers`、`test_S_*` |
| 伪造的 TRUE 决策对象无效 | 决策令牌 = 每个 gate 独有密钥上的 HMAC | `test_O_agent_bypass_attempts` |
| 调用方自报 `verification_status` 不被信任 | 只记录为 `claimed_status` | `test_caller_claimed_status_is_never_trusted`、`test_F_*` |
| 调用方自算 hash 不被信任 | 文件验证器自行重新计算 | `test_file_verifier_recomputes_hash`、`test_L_*`、`test_K_*` |
| 无注册验证器的证据不可信 | UNVERIFIABLE | `test_F_*` |
| 不执行任意代码/自然语言 | 无 eval/exec；不可执行谓词 → UNKNOWN | `test_G_*`、`test_no_fbs_llm_or_cloud_imports_in_package` |
| 契约中途被改 → 不放行 | 会话钉扎 + 可选自哈希 | `test_M_*` |
| 验收基线被生产者修改/删需求 → 不 PASS | 独立锚（可签名） | `test_P_*`、`test_Q_*` |
| 审计记录被编辑/删除/插入/重排 → 可检测（相对已知头哈希） | SHA-256 链 + 快照 hash | `test_tamper_detection`、`test_snapshot_tamper_*` |
| 工作区 Schema 被改不能使 Φ TRUE / 验收 PASS | 契约/基线冻结 Schema 闭包 hash | `test_1_*`（`tests/test_round2_fixes.py`） |
| Schema 校验不访问网络、不读工作区外文件，失败不抛出入口 | `safeschema` 受控 registry | `test_2_*` |
| 被改或缺失的冻结验收脚本/配置不能 PASS | `pinned_files` 运行前后 hash | `test_3_*` |
| `artifacts` 不能豁免被执行的程序；任何别名都不行 | 程序/数据分角色 | `test_n1_*`（`tests/test_round3_fixes.py`） |
| 链接逃逸、悬空/循环链接、`..`、绝对别名、PATH 歧义失败即关闭，不读外部目标 | 字面检查 + 严格解析 + `O_NOFOLLOW` | `test_n2_*` |
| provider 只要能接收检查点就收到检查点 | 按签名分派 | `test_n3_*` |
| 命令读取的是冻结的标准字节，运行中改写并还原无效 | 私有快照 + 已核对字节 | `test_n4_*` |
| 证据密钥不能批准需求变更 | 密钥用途域 `baseline-anchor` | `test_4_*` |
| 每个检查点使用该时点的证据 | provider 按检查点调用 | `test_5_*` |
| 证明不能跨任务/契约/检查点/基线复用 | 签名覆盖的 `binding` | `test_6_*` |

## 2. 库不能保证的（明确的边界）

### 2.1 进程内门禁 ≠ OS 级隔离

phi-core 是 Python 库。它**无法阻止**不经过它的代码：同进程的其他代码、其他线程、其他进程、
拥有文件写权限的用户或 Agent，都可以直接写文件或执行命令。`test_O_boundary_direct_write_outside_library_is_not_prevented`
明确演示了这一点：直接写入成功；库能做的只是在**下一个受支持的检查点**重新观测并发现不合规结果
（例如 COMMIT 时输出不符合 Schema → FALSE）。若产出内容恰好合规，绕过行为本身无法被库发现。

要获得真正的强制，宿主必须在 OS 层面隔离：例如 Agent 只能在沙箱/容器中运行，而唯一能产生副作用的通道是
宿主进程里经 `PhiGate.guard` 或 `phi gate-exec` 启动的动作；Agent 无权修改 phi-core、TrustStore、
审计日志与验收锚。

**门禁不回滚。** 每个 STEP 在执行前裁决；裁决 TRUE 的步骤其副作用会真实发生。之后某个检查点（下一 STEP
或 COMMIT）若为 FALSE/UNKNOWN，只阻止后续动作与"完成"状态转换，不撤销已写入的文件。示例 Harness 中
`bad_output` 场景留下 `output/*`（但任务状态仍为 `ready`，COMMIT 被 BLOCK），`contract_edit_midrun` 留下
`output/upper.txt`。需要原子性的宿主应在临时目录执行步骤，仅在 COMMIT 为 TRUE 后再提升结果。

### 2.2 HMAC 签名的含义

`hmac_attestation` 只证明"签名者持有 TrustStore 中该共享密钥"。密钥按**用途**分域：`evidence` 用途的密钥只能签证据，
`baseline-anchor` 用途的密钥只能签验收锚条目（缺省用途是 `evidence`）。用途域只在宿主把两类密钥分别发放给不同持有者时
才有意义；同一个人同时持有两类密钥，库无法区分其行为。版本化需求不等于 Agent 可以自己改需求：新修订必须由持有
`baseline-anchor` 密钥的验收方签署，签过名的锚链之后再出现未签名修订会被拒绝。它**不**证明人的身份或作者身份；
任何拿到密钥的人（包括验证方本身，因为 HMAC 是对称的）都能产生有效签名；拥有宿主权限者可以读取密钥并伪造。
密钥必须经带外方式发放给宿主，绝不能放进证据或交给被检查的 Agent。`examples/trust.demo.json` 是公开演示密钥。

### 2.3 普通 hash 的含义

SHA-256 只检测"内容与某个已知 hash 是否一致"。它不证明作者，不防止拥有写权限的人同时改内容和 hash。
因此：契约 `integrity.contract_hash` 只能检测天真修改（能改契约的人也能重算它）；真正的防护来自
`GateSession` 在 preflight 时钉扎、由宿主持有的 hash。验收基线 hash 同理，真正的参照是**由验收方单独保管**的锚，
可加 HMAC 签名。

### 2.4 审计日志：防篡改证据，不是不可篡改

链式 hash 能检测相对于"已知可信头哈希"的任何修改。若没有外部锚，能写整个文件的人可以重写全部记录并重算整条链，
内部校验仍会通过（`test_full_rewrite_needs_external_anchor` 演示）。要防止这一点，需定期把 `phi audit head`
的输出保存到写入者无法修改的位置，并用 `phi audit verify --anchor-seq --anchor-hash` 校验。

### 2.5 状态 S 被信任

`S`（任务状态、资源、能力、文件归属、`now`）由宿主调度器提供，引擎把它当作事实。若宿主本身被攻破或提供了错误状态，
Φ 的结论随之错误。`now` 也是宿主提供的；库不访问墙钟，因此也无法发现宿主伪造时间。

### 2.6 能验证什么

phi-core 只验证**已注册谓词和验证器覆盖的内容**：文件存在/hash、JSON Schema 兼容、依赖状态、归属、资源、能力、
时间边界、HMAC 签名的声明值、以及宿主注册的确定性验证器。它不能验证任意现实世界事实，也不能判断"测试是否有意义"
等语义问题。无法确定性验证的约束一律 UNKNOWN。

### 2.7 验收命令的执行

`command` 方法执行**基线中冻结的** argv（不经 shell，环境只保留清理后的 PATH，stdin 为空）。实现见 `phi_core.command`。

**角色。** 基线作者显式声明，库不从 `artifacts` 推断：

1. argv 文本由基线 hash 冻结。
2. **标准文件**（检查脚本、模块、配置、fixture）列入 `pinned_files[{path, sha256}]`。库读取一次、在内存中 hash，缺失 → FAIL
   `COMMAND_PINNED_FILE_MISSING`，不符 → FAIL `COMMAND_PINNED_FILE_MODIFIED`，命令**不运行**。
3. **程序**是命令从工作区执行的代码：`{python}` 的脚本（或目录程序）、`-m mod` 能从工作区加载的每个文件（`mod.py`、`mod.pyc`、
   扩展模块、包的 `__init__`/`__main__`）、工作区内的 `argv[0]`。程序必须是标准文件；`artifacts` 不能豁免程序，即使列出的是
   该文件、其父目录、`.` 或任何别名。未冻结 → INCONCLUSIVE `COMMAND_WORKSPACE_FILE_NOT_PINNED`（`detail.program_not_pinned`）。
4. **数据**：`{python}` 程序的脚本参数（及 `--opt=path` 的值）若指向工作区文件，必须被冻结或位于 `artifacts` 内
   （`detail.data_not_pinned_or_declared`）。数据参数不会被当成程序。对 `{python}` 以外的程序，库无法区分它的参数是数据还是
   代码（例如 `sh check.sh`），因此 argv 中所有工作区文件都必须冻结，`artifacts` 不起豁免作用（`detail.argv_roles =
   "unparsed-program-all-pinned"`）。

**路径失败即关闭。** argv、`-m` 候选和 `--opt=` 值中的路径先按字面检查、再解析：经文件或目录符号链接解析到工作区外、
悬空链接、循环链接、相对 `..` 逃逸 → INCONCLUSIVE `COMMAND_PATH_ESCAPES_WORKSPACE`；指向工作区的绝对路径（包括工作区外
指回工作区的别名，以及逐级解析时任一跳经过工作区的宿主路径，例如工作区外链接 → 工作区内链接 → 工作区外）→ INCONCLUSIVE
`COMMAND_ABSOLUTE_WORKSPACE_PATH`。解释器、PATH 项和 PATH 解析出的程序使用同一逐级检查。这些情况下命令不运行，外部链接目标的内容不被读取
（测试用指向工作区外 FIFO 的链接验证：读取会阻塞）。标准文件逐级以 `O_NOFOLLOW` 打开，解析后被换成链接的路径分量会导致读取失败
而不是读到工作区外。PATH 中的空项、相对项、工作区内的项被删除，裸程序名解析为绝对路径后再执行；解释器或解析出的程序位于工作区内
→ INCONCLUSIVE。

**冻结快照。** 命令的 cwd 是库新建的私有目录（`tempfile.mkdtemp`，模式 0700，位于工作区外）：先复制工作区（跳过
`__pycache__`，离开工作区的链接不跟随、不复制并列入 `detail.execution.omitted_links_leaving_workspace`，工作区内的链接重建为
指向快照内对应位置的链接，FIFO 等特殊文件跳过），再用**第 2 步已核对的内存字节**覆盖每个标准文件。因此运行期间对工作区的写入
（包括"改标准—运行—还原"）不影响命令读到的字节。运行后：快照中的标准文件被改 → FAIL `COMMAND_PINNED_FILE_MODIFIED_DURING_RUN`
（`detail.where = "snapshot"`）；工作区标准文件被改且未还原 → 同一代码（`where = "workspace"`）；命令新建或修改的其他文件以
`O_NOFOLLOW` 逐级写回工作区（标准文件与 `__pycache__` 不写回；路径上有链接则拒绝并列入 `outputs_not_written_back`），快照随后删除。

**可信检查器与不可信产物。** 标准文件由基线作者冻结、由验收方签名的锚确认，库**信任**其行为：作者签署的检查器若本身恶意
（例如无条件 `exit 0`），库无法发现，这是作者的责任，而不是被测产物能够利用的漏洞。被测产物（生产者写入工作区的一切）是**不可信**的：
它不能改变标准字节（第 2 步与快照保证），不能借 `artifacts` 让自己成为程序（第 3 步），不能用链接或别名把程序指到别处（路径规则）。
但如果冻结的检查器**主动执行**被测代码（`import` 交付模块、`pytest` 收集交付目录里的 `conftest.py` 等），被测代码就运行在命令进程中，
可以伪造退出码或改写快照；这时结果只能达到检查器自身隔离被测代码的程度。库不提供 OS 级沙箱。

**边界。** 快照仅靠文件模式与随机路径与其他进程隔离：同一 OS 账号下的恶意进程可以找到并修改快照，库对此**不作承诺**；需要这种
隔离的宿主应以独立账号或容器运行验收。工作区外的程序（解释器、系统工具、宿主在工作区外安装的检查器）被视为宿主可信，不被 hash。
程序在内部按名字 `import` 或打开、但未列入 `pinned_files` 的工作区文件，会以运行开始时的副本出现在快照中，其内容不受冻结保护
（与 1.0.1 相同的已披露限制）；需要保护时必须冻结。每次运行复制整个工作区，工作区很大时有相应的 I/O 开销（见基准中
`acceptance_command_snapshot`）。Windows 上没有 `os.fwalk`/`dir_fd`，退回到按路径读取，未测试。

### 2.8 并发

`AuditLog.append` 使用线程锁和 POSIX `fcntl.flock`。多线程并发已测试；多进程并发写同一文件**未测试**；
非 POSIX 平台没有文件锁。并发运行的多个验收命令各自使用独立快照（`test_concurrent_command_acceptance_is_isolated`）。

### 2.9 Schema 引用闭包

Schema 校验只加载工作区内的文件和本地元 Schema，并记录实际加载的每个文件的 SHA-256（闭包）。闭包中的每个文件都必须被契约
或基线冻结。解析是惰性的：只有被校验文档实际走到的 `$ref` 才会加载，因此闭包随文档变化；未被走到的引用文件即使被改也不影响
本次结论。

### 2.10 证据绑定

`binding` 由签名覆盖，改动会使签名失效。Φ 侧绑定 `task_id`（必需）及可选的 `contract_hash`、`checkpoints`；验收侧绑定
`baseline_id`（必需）及可选的 `baseline_revision`、`requirement_id`。绑定只说明签名者**声称**该证明针对哪个任务；
它防止证明被挪用到其他任务，不证明签名者如实陈述。文件类证据（`file_sha256`、`json_schema`）可以不绑定，因为验证器每次都在
当前工作区重新计算观测值。
