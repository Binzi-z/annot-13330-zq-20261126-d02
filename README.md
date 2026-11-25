# 离线安全复核 13330 — 并发解冻 / 停用

值班组遇到一次并发的账号解冻与停用：两份工单都报告成功，接班人却无法判断
哪份真正生效。本工具用 **Python 3.12 标准库**、在 **原生 Windows** 上离线复核
这一事件。输入全部是**合成账号、委派关系、解冻工单和本地决定日志**；
**不接触任何真实账户、不联网**。

## 快速开始

```bash
python -m govreview demo --out artifacts/demo    # 生成合成输入并完整复核
python -m govreview verify --in artifacts/demo   # 校验已有产物（先查哈希）
python -m unittest discover -s tests             # 26 项测试
```

`demo` 会写出自包含的产物目录（见下）并在 `RESULT.json` 里给出机器可核验的
结论；任一检查失败则返回非零退出码。`verify` **先核对 `MANIFEST.json` 的哈希**
再重跑比对，因此被篡改的产物会被报告而不是被覆盖重生成。

## 复核做了什么

| 需求 | 实现 |
| --- | --- |
| 双控制链独立批准、绑定账号/待解冻代/工单摘要 | `delegation.py` + `authorization.py` |
| 停用抢先、解冻已提交但无回执、旧代同号异摘要 | `concurrency.py`（**两个真实 `threading.Thread` + 两个 `Barrier`**） |
| 小模型穷举短交错 | `smallmodel.py`（15 种交错，手写模型 vs 参考重放逐条比对） |
| 按本地文件与持久化决定重建每个历史水位 | `ledger.py`（append-only + 哈希链 + 逐水位重放） |
| 最短可独立核验的批准/拒绝凭据 | `credential.py`（独立第二实现 + 最小性 + 篡改测试） |
| 六万条按组织分区记录、停用实际影响 | `impact.py`（三套独立算法交叉核对 + 全量校验） |

### 关键语义

- **停用是终态**：停用一旦提交，之后任何形式合规的解冻都**没有效果**。
  账本仍记录该“已提交”的决定（`committed=true`），但 `effect` 为
  `NO_EFFECT_DEACTIVATED` —— 这正是“工单报告成功”与“账户真的解冻”之间的裂缝。
- **回执可丢，提交不丢**：`receipt_delivered=false` 的解冻仍在持久化日志里，
  接班人能凭本地文件重建结果，而不必相信调用方。
- **旧代/异摘要拒绝**：指向旧代或旧摘要的写入被拒绝并记为异常，绝不静默改指。
  同一工单号 `T-1023` 在轮换后携带新正文（新摘要），旧决定仍引用旧摘要 —— 精确复现
  “同号异摘要”。
- **独立 = 不同控制链**；可选 `strict_no_common_delegator` 进一步要求委派谱系不相交。

## 产物目录（`artifacts/demo/`）

| 文件 | 内容 |
| --- | --- |
| `accounts.json` / `delegation.json` / `tickets.json` / `ledger.jsonl` | 合成输入 |
| `decision_log.jsonl` | 带前向哈希链的持久化决定日志 |
| `watermarks.json` | 每个历史水位的授权/运行状态（逐事件） |
| `credentials.json` | 每条解冻决定的最短凭据 + 校验 + 最小性 + 篡改测试 |
| `concurrency.json` | 真实双线程复现证据（线程 ID、屏障轨迹、三项隐患断言） |
| `smallmodel.json` | 15 种交错的不变量核对 |
| `impact.json` | 六万条分区记录的停用影响 + 全量三算法核对 |
| `RESULT.json` | 汇总结论与全部检查项 |
| `REPORT.md` | 中文人读报告 |
| `MANIFEST.json` | 全部产物的 SHA-256 清单 |

## 凭据形态（最短、可独立核验）

批准：`{kind, account, generation, ticket, ticket_digest, decision, independence_mode, seal}`
拒绝：`{kind, account, generation, ticket, ticket_digest, decision, reason, seal}`

`seal` 为对其余字段的 SHA-256。校验器 `verify_credential` 是**独立的第二实现**：
自行重算工单摘要、重读日志批准、依委派森林重判独立性，从不调用评估器。
`assert_minimal` 逐字段删除证明每个字段都是承重的；`tamper_report` 证明单字段改动
必被拒。

## 入参安全

`schema.assert_local_tree` 拒绝 URL/网络式路径、越出输入根目录的路径、以及
解析后逃逸根目录的符号链接；输入仅接受普通本地文件。所有 JSON 字段做类型、
长度、引用完整性、委派环检测，工单摘要按规范化 JSON 重算并核对。

## 事件模型

```
provision --freeze_applied--> FROZEN --unfreeze_decided(合规)--> ACTIVE
any --deactivate_decided--> DEACTIVATED(终态)
rotate(前进代) : 冻结若绑定旧代则转为陈旧
```

`unfreeze_decided` 需要：工单存在且摘要重算一致、代 == 当前代、已提交、
两名**不同**且**控制链独立**的批准人各自绑定 `(账号, 代, 工单摘要)`。

## 测试

`python -m unittest discover -s tests` 覆盖：规范化/委派独立性/账本重放/授权/
凭据最小性与篡改/真实线程复现/小模型穷举/六万条分区核对/入参守卫/端到端与
`verify` 的篡改检测，共 26 项，全部通过。
