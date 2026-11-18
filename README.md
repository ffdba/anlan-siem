# 安澜 SIEM | 检测即代码与告警研判

基于 Wazuh 的个人蓝队工程项目：不仅编写攻击特征规则，还将日志字段约定、规则静态校验、离线告警归并和降噪审计放进同一个可复现工作流。

**Python 标准库即可运行演示，无需 Docker、密钥或网络服务。** Wazuh 负责检测，Python 负责整理已有告警，两者职责独立。

## 快速体验

要求 Python 3.10+，支持 Windows / Linux / macOS。在仓库根目录执行：

```bash
git clone https://github.com/ffdba/anlan-siem.git
cd anlan-siem
python -S -m anlan validate -o output/validation.json
python -m unittest discover -s tests -v
python -S -m anlan demo
```

演示使用合成的 Wazuh 告警，输出 `output/demo/incidents.json` 和 `output/demo/triage.md`：

| 输入告警 | 去重后 | 重复记录 | 本地降噪 | 待审告警 | 归并事件 |
| --- | --- | --- | --- | --- | --- |
| 10 | 9 | 1 | 1 | 8 | 5 |

这些数字仅描述固定样本，不是误报率、检测准确率或生产性能指标。演示不会发起攻击、执行扫描或启动 Wazuh。

## 解决的问题

| 问题 | 实现 |
| --- | --- |
| Web 解码器字段不一致，规则条件无法复用 | Apache / Nginx / 通用访问日志统一字段，显式选择 PCRE2 |
| 关联规则只看总次数，将不同来源混计 | 独立基础事件与历史选择器，使用同源 IP 条件 |
| XML、引用或字段错误难以及时发现 | 校验规则 ID、引用、捕获组、字段与关联约束，输出机器可读清单 |
| 同一告警重复导出，分析队列膨胀 | 稳定事件标识、内容冲突检查、重复证据保留 |
| 同一行为跨主机或跨部署被错误归并 | 按 manager、agent、来源与类别隔离，在锚定时间窗口内归并 |
| 永久白名单掩盖后续异常 | 有范围、有负责人、有工单、有到期时间的降噪策略，保留被降噪事件 |
| 告警被直接写成“已失陷” | 优先级依据规则等级，报告保留判定理由、证据位置和验证边界 |

## 检测配置

当前包含 **34 条规则、10 个 decoder 定义**（分布在 3 个解码器文件中，其中包含父/子 decoder），27 条规则具有 ATT&CK 映射。数量由 `validate` 清单计算，不代表检测覆盖率。

| 文件 | 规则数 | 内容 |
| --- | --- | --- |
| `000-web-foundation.xml` | 5 | Web 基础事件、认证失败、404 历史事件 |
| `001-sql-injection.xml` | 4 | SQL 关键词、布尔/时间盲注、认证绕过线索 |
| `002-directory-scanning.xml` | 5 | 敏感路径上下文、路径穿越、同源频率关联 |
| `003-brute-force.xml` | 8 | SSH / Web / FTP 认证失败与关联 |
| `004-abnormal-login.xml` | 6 | root 登录、非工作时间、用户枚举、sudo、账号创建 |
| `005-web-attacks.xml` | 6 | XSS、RFI / LFI、命令注入、脚本写请求、404 关联 |

访问日志约定：

```text
ANLAN_WEB 192.0.2.10 - - [19/Nov/2026:09:00:00 +0800] "GET / HTTP/1.1" 200 -
ANLAN_APACHE 192.0.2.10 - - [19/Nov/2026:09:00:00 +0800] "GET / HTTP/1.1" 200 120 "-" "demo-client"
ANLAN_NGINX 2001:db8::10 - - [19/Nov/2026:09:00:00 +0800] "GET / HTTP/1.1" 200 120 "-" "demo-client"
```

三个来源均输出 `srcip`、`log_timestamp`、`http_method`、`url`、`status_code`、`response_size`，Combined 格式另含 `referer`、`user_agent`。

前缀需在受控采集/重放阶段提供，用于避免与 Wazuh 内置 Web decoder 竞争。未加前缀的日志可能由内置 decoder 先匹配，不能假设会进入本项目规则。错误日志 decoder 只提供有限格式解析，不是完整错误日志检测集。

## 整理实际告警

输入为已导出的 Wazuh `alerts.json`，每行一个 JSON 对象：

```bash
python -S -m anlan triage /path/to/alerts.json --window 300 -o output/review
```

经审批的降噪策略可通过 `--policies` 提供；`config/demo-policies.json` 仅是演示样例。策略必须同时限定规则、manager、agent、源 CIDR 及开始/到期时间，并记录负责人、理由、工单；有效期最多 30 天，不允许全网或通配范围。当前时钟和告警时间都必须在有效期内。

```bash
python -S -m anlan triage examples/alerts.jsonl \
  --policies config/demo-policies.json \
  --now 2026-11-19T09:20:00+08:00 -o output/replay
```

默认遇到非法输入即退出；显式添加 `--skip-invalid` 才会继续，并在报告中登记错误行。所有数据在本地处理，输出默认被 Git 忽略。JSON 包含完整的标准化事件与降噪审计，Markdown 提供优先级队列和证据摘要。

## 验证边界

| 层级 | 命令 / 工作流 | 能证明什么 |
| --- | --- | --- |
| 静态契约 | `python -S -m anlan validate` | XML 可解析、ID/引用/字段/关联约束符合项目约定 |
| 离线回归 | `python -m unittest discover -s tests -v` | 归并、隔离、去重、策略到期、输入拒绝和报告转义等 Python 行为 |
| 原生规则 | `python scripts/verify-logtest.py --container YOUR_TEST_MANAGER` | 指定测试环境中真实 `wazuh-logtest` 的 decoder、字段和规则输出 |
| 端到端部署 | 手工验证采集、Filebeat、Indexer、Dashboard | 实际链路运行情况，不能用离线演示替代 |

`tests/logtest-cases.json` 提供 22 个原生断言案例，包括 Web 特征、正常请求反例、同源 404 序列和分散来源序列。反例可声明 `forbidden_rule_ids`，检查整段序列，而非只检查最后一行。

GitHub Actions 自动执行 Linux / Windows、Python 3.10 / 3.13 的离线回归；独立的 `Native Wazuh Rule Assertions` 工作流需要手动触发，在无网络、无宿主端口映射的临时 Wazuh 4.9.0 容器中验证并保存证据。原生工作流的通过/失败应以实际运行记录为准，**静态检查通过不等于原生规则或完整集群验证通过**。

## Wazuh 实验环境

`docker-compose.yml` 保留为 **未补齐的单节点实验模板，不是开箱即用部署包**。它仍需按照 Wazuh 官方 4.9 配置完成 TLS 证书、Indexer 安全初始化、凭据及 Filebeat 配置。4.9.0 是规则兼容性实验目标；生产环境应选受支持版本并重新验证。

Linux 上可先只检查配置：

```bash
bash scripts/setup.sh --check
```

脚本不会自动复制/修改只读挂载目录，不会自动重启已有 manager。只有主动使用 `--start` 且确认 `START` 才会请求启动；启动前检查当前 Compose 的宿主端口并拒绝已占用、保留或非回环端口。WSL / Docker Desktop 还需单独检查 Windows 宿主监听，不能仅凭 WSL 的 `ss` 判断。

模板宿主端口：Indexer `127.0.0.1:9200`、Dashboard `127.0.0.1:9443`、API `127.0.0.1:55000`、事件接收 `127.0.0.1:15140/tcp`、注册 `127.0.0.1:15150/tcp`。未发布集群内部端口；默认不接收远程 agent。

## 项目结构

```text
anlan/                  # 标准化、归并、策略审计、报告与静态校验
wazuh_config/           # 检测即代码：decoder 与 rule XML
examples/               # 合成 Wazuh JSONL 告警
config/                 # 限时降噪策略样例
sample_logs/            # 原始日志样本，不是已验证攻击证据
tests/                  # Python 回归与原生 logtest 断言清单
scripts/                # 显式启动检查与真实引擎断言工具
.github/workflows/      # 离线 CI 与手动原生规则验证
docs/                   # 架构、字段契约、规则开发和研判设计
```

进一步阅读：[架构](docs/architecture.md)、[解码器契约](docs/decoder-development-guide.md)、[规则开发](docs/rule-development-guide.md)、[研判设计](docs/triage-design.md)、[排错](docs/troubleshooting.md)。

## 使用范围

本项目用于授权环境中的安全监测学习与工程展示，不包含自动封禁、攻击执行或自动响应。规则命中只是线索；高等级、ATT&CK 映射及“无告警”都不直接证明攻击成功或环境安全。

报告省略 `full_log`，但 URL、用户名、来源地址等仍可能敏感。分享前需脱敏，并为原始输入与输出设置访问控制。离线处理为内存批处理，不承诺无限规模或实时吞吐。

Wazuh 的上游许可见 [Wazuh 仓库](https://github.com/wazuh/wazuh)。本仓库不把上游组件许可证徽章当作自身代码的授权声明。
