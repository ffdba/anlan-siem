# 架构与职责边界

## 两条独立链路

```text
授权环境日志
    -> Wazuh Agent / Logcollector
    -> Wazuh Manager
         -> decoder 字段提取
         -> rule 单事件匹配 / 历史关联
         -> alerts.json
              -> Filebeat -> Wazuh Indexer -> Wazuh Dashboard
              -> JSONL 导出 -> anlan 离线研判 -> JSON / Markdown
```

本仓库维护 decoder / rule 配置以及 `anlan` 离线工具，不实现新的实时检测引擎，也不实现自定义 Web Dashboard。Wazuh 原生界面来自上游项目，是否可用取决于实际部署。

## 检测层

访问日志使用受控来源前缀，输出统一 Web 字段。基础规则提供非零等级的历史事件，攻击规则依赖基础 ID；频率规则使用 `if_matched_sid` / `if_matched_group` 与 `same_srcip`，不把所有地址的失败相加。

SSH / FTP 依赖 Wazuh 内置解码器和认证事件。Wazuh 通常按 agent 隔离关联历史，本配置未开启跨 agent 的 `global_frequency`；部署版本和 manager 配置仍需原生验证。

时间异常规则使用 Wazuh manager 的处理时间语义，不能从访问日志中的 `log_timestamp` 推断其时区行为。

## 研判层

| 模块 | 职责 |
| --- | --- |
| `triage.py` | 输入校验、UTC 归一化、稳定标识、去重、限时策略、事件归并 |
| `validation.py` | XML 与项目契约清单，不执行 Wazuh |
| `reporting.py` | JSON 导出、转义后的 Markdown 摘要 |
| `__main__.py` | `validate`、`demo`、`triage` 命令 |

归并维度为 manager + agent + actor + category。时间窗口从该批次第一条事件开始，不采用无限延长的滑动链式归并。报告按最高规则等级、唯一事件数和稳定 ID 排序，输出判定理由与输入行号。

## 运行方式

离线链路仅需 Python 3.10+ 标准库，不连接网络、不启动监听、不调用扫描器、不写回 Wazuh。处理过程将整份输入载入内存，适合有限规模的导出审查，不是流式 SOC 后端。

原生规则断言需要现有测试 manager 或本地 `wazuh-logtest`；脚本不创建容器。GitHub 上的手动原生工作流另行创建隔离临时容器，未发布宿主端口。

Compose 是实验模板，需要补齐官方 TLS、安全初始化、凭据和 Filebeat 后才能评估端到端链路。只读规则挂载由部署流程管理，不由脚本覆盖或重启。
