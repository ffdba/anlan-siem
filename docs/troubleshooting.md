# 排错与验证边界

## 离线命令失败

先在仓库根目录执行：

```bash
python --version
python -S -m anlan validate
python -m unittest discover -s tests -v
```

需要 Python 3.10+。没有第三方 Python 依赖；`-S` 禁用 site-packages，方便确认离线命令不依赖本机额外包。

输入报错应定位报告/终端中的文件行号，检查 timezone、manager、agent、rule 和 `data.srcip`。不能为了“跑通”而给所有缺失主机填同一个 ID；缺少身份的输入不满足隔离契约。

## XML 通过但规则不命中

XML 可解析不证明 Wazuh 接受所有规则语义。使用真实引擎断言：

```bash
python scripts/verify-logtest.py --container YOUR_TEST_MANAGER
```

查看 `output/logtest-results.json` 中的原生输出：

1. Phase 2 是否是预期 decoder，字段是否完整？
2. 是否在受控采集/重放中加入了正确的 `ANLAN_*` 来源前缀？
3. Phase 3 是否匹配基础规则或某条更早/更具体的规则？
4. 关联案例是否在同一个会话中输入，来源和历史事件是否一致？
5. 是否使用本项目目标版本和同一份配置？

别把 Python `re` 的样本检查当作 PCRE2 / Wazuh 验证，也别因为原生工具缺失而跳过断言后返回成功。

## 误报与漏报

先保存原始输入和 Phase 2/3 输出，再增加正常行为反例。管理接口访问、认证重试及批准扫描不直接证明攻击；需要临时降噪时明确规则、部署、主机、来源、有效期和工单。

URL 规则不解析请求体，不覆盖全部编码与绕过。对真实流量的检测率、误报率、性能和业务影响应另外测量，不能从合成样本外推。

## Compose 或 Dashboard 不可用

本仓库 Compose 是未完成的实验模板。证书缺失、Indexer 未初始化、凭据不一致、Filebeat 没配置都会使完整链路失败，等待固定秒数不能解决这些问题。

在自建测试环境中先检查：

```bash
docker compose config --quiet
docker compose ps
docker logs YOUR_TEST_MANAGER
docker exec YOUR_TEST_MANAGER /var/ossec/bin/wazuh-control status
docker exec YOUR_TEST_MANAGER filebeat test output
```

按 Wazuh 官方对应版本配置 TLS 和权限，不使用硬编码默认口令或跳过 TLS 验证作为修复。宿主内核参数、凭据、配置与服务重启需由环境负责人批准。

启动前必须查宿主监听，发现冲突应选择其他获准端口，而不是结束占用者。WSL / Docker Desktop 需要额外检查 Windows 宿主：

```powershell
Get-NetTCPConnection -LocalPort 9200,9443,55000,15140,15150 -State Listen -ErrorAction SilentlyContinue
```

测试脚本不启动容器、不修改生产配置、不自动重启或结束其他进程。
