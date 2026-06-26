# 安澜·SIEM 安全监测系统 - 规则开发指南

## 概述

本文档记录了 Wazuh 检测规则的开发方法、语法规范和最佳实践。规则使用 XML 编写，遵循 Wazuh 规则引擎语法。

## 规则结构

```xml
<rule id="100001" level="12" frequency="5" timeframe="120" ignore="60">
    <if_matched_group>authentication_failed</if_matched_group>
    <field name="url">(?i)(SELECT.*FROM|UNION.*SELECT)</field>
    <description>检测到 SQL 注入攻击</description>
    <group>web_attack,sql_injection,</group>
    <mitre>
        <id>T1190</id>
    </mitre>
    <options>no_full_log</options>
</rule>
```

### 关键属性说明

| 属性 | 说明 | 示例 |
|------|------|------|
| `id` | 规则唯一 ID（自定义规则使用 100000+） | `100001` |
| `level` | 告警级别 0-15 | `12` |
| `frequency` | 在时间窗口内触发次数 | `5` |
| `timeframe` | 时间窗口（秒） | `120` |
| `ignore` | 匹配后忽略同一来源的秒数 | `60` |

### 告警级别定义

| 级别 | 分类 | 说明 |
|------|------|------|
| 0-2 | 信息 | 普通事件信息 |
| 3-5 | 关注 | 值得注意但不可疑 |
| 6-8 | 低危 | 轻微安全关注 |
| 9-10 | 中危 | 确认的可疑活动 |
| 11-13 | 高危 | 攻击进行中 |
| 14-15 | 严重 | 确认失陷，需立即响应 |

## 规则开发流程

### 第一步：了解日志来源

```bash
# 分析 Apache 日志格式
192.168.1.1 - - [26/Jun/2026:10:15:30 +0800] "GET /index.html HTTP/1.1" 200 2345
```

### 第二步：确保解码器匹配

```xml
<decoder name="apache-access-log">
    <prematch>^(\d+\.\d+\.\d+\.\d+) </prematch>
    <regex>...提取模式...</regex>
    <order>srcip, timestamp, request_method, request_path, status_code, response_size</order>
</decoder>
```

### 第三步：编写规则条件

使用解码器提取的字段编写匹配条件：

```bash
# 交互式测试
docker exec -it wazuh-server /var/ossec/bin/wazuh-logtest
```

### 第四步：设置告警级别

- 信息收集行为 → 较低级别（7-8）
- 确认的探测行为 → 中等级别（9-10）
- 正在进行的利用 → 高级别（11-12）
- 确认失陷 → 严重级别（13-15）

### 第五步：映射 MITRE ATT&CK

每条规则关联对应的 MITRE 攻击技术，遵循行业标准：

| 规则 | 攻击技术 | MITRE ID |
|------|---------|----------|
| SQL 注入 | 利用面向公众的应用 | T1190 |
| 暴力破解 | 暴力破解 | T1110 |
| 活动扫描 | 主动扫描 | T1595 |
| 命令注入 | 命令/脚本执行 | T1059 |
| 创建账号 | 创建账号 | T1136 |

## 开发的规则类型

### 1. Web 攻击检测

| 规则 ID | 检测类型 | 匹配方式 | 级别 |
|---------|---------|---------|------|
| 100001-100004 | SQL 注入 | 关键词、盲注、认证绕过 | 12 |
| 100010-100014 | 目录扫描 | 敏感路径、聚合频率 | 7-10 |
| 100040 | XSS | 脚本标签、事件处理器 | 10 |
| 100041-100042 | LFI/RFI | 文件包含参数 | 9-10 |
| 100043 | 命令注入 | Shell 元字符 | 12 |
| 100044 | 文件上传 | 可执行扩展名 | 8 |
| 100045 | Web 扫描器 | 大量 404 聚合 | 7 |

### 2. 暴力破解检测

| 规则 ID | 检测类型 | 阈值 | 时间窗口 | 级别 |
|---------|---------|------|---------|------|
| 100020 | SSH 暴力破解 | 8 次 | 120 秒 | 10 |
| 100021 | SSH 持续攻击 | 20 次 | 300 秒 | 12 |
| 100022 | SSH 大规模协同 | 50 次 | 600 秒 | 14 |
| 100024 | Web 登录爆破 | 15 次 | 180 秒 | 8 |
| 100025 | FTP 暴力破解 | 10 次 | 180 秒 | 8 |

### 3. 异常活动检测

| 规则 ID | 检测类型 | 匹配条件 | 级别 |
|---------|---------|---------|------|
| 100030 | Root SSH 登录 | srcuser=root | 5 |
| 100031 | 周末登录 | weekday=saturday,sunday | 5 |
| 100032 | 深夜登录 | time=0:00-6:00 | 5 |
| 100033 | 用户枚举 | 5 用户名/60 秒 | 7 |
| 100034 | 权限提升 | sudo 到 root | 5 |
| 100035 | 创建账号 | useradd/groupadd | 8 |

## 聚合规则

使用 frequency + timeframe 检测时间序列上的攻击模式：

```xml
<!-- 120 秒内匹配 12 次触发 -->
<rule id="100014" level="10" frequency="12" timeframe="120">
    <if_matched_sid>100010</if_matched_sid>
    <description>检测到目录爆破攻击</description>
</rule>
```

## 调试方法

```bash
# 交互式规则测试
echo '{"srcip":"203.0.113.5","url":"/login.php?id=1%27OR%271%27=%271"}' | \
    docker exec -i wazuh-server /var/ossec/bin/wazuh-logtest

# 查看已加载规则列表
docker exec wazuh-server /var/ossec/bin/wazuh-logtest -l

# 查看实时告警
docker exec wazuh-server tail -f /var/ossec/logs/alerts/alerts.json
```
