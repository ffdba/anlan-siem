# 安澜·SIEM 安全监测系统

> 基于 Wazuh 开源 SIEM/EDR 平台，针对 Web 攻击、Linux 系统日志及认证日志进行日志解析与检测规则开发，实现攻击行为的自动识别与告警。

![Wazuh](https://img.shields.io/badge/Wazuh-4.9.0-5B9BD5?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square)
![Elastic Stack](https://img.shields.io/badge/Elastic-Stack-005571?style=flat-square)
![License](https://img.shields.io/badge/License-GPLv2-green?style=flat-square)

---

## 📋 目录

- [项目简介](#-项目简介)
- [技术栈](#-技术栈)
- [系统架构](#-系统架构)
- [功能特性](#-功能特性)
- [快速开始](#-快速开始)
- [自定义解码器](#-自定义解码器)
- [检测规则](#-检测规则)
- [样本数据](#-样本数据)
- [项目结构](#-项目结构)
- [开发记录](#-开发记录)
- [核心收获](#-核心收获)

---

## 🎯 项目简介

本项目基于 **Wazuh 开源 SIEM/EDR 平台**，通过 Docker 搭建完整的安全监测实验环境，围绕真实的网络安全攻击场景，完成了以下工作：

- **自定义解码器**：针对 Apache、Nginx 及通用 Web 应用日志编写解码器，实现日志字段的精细化解析
- **检测规则开发**：开发 20+ 条检测规则，覆盖 SQL 注入、XSS、目录扫描、暴力破解、命令注入、异常登录等攻击类型
- **规则调试与优化**：使用 wazuh-logtest 进行交互式调试，优化正则表达式降低误报率
- **可视化展示**：配置 Dashboard 展示安全事件，分析攻击来源 IP、攻击类型及事件趋势
- **完整文档**：总结日志解析流程、规则开发方法及调试过程

---

## 🛠 技术栈

| 类别 | 技术 |
|------|------|
| **SIEM/EDR 平台** | Wazuh（开源） |
| **部署方式** | Docker + Docker Compose |
| **存储与搜索** | OpenSearch（Elasticsearch 分支） |
| **可视化** | Wazuh Dashboard（Kibana 基础） |
| **数据格式** | JSON、XML、YAML |
| **模式匹配** | 正则表达式 (PCRE) |
| **运行环境** | Linux（Ubuntu） |

---

## 🏗 系统架构

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│   Wazuh Agent   │────▶│   Wazuh Server  │────▶│  Wazuh Indexer  │
│   （终端节点）   │ UDP │  （管理器 +     │ SSL │  （OpenSearch）  │
│                 │ 514 │    Filebeat）    │9200 │                 │
└─────────────────┘     │                 │     └───────┬─────────┘
                        │ 自定义解码器     │             │
                        │   + 检测规则     │             ▼
                        └─────────────────┘     ┌─────────────────┐
                                                 │ Wazuh Dashboard │
                                                 │ （可视化面板）   │
                                                 └─────────────────┘
```

### 数据处理流程

```
日志采集 → 解码器解析 → 规则引擎评估 → 告警生成 → OpenSearch 索引 → Dashboard 可视化
```

---

## ✨ 功能特性

### 🔍 Web 攻击检测

| 攻击类型 | 检测方式 | 告警级别 |
|---------|---------|---------|
| **SQL 注入** | 关键词匹配、布尔盲注、时间盲注、认证绕过 | 高危 (12) |
| **XSS 跨站脚本** | 脚本标签、事件处理器、编码载荷 | 高危 (10) |
| **路径穿越** | ../ 模式、敏感文件探测 | 中高危 (7-9) |
| **目录扫描** | 敏感路径访问、聚合频率检测 | 中高危 (7-10) |
| **命令注入** | Shell 元字符检测 | 严重 (12) |
| **LFI/RFI 文件包含** | 文件包含参数检测 | 高危 (9-10) |
| **恶意文件上传** | 可执行扩展名检测 | 中危 (8) |
| **Web 扫描器** | 大量 404 响应聚合 | 中危 (7) |

### 🔐 认证与系统监控

| 检测项 | 检测方式 | 告警级别 |
|--------|---------|---------|
| **SSH 暴力破解** | 分级频率阈值（8/20/50 次） | 10/12/14 |
| **Web 登录爆破** | 登录接口重复 401/403 | 8 |
| **FTP 暴力破解** | FTP 认证失败追踪 | 8 |
| **异常登录时间** | 深夜/周末行为检测 | 5 |
| **用户枚举** | 多用户名尝试 | 7 |
| **权限提升** | sudo 切换 root 检测 | 5 |
| **新用户创建** | 账号创建监控 | 8 |

---

## 🚀 快速开始

### 环境要求

- Docker 24.x+ & Docker Compose 2.x+
- Linux / WSL2 / macOS

### 部署步骤

```bash
# 1. 克隆项目
git clone https://github.com/ffdba/anlan-siem.git
cd anlan-siem

# 2. 启动 Wazuh 集群
docker-compose up -d

# 3. 等待初始化（约 90 秒）
# 4. 访问 Dashboard
open https://localhost

# 5. 安装自定义解码器和规则
./scripts/setup.sh
```

### 测试自定义规则

```bash
# 使用 wazuh-logtest 进行交互式规则测试
docker exec -it wazuh-server /var/ossec/bin/wazuh-logtest

# 或运行自动化测试
./scripts/test-rules.sh

# 查看实时告警
docker exec wazuh-server tail -f /var/ossec/logs/alerts/alerts.json | jq .
```

---

## 📝 自定义解码器

开发了 **3 个自定义解码器**，用于 Web 服务器日志的结构化解析：

| 解码器 | 文件 | 用途 |
|--------|------|------|
| **Web 访问日志解码器** | `001-web-decoder.xml` | 通用 HTTP 访问日志解析（CLF 格式） |
| **Apache 解码器** | `002-apache-decoder.xml` | Apache 访问日志与错误日志专用解析 |
| **Nginx 解码器** | `003-nginx-decoder.xml` | Nginx 访问日志与错误日志专用解析 |

### 解析示例

**原始日志**：
```
203.0.113.5 - - [26/Jun/2026:10:20:00 +0800] "GET /login.php?id=1%27OR%271%27=%271 HTTP/1.1" 403 234
```

**解析后结构化字段**：

| 字段 | 值 |
|------|-----|
| srcip | 203.0.113.5 |
| timestamp | 26/Jun/2026:10:20:00 +0800 |
| http_method | GET |
| url | /login.php?id=1%27OR%271%27=%271 |
| status_code | 403 |
| size | 234 |

---

## 📜 检测规则

开发了 **20+ 条自定义检测规则**，分布在 5 个规则文件中：

| 规则文件 | 规则数 | 覆盖范围 | 规则 ID |
|---------|--------|---------|---------|
| `001-sql-injection.xml` | 4 | SQL 注入各类变体 | 100001-100004 |
| `002-directory-scanning.xml` | 5 | 信息收集与路径穿越 | 100010-100014 |
| `003-brute-force.xml` | 6 | SSH/Web/FTP 暴力破解 | 100020-100025 |
| `004-abnormal-login.xml` | 6 | 异常认证与系统事件 | 100030-100035 |
| `005-web-attacks.xml` | 6 | XSS、RFI、LFI、命令注入 | 100040-100045 |

所有规则均包含 **MITRE ATT&CK 映射**，采用 **分级告警策略**。

### 聚合规则示例

```xml
<!-- SSH 暴力破解三级阈值 -->
<rule id="100020" level="10" frequency="8" timeframe="120">  <!-- 8次/120秒 -->
<rule id="100021" level="12" frequency="20" timeframe="300"> <!-- 20次/300秒 -->
<rule id="100022" level="14" frequency="50" timeframe="600"> <!-- 50次/600秒 -->
```

---

## 📁 项目结构

```
anlan-siem/
├── docker-compose.yml                # Docker 部署配置
├── wazuh_config/
│   ├── decoders/                     # 自定义解码器
│   │   ├── 001-web-decoder.xml       # 通用 Web 解码器
│   │   ├── 002-apache-decoder.xml    # Apache 解码器
│   │   └── 003-nginx-decoder.xml     # Nginx 解码器
│   └── rules/                        # 自定义检测规则
│       ├── 001-sql-injection.xml     # SQL 注入检测
│       ├── 002-directory-scanning.xml # 目录扫描检测
│       ├── 003-brute-force.xml       # 暴力破解检测
│       ├── 004-abnormal-login.xml    # 异常登录检测
│       └── 005-web-attacks.xml       # Web 通用攻击检测
├── sample_logs/                      # 攻击样本日志
│   ├── web_attacks.log               # Web 攻击样本
│   └── system_attacks.log            # 系统攻击样本
├── scripts/                          # 部署与测试脚本
│   ├── setup.sh                      # 一键部署
│   └── test-rules.sh                 # 规则批量测试
├── docs/                             # 项目文档
│   ├── architecture.md               # 架构说明
│   ├── decoder-development-guide.md  # 解码器开发指南
│   ├── rule-development-guide.md     # 规则开发指南
│   └── troubleshooting.md            # 排错指南
└── README.md                         # 本文件
```

---

## 📖 开发记录

### 第一阶段：环境搭建
- 研究 Wazuh 三组件架构（Manager、Indexer、Dashboard）
- 设计 Docker Compose 配置，实现集群化部署
- 配置网络和持久化卷映射

### 第二阶段：日志分析与解码器开发
- 分析 Apache/Nginx Combined Log Format 结构
- 掌握 Wazuh 解码器 prematch → regex → order 三级处理流程
- 开发 3 个解码器，覆盖通用 Web、Apache、Nginx 三类日志
- 使用 wazuh-logtest 验证解析准确性

### 第三阶段：检测规则开发
- 开发 20+ 条规则，覆盖 5 大类攻击场景
- 应用频率聚合实现暴力破解和扫描检测
- 映射 MITRE ATT&CK 框架（T1190、T1110、T1595 等）
- 实现分级告警策略（告警级别 7-15）

### 第四阶段：测试与优化
- 使用 wazuh-logtest 进行交互式规则测试
- 优化正则表达式减少误报
- 根据真实攻击模式调整频率阈值

### 第五阶段：文档与总结
- 编写完整架构文档和开发指南
- 记录调试过程中的经验教训

---

## 💡 核心收获

### 技术能力
- **SIEM 架构理解**：深入掌握 Wazuh 三组件架构的协作机制
- **日志解析能力**：掌握解码器 prematch → regex → order 处理管线
- **规则引擎应用**：熟练使用频率聚合、组匹配、MITRE 映射等高级特性
- **正则优化**：开发高效的 PCRE 模式，减少回溯，提高匹配准确性
- **Docker 部署**：配置多容器 Docker Compose，管理服务依赖和持久化存储

### 安全知识
- **Web 攻击原理**：深入理解 SQL 注入、XSS、LFI/RFI、命令注入的攻击模式
- **认证攻击模式**：SSH 暴力破解、Web 登录枚举、凭证填充攻击特征
- **MITRE ATT&CK**：应用行业标准威胁分类法（T1190、T1110、T1595、T1059 等）
- **告警策略设计**：分级告警机制设计，平衡检测率与误报率

---

## 📄 协议

本项目为个人学习与简历展示用途。

基于 [Wazuh](https://github.com/wazuh/wazuh) 开源安全平台构建，Wazuh 使用 GPLv2 协议。

---

> **⭐ 如果这个项目对你有帮助，欢迎 Star！**
