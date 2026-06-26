# 安澜·SIEM 安全监测系统 - 架构说明

## 系统架构总览

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

## 组件说明

### 1. Wazuh Indexer
- 基于 OpenSearch（Elasticsearch 7.x 分支）
- 存储安全事件和告警数据，提供全文搜索能力
- 提供 REST API 接口供 Dashboard 查询
- 管理索引生命周期和数据保留策略

### 2. Wazuh Server（管理器）
- Wazuh 集群的中央管理节点
- 包含 **规则引擎**，负责事件分析和告警判定
- 运行 **自定义解码器** 对日志进行结构化解析
- 解码器和规则配置文件位置：
  - `/var/ossec/etc/decoders/` - XML 格式解码器
  - `/var/ossec/etc/rules/` - XML 格式检测规则
- Filebeat 将告警数据发送至 Indexer

### 3. Wazuh Dashboard
- OpenSearch Dashboards（Kibana 基础）可视化平台
- 预配置的安全监控面板
- 支持安全事件实时监测和分析
- 自定义可视化图表

## 数据处理流程

```
日志采集 → 解码器解析 → 规则引擎评估 → 告警生成 → OpenSearch 索引 → Dashboard 可视化
```

### 解码器处理管线

```
原始日志（syslog/JSON）
       │
       ▼
  [Prematch 预匹配] ───→ 不匹配 ───→ 使用默认解码器
       │
       ▼（匹配）
  [Regex 正则提取]
       │
       ▼
  [Order 字段映射]
       │
       ▼
  结构化事件（字段名:值）
```

### 规则引擎评估流程

```
结构化事件
       │
       ▼
  [规则匹配] ───→ 不匹配 ───→ 仅存储事件
       │                            │
       ▼（匹配）                     ▼
  [生成告警]                  OpenSearch 索引
       │
       ▼
  [MITRE ATT&CK 映射]
       │
       ▼
  [Dashboard 告警展示]
```

## 项目目录结构

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
├── scripts/                          # 部署与测试脚本
├── docs/                             # 项目文档
└── README.md                         # 项目说明
```
