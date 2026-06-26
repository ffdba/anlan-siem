# 安澜·SIEM 安全监测系统 - 解码器开发指南

## 概述

解码器（Decoder）是 Wazuh 日志处理流程的第一环，负责将原始日志字符串解析为结构化字段，供规则引擎评估使用。本文档记录了自定义解码器的开发方法和最佳实践。

## 解码器三级处理管线

```
原始日志字符串
       │
       ▼
  1. PREMATCH（预匹配）
     - 快速模式匹配，筛选日志类型
     - 决定使用哪个解码器处理
       │
       ▼（找到匹配）
  2. REGEX（正则提取）
     - 使用捕获组提取字段
     - 定位关键信息位置
       │
       ▼
  3. ORDER（字段映射）
     - 捕获组按顺序映射到字段名
     - 字段可供规则引擎直接使用
```

## 解码器开发步骤

### 第一步：分析日志格式

```bash
# 以 Apache 访问日志为例
192.168.1.1 - - [26/Jun/2026:10:15:30 +0800] "GET /index.html HTTP/1.1" 200 2345
# 字段：源IP  标识 用户  [时间]  "方法 路径 协议"  状态码  大小
```

### 第二步：编写解码器

```xml
<decoder name="apache-access-log">
    <!-- Prematch：快速预匹配规则 -->
    <prematch>^(\d+\.\d+\.\d+\.\d+) </prematch>
    <!-- Regex：正则提取字段，() 内为捕获组 -->
    <regex>^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)(?: [^"]*)?" (\d+) (\d+)$</regex>
    <!-- Order：捕获组顺序映射到字段名 -->
    <order>srcip, timestamp, request_method, request_path, status_code, response_size</order>
</decoder>
```

### 第三步：验证解析效果

```bash
# 使用 wazuh-logtest 验证解码器
echo '192.168.1.1 - - [26/Jun/2026:10:15:30 +0800] "GET / HTTP/1.1" 200 2345' | \
    docker exec -i wazuh-server /var/ossec/bin/wazuh-logtest
```

## 自定义解码器一览

### 1. 通用 Web 访问解码器（001-web-decoder.xml）
解析标准 Combined Log Format（CLF）格式的 Web 日志：

**示例输入**：
```
203.0.113.5 - - [26/Jun/2026:10:20:00 +0800] "GET /login.php?id=1 HTTP/1.1" 403 234
```

**提取字段**：

| 字段 | 值 |
|------|-----|
| srcip | 203.0.113.5 |
| timestamp | 26/Jun/2026:10:20:00 +0800 |
| http_method | GET |
| url | /login.php?id=1 |
| status_code | 403 |
| size | 234 |
| referer | - |
| user_agent | - |

### 2. Apache 解码器（002-apache-decoder.xml）
Apache 专用解析器，支持错误日志：

- **访问日志字段**：srcip, timestamp, request_method, request_path, status_code, response_size
- **错误日志字段**：timestamp, module, srcip, error_message

**错误日志示例**：
```
[Mon Jun 26 10:20:00.123456 2026] [php:notice] [pid 12345] [client 203.0.113.5:54321] WordPress database error...
```

### 3. Nginx 解码器（003-nginx-decoder.xml）
Nginx 专用解析器，支持更多字段：

- **访问日志字段**：srcip, identity, timestamp, request_method, request_path, status_code, body_bytes, http_referer, user_agent
- **错误日志字段**：timestamp, log_level, connection_id, srcip, server_name, request_method, request_uri, upstream, host

## Prematch 策略

选择合适的预匹配规则，避免不必要的正则运算：

| 策略 | 示例 |
|------|------|
| IP 前缀匹配 | `^\d+\.\d+\.\d+\.\d+ ` |
| 关键词匹配 | `\[error\]` |
| 应用特征匹配 | `(PHP Fatal\|WordPress\|mod_security)` |

## 正则优化技巧

1. **使用锚点**：正则始终以 `^` 开头
2. **减少回溯**：使用非捕获组 `(?:...)` 代替捕获组 `(...)` 在不需提取时
3. **限定范围**：用 `[^\]]+` 代替 `.*` 匹配引号内的内容
4. **按序排列**：解码器按优先级从高到低排列
5. **渐进开发**：先写 prematch，再逐步完善 regex

## 调试方法

```bash
# 交互式测试
echo '<日志内容>' | docker exec -i wazuh-server /var/ossec/bin/wazuh-logtest

# 开启解码器调试日志
docker exec wazuh-server sed -i 's/<logall>no/<logall>yes/' /var/ossec/etc/ossec.conf
docker exec wazuh-server /var/ossec/bin/wazuh-control restart
docker exec wazuh-server tail -f /var/ossec/logs/decoders/debug.log
```

## 字段命名规范

使用统一、语义化的字段名：

| 字段名 | 含义 |
|--------|------|
| srcip | 源 IP 地址 |
| dstip | 目标 IP 地址 |
| srcuser | 源用户名 |
| http_method | HTTP 请求方法（GET、POST 等） |
| status_code | HTTP 状态码 |
| url / request_path | 请求路径 |
| user_agent | User-Agent 请求头 |
| http_referer | Referer 来源头 |
| error_message | 错误描述 |
| timestamp | 事件时间戳 |
| response_size / body_bytes | 响应大小（字节） |
