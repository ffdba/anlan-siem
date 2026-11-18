# 解码器字段契约

## 来源与优先级

Wazuh 内置 Web decoder 可能在自定义 decoder 之前匹配普通访问日志。为了让实验输入可控，本项目约定：

| 来源标记 | decoder | 格式 |
| --- | --- | --- |
| `ANLAN_WEB` | `web-access-log` + 子 decoder | Common 或 Combined |
| `ANLAN_APACHE` | `apache-access-log` | Common 或 Combined |
| `ANLAN_NGINX` | `nginx-access-log` | Common 或 Combined，支持 IPv6 |

Common Log Format 没有 Referer / User-Agent；Combined Log Format 追加这两个字段。通用 decoder 也允许无前缀输入，但不能保证赢过内置 decoder。采集路径必须先在授权测试环境中用原生引擎确认。

## 统一字段

| 字段 | 含义 | 示例 |
| --- | --- | --- |
| `srcip` | IPv4 / IPv6 来源 | `192.0.2.10` |
| `log_timestamp` | 访问日志中的原始时间字符串 | `19/Nov/2026:09:00:00 +0800` |
| `http_method` | 请求方法 | `GET` |
| `url` | 原始请求路径及查询字符串 | `/search?q=demo` |
| `status_code` | HTTP 状态码字符串 | `200` |
| `response_size` | 响应大小或未知标记 | `120` / `-` |
| `referer` | Combined 中的来源头 | `-` |
| `user_agent` | Combined 中的客户端头 | `demo-client` |

不再混用 `request_path`、`request_method`、`body_bytes`、`size` 等别名。`log_timestamp` 不等于 Wazuh 告警的顶层 `timestamp`；离线研判读取后者并要求显式时区。

## 开发要求

1. 先用 `prematch` 确定来源，避免宽泛的 IP 前缀抢占其他日志。
2. 提取正则显式标注 `type="pcre2"`；不需要提取的括号使用 `(?:...)`。
3. `order` 的字段数与捕获组数一致，访问 decoder 共享核心契约。
4. XML 文本中的 `<`、`&` 必须转义，PCRE2 语法检查与 XML 解析是两回事。
5. 添加正例、正常输入反例及 IPv6 / 未知大小等边界样本。

错误日志 decoder 提取有限格式的 module、level、message 等字段，不承诺覆盖所有 Apache / Nginx 日志版本，也没有完整的错误日志攻击检测规则。

## 验证

静态检查：

```bash
python -S -m anlan validate
```

原生测试，在已安装本项目配置的授权测试 manager 中执行：

```bash
python scripts/verify-logtest.py --container YOUR_TEST_MANAGER
```

或者：

```bash
python scripts/verify-logtest.py --binary /var/ossec/bin/wazuh-logtest
```

脚本断言 Phase 2 decoder 与字段，并核对 Phase 3 规则 ID / 等级。它不模拟原生正则或 decoder 优先级；工具不可用、输出不完整或断言失败会返回非零退出码。

不要通过自动修改 `ossec.conf`、关闭内置 decoder 或重启生产 manager 来“修好”样本；先确认采集格式和 Phase 2 输出。
