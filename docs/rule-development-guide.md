# 检测规则开发

## 单事件与历史事件

当前事件条件使用 `if_sid` / `if_group`，历史关联使用 `if_matched_sid` / `if_matched_group`。二者不互换。

```xml
<!-- 基础事件非零等级，允许保留历史 -->
<rule id="100046" level="1">
  <if_sid>100000,100005,100006</if_sid>
  <field name="status_code" type="pcre2">^404$</field>
  <description>Anlan Web not-found event.</description>
  <group>anlan_web_not_found,</group>
</rule>

<!-- 当前配置中的同源关联 -->
<rule id="100045" level="7" frequency="20" timeframe="120">
  <if_matched_sid>100046</if_matched_sid>
  <same_srcip />
  <description>Repeated not-found events from one source.</description>
  <group>web_attack,reconnaissance,scanning,</group>
  <mitre><id>T1595</id></mitre>
</rule>
```

这里只展示规则片段，须置于 group 容器内。Wazuh 的计数、历史保留、`ignore` 和规则优先级由原生引擎决定；不能用 Python 正则匹配或简单计数器声称已验证 frequency 行为。原生序列样本以真实触发结果为准。

## 当前约束

- 自定义 ID 使用 Wazuh 建议范围 `100000` 至 `120000`，本仓库不允许重复。
- `decoded_as` 是实际 decoder 名称，不是用 `|` 拼接的候选列表。
- Web 条件只使用统一字段；`field` 正则显式指定 PCRE2。
- 关联规则必须有历史选择器、正频率/时间窗口、源 IP 隔离。
- 用户枚举使用 `different_user`；它表达原生不同用户条件，不等于自行实现的“精确 N 个唯一用户名”。
- SSH root 登录读取认证成功事件中的 `dstuser`，不是用认证失败作为成功事件。
- 高等级规则需检查 ATT&CK 映射；基础事件、周末/深夜上下文等可不映射。
- 顶层 group 不应包含所有攻击类别，否则 RFI、命令注入等事件也会继承 `xss` 标签。

## 控制误判

单次管理路径访问设置为等级 3/4 的上下文；重复访问再通过历史关联提示扫描。该规则不保证访问路径各不相同。

命令参数出现 `cmd=help` 不直接判为命令注入；脚本上传线索还需写请求方法及上传目录，普通 `POST /index.php` 是反例。URL 规则不检查请求体，不进行通用 URL 解码，也不能证明服务端执行了载荷。

认证失败后成功可能是用户重试；root 登录、sudo、创建账号和夜间登录也可能是批准的运维。报告必须保留“需核查”的语义，不能把规则等级 14/15 写成“确认失陷”。

## ATT&CK 与分级

本配置使用 T1190、T1110、T1595、T1078、T1059 等标签组织线索，映射仅提供检索背景，不代表技术已成功执行。静态校验仅检查 ID 格式，不审定整个 ATT&CK 语义。

离线队列分级：14-15 为 `critical`，11-13 为 `high`，7-10 为 `medium`，0-6 为 `low`。这是本项目的规则等级排序，不是 CVSS、业务风险评分或 Wazuh 官方统一分类。

## 回归流程

1. 修改最小范围的 decoder / rule。
2. 执行 `python -S -m anlan validate`，检查清单和警告。
3. 执行 Python 回归，确认字段与项目契约。
4. 在 `tests/logtest-cases.json` 增加原生期望，包括 decoder、字段、ID、等级及必要的整段禁止规则。
5. 在安装相同配置的测试 manager 上运行真实引擎断言，保留 `output/logtest-results.json`。
6. 独立验证授权环境里的采集和告警链路，再评估上线；不要由测试脚本重启生产服务。

同一个序列在同一 logtest 会话中输入，以保留关联历史；不同案例使用独立会话。禁止规则命中发生在中间行也必须让反例失败。
