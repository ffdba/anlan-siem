# 安澜·SIEM 安全监测系统 - 排错指南

## 常见问题与解决方案

### Docker 部署问题

**问题：Wazuh Indexer 启动失败**
```bash
# 查看容器日志
docker logs wazuh-indexer
# 检查内存使用
docker stats wazuh-indexer
# 解决方法：增加宿主机 vm.max_map_count
# Linux: sudo sysctl -w vm.max_map_count=262144
```

**问题：容器不断重启**
```bash
# 查看容器日志
docker logs wazuh-server
# 常见原因：等待 Indexer 初始化时间不足
# 解决方法：延长等待时间后重启
docker-compose restart wazuh.server
```

### 规则开发问题

**问题：规则未触发**
```bash
# 1. 检查解码器是否先匹配成功
echo '<样本日志>' | docker exec -i wazuh-server /var/ossec/bin/wazuh-logtest
# 2. 检查规则 XML 语法
docker exec wazuh-server /var/ossec/bin/wazuh-logtest -a
# 3. 确认规则 ID 无冲突（自定义使用 100000+）
```

**问题：误报率过高**
```
解决方案：
- 使用更精确的正则表达式
- 添加 AND 条件（多个 field 条件）
- 调整频率阈值
- 增加告警忽略时间
- 添加 NOT 排除条件
```

### 解码器问题

**问题：日志未被解析**
```bash
# 开启解码器调试日志
docker exec wazuh-server sed -i 's/<logall>no/<logall>yes/' /var/ossec/etc/ossec.conf
docker exec wazuh-server /var/ossec/bin/wazuh-control restart
# 查看调试输出
docker exec wazuh-server tail -f /var/ossec/logs/decoders/debug.log
```

### Dashboard 问题

**问题：Dashboard 无数据**
```bash
# 验证是否生成告警
docker exec wazuh-server tail -f /var/ossec/logs/alerts/alerts.json
# 检查 Filebeat 连接
docker exec wazuh-server filebeat test output
# 检查 Indexer 索引
curl -k -u admin:admin https://localhost:9200/_cat/indices
```

## 常用命令速查

```bash
# 查看 Wazuh 管理器状态
docker exec wazuh-server /var/ossec/bin/wazuh-control status

# 查看实时告警（JSON 格式）
docker exec wazuh-server tail -f /var/ossec/logs/alerts/alerts.json | jq .

# 重启 Wazuh 管理器
docker exec wazuh-server /var/ossec/bin/wazuh-control restart

# 列出已加载规则
docker exec wazuh-server /var/ossec/bin/wazuh-logtest -l

# 按规则 ID 统计告警数量
docker exec wazuh-server cat /var/ossec/logs/alerts/alerts.json | jq -r '.rule.id' | sort | uniq -c | sort -rn

# 查看事件统计
docker exec wazuh-server cat /var/ossec/logs/stats/total_events.log

# 交互式日志测试
docker exec -it wazuh-server /var/ossec/bin/wazuh-logtest
```
