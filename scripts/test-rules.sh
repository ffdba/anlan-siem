#!/bin/bash
# ======================================================
# 安澜·SIEM 安全监测系统 - 规则测试脚本
# 使用样本日志批量测试自定义解码器和规则
# ======================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SAMPLE_LOGS="$PROJECT_DIR/sample_logs"
DOCKER_MANAGER="wazuh-server"

echo "================================================"
echo "  安澜·SIEM 规则测试脚本"
echo "================================================"

# 检查 Docker 容器是否运行
docker ps | grep "$DOCKER_MANAGER" >/dev/null 2>&1 || {
    echo "错误：Wazuh 管理器容器未运行"
    echo "请先启动集群：docker-compose up -d"
    exit 1
}

test_rules() {
    local log_file="$1"
    local test_name="$2"
    echo ""
    echo "------------------------------------------"
    echo "  测试：$test_name"
    echo "  文件：$log_file"
    echo "------------------------------------------"

    if [ ! -f "$log_file" ]; then
        echo "  [跳过] 样本日志文件不存在"
        return
    fi

    echo "  [开始] 逐行测试规则匹配..."
    docker cp "$log_file" "$DOCKER_MANAGER:/tmp/test_log.txt"
    docker exec "$DOCKER_MANAGER" bash -c "
        while IFS= read -r line; do
            [[ \"\$line\" =~ ^#.*$ ]] && continue
            [[ -z \"\$line\" ]] && continue
            echo \"\$line\" | /var/ossec/bin/wazuh-logtest -q 2>/dev/null || true
        done < /tmp/test_log.txt
    " || echo "  [提示] 部分规则可能需要 wazuh-logtest 交互模式测试"
    echo "  [完成] $test_name"
}

# 测试 Web 攻击规则
test_rules "$SAMPLE_LOGS/web_attacks.log" "Web 攻击检测规则"

# 测试系统攻击规则
test_rules "$SAMPLE_LOGS/system_attacks.log" "系统攻击检测规则"

echo ""
echo "================================================"
echo "  测试完成！"
echo "================================================"
echo ""
echo "如需交互式测试："
echo "  docker exec -it $DOCKER_MANAGER /var/ossec/bin/wazuh-logtest"
echo ""
echo "查看实时告警："
echo "  docker exec $DOCKER_MANAGER tail -f /var/ossec/logs/alerts/alerts.json"
echo "================================================"
