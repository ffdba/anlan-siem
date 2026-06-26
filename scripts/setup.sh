# 安澜·SIEM 安全监测系统 - 部署脚本
# 通过 Docker Compose 部署 Wazuh 集群并安装自定义解码器和规则
# ======================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "================================================"
echo "  安澜·SIEM 安全监测系统 - 部署脚本"
echo "================================================"

# 第一步：检查环境依赖
echo "[1/5] 检查环境依赖..."
command -v docker >/dev/null 2>&1 || { echo "错误：未安装 Docker"; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "错误：未安装 docker-compose"; exit 1; }
echo "  - Docker: OK"
echo "  - docker-compose: OK"

# 第二步：启动 Wazuh 集群
echo "[2/5] 通过 Docker Compose 启动 Wazuh 集群..."
cd "$PROJECT_DIR"
docker-compose up -d
echo "  - Wazuh 集群启动成功"

# 第三步：等待服务初始化
echo "[3/5] 等待服务初始化（约 90 秒）..."
sleep 90

# 第四步：安装自定义解码器
echo "[4/5] 安装自定义解码器..."
DOCKER_MANAGER="wazuh-server"
docker cp "$PROJECT_DIR/wazuh_config/decoders/" "$DOCKER_MANAGER:/var/ossec/etc/"
docker exec "$DOCKER_MANAGER" chown -R wazuh:wazuh /var/ossec/etc/decoders
echo "  - 自定义解码器安装完成"

# 第五步：安装自定义规则并重启
echo "[5/5] 安装自定义检测规则..."
docker cp "$PROJECT_DIR/wazuh_config/rules/" "$DOCKER_MANAGER:/var/ossec/etc/"
docker exec "$DOCKER_MANAGER" chown -R wazuh:wazuh /var/ossec/etc/rules
docker exec "$DOCKER_MANAGER" /var/ossec/bin/wazuh-control restart
echo "  - 自定义检测规则安装完成"
echo "  - Wazuh 管理器已重启"

echo ""
echo "================================================"
echo "  部署完成！"
echo "================================================"
echo ""
echo "访问 Wazuh Dashboard：https://localhost"
echo "默认账号：admin / SecretPassword"
echo ""
echo "已安装的自定义解码器："
ls -1 "$PROJECT_DIR/wazuh_config/decoders/"
echo ""
echo "已安装的自定义规则："
ls -1 "$PROJECT_DIR/wazuh_config/rules/"
echo ""
echo "测试规则：docker exec wazuh-server /var/ossec/bin/wazuh-logtest"
echo "================================================"
