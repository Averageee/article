#!/bin/bash

# 停止所有分布式组件

echo "=== ThresholdPRF 停止脚本 ==="
echo ""

# 配置部分
SERVER_HOST="192.168.1.100"
SERVER_USER="average"

DEVICE_HOSTS=("192.168.1.101" "192.168.1.102" "192.168.1.103")
DEVICE_USER="average"

# 停止服务器
echo ">>> 停止服务器 $SERVER_HOST"
ssh $SERVER_USER@$SERVER_HOST "pkill -f server_main" || echo "服务器未运行或已停止"

# 停止设备
for i in "${!DEVICE_HOSTS[@]}"; do
    device_id=$((i+1))
    host=${DEVICE_HOSTS[$i]}
    echo ">>> 停止设备$device_id $host"
    ssh $DEVICE_USER@$host "pkill -f device_main" || echo "设备$device_id 未运行或已停止"
done

echo ""
echo "=== 所有组件已停止 ===" 