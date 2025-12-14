#!/bin/bash

# 一键启动所有分布式组件
# 需要配置SSH免密登录

set -e

echo "=== ThresholdPRF 一键启动脚本 ==="
echo ""

# 配置部分
SERVER_HOST="192.168.1.100"
SERVER_USER="average"

DEVICE_HOSTS=("192.168.1.101" "192.168.1.102" "192.168.1.103")
DEVICE_USER="average"

REMOTE_DIR="/home/average/code"

# 启动服务器
echo ">>> 启动服务器 $SERVER_HOST"
ssh $SERVER_USER@$SERVER_HOST "cd $REMOTE_DIR/build && nohup ./server_main > server.log 2>&1 &"
echo "服务器已启动，日志: server.log"
sleep 2

# 启动设备
for i in "${!DEVICE_HOSTS[@]}"; do
    device_id=$((i+1))
    host=${DEVICE_HOSTS[$i]}
    echo ">>> 启动设备$device_id $host"
    ssh $DEVICE_USER@$host "cd $REMOTE_DIR/build && nohup ./device_main $device_id > device$device_id.log 2>&1 &"
    echo "设备$device_id 已启动，日志: device$device_id.log"
    sleep 1
done

echo ""
echo "=== 所有组件已启动 ==="
echo ""
echo "查看日志："
echo "  服务器: ssh $SERVER_USER@$SERVER_HOST 'tail -f $REMOTE_DIR/build/server.log'"
for i in "${!DEVICE_HOSTS[@]}"; do
    device_id=$((i+1))
    echo "  设备$device_id: ssh $DEVICE_USER@${DEVICE_HOSTS[$i]} 'tail -f $REMOTE_DIR/build/device$device_id.log'"
done
echo ""
echo "停止所有组件: ./stop_all.sh" 