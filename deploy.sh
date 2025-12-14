#!/bin/bash

# ThresholdPRF 分布式部署脚本
# 此脚本将代码和配置文件分发到各个节点并编译

set -e

echo "=== ThresholdPRF 分布式部署脚本 ==="
echo ""

# 配置部分 - 根据实际情况修改
SERVER_HOST="192.168.1.100"
SERVER_USER="average"

DEVICE_HOSTS=("192.168.1.101" "192.168.1.102" "192.168.1.103")
DEVICE_USER="average"

REMOTE_DIR="/home/average/code"
LOCAL_DIR="$(pwd)"

# 检查network.conf是否存在
if [ ! -f "network.conf" ]; then
    echo "错误: network.conf 不存在，请先创建配置文件"
    exit 1
fi

echo "当前配置:"
cat network.conf
echo ""
read -p "确认使用以上配置进行部署？(y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "部署已取消"
    exit 0
fi

# 函数：部署到单个节点
deploy_to_node() {
    local host=$1
    local user=$2
    local node_type=$3
    
    echo ">>> 部署到 $node_type: $user@$host"
    
    # 创建远程目录
    ssh $user@$host "mkdir -p $REMOTE_DIR"
    
    # 同步代码（排除build目录）
    rsync -avz --exclude 'build' --exclude '.git' \
          $LOCAL_DIR/ $user@$host:$REMOTE_DIR/
    
    # 远程编译
    ssh $user@$host "cd $REMOTE_DIR && ./build_ubuntu.sh"
    
    echo ">>> $node_type ($host) 部署完成"
    echo ""
}

# 部署到服务器
echo "=== 部署服务器 ==="
deploy_to_node $SERVER_HOST $SERVER_USER "Server"

# 部署到设备
echo "=== 部署设备节点 ==="
for i in "${!DEVICE_HOSTS[@]}"; do
    device_id=$((i+1))
    deploy_to_node ${DEVICE_HOSTS[$i]} $DEVICE_USER "Device$device_id"
done

echo "=== 部署完成 ==="
echo ""
echo "下一步操作："
echo "1. 在服务器上启动: ssh $SERVER_USER@$SERVER_HOST 'cd $REMOTE_DIR/build && ./server_main'"
for i in "${!DEVICE_HOSTS[@]}"; do
    device_id=$((i+1))
    echo "$((i+2)). 在设备${device_id}上启动: ssh $DEVICE_USER@${DEVICE_HOSTS[$i]} 'cd $REMOTE_DIR/build && ./device_main $device_id'"
done
echo ""
echo "或使用 start_all.sh 脚本一键启动所有组件" 