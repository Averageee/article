#!/bin/bash

# 网络连通性测试脚本

echo "=== ThresholdPRF 网络连通性测试 ==="
echo ""

# 读取network.conf
if [ ! -f "network.conf" ]; then
    echo "错误: network.conf 不存在"
    exit 1
fi

# 解析配置
SERVER_IP=$(grep "^SERVER_IP" network.conf | awk '{print $2}')
SERVER_PORT=$(grep "^SERVER_PORT" network.conf | awk '{print $2}')

echo "服务器配置: $SERVER_IP:$SERVER_PORT"
echo ""

# 测试服务器端口
echo "测试服务器端口..."
if timeout 2 bash -c "echo > /dev/tcp/$SERVER_IP/$SERVER_PORT" 2>/dev/null; then
    echo "✓ 服务器端口 $SERVER_IP:$SERVER_PORT 可访问"
else
    echo "✗ 服务器端口 $SERVER_IP:$SERVER_PORT 不可访问"
fi
echo ""

# 测试设备端口
echo "测试设备端口..."
grep "^DEVICE" network.conf | while read -r line; do
    dev_id=$(echo $line | awk '{print $2}')
    dev_ip=$(echo $line | awk '{print $3}')
    dev_port=$(echo $line | awk '{print $4}')
    
    if timeout 2 bash -c "echo > /dev/tcp/$dev_ip/$dev_port" 2>/dev/null; then
        echo "✓ 设备$dev_id ($dev_ip:$dev_port) 可访问"
    else
        echo "✗ 设备$dev_id ($dev_ip:$dev_port) 不可访问"
    fi
done

echo ""
echo "测试完成"
echo ""
echo "提示："
echo "- 如果端口不可访问，请检查："
echo "  1. 对应机器上的程序是否已启动"
echo "  2. 防火墙设置是否允许相应端口"
echo "  3. IP地址是否正确" 