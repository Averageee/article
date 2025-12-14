# ThresholdPRF 分布式部署指南

本文档说明如何在不同的Ubuntu 25.04设备上部署ThresholdPRF系统。

## 系统架构

系统由三类组件组成：
- **Server（服务器）**：协调者，1个实例
- **Device（设备）**：计算节点，n个实例（每个在独立机器上）
- **User（用户客户端）**：发起请求，可在任意机器运行

## 部署前准备

### 1. 网络规划

假设有如下网络拓扑：
```
服务器:    192.168.1.100:9000
设备1:     192.168.1.101:9101
设备2:     192.168.1.102:9101
设备3:     192.168.1.103:9101
用户客户端: 任意位置
```

### 2. 每台机器上的准备工作

在每台Ubuntu 25.04设备上执行：

```bash
# 更新系统
sudo apt update

# 安装依赖
sudo apt install -y cmake build-essential libboost-all-dev \
                    libssl-dev libntl-dev libgmp-dev pkg-config git

# 克隆或复制项目代码
# 如使用git: git clone <your-repo>
# 或使用scp从开发机器复制
```

## 配置步骤

### 1. 创建网络配置文件

在**所有机器**上，编辑 `network.conf` 文件（确保所有机器使用相同配置）：

```conf
# 服务器地址
SERVER_IP 192.168.1.100
SERVER_PORT 9000

# 设备列表（设备ID 设备IP 设备端口）
DEVICE 1 192.168.1.101 9101
DEVICE 2 192.168.1.102 9101
DEVICE 3 192.168.1.103 9101
```

**重要**：所有机器上的 `network.conf` 必须完全一致！

### 2. 编译项目

在**每台机器**上执行：

```bash
cd /path/to/ThresholdPRFBoost
./build_ubuntu.sh
```

## 启动系统

### 1. 启动服务器（192.168.1.100）

```bash
cd build
./server_main
```

输出应该显示：
```
=== 网络配置 ===
服务器: 192.168.1.100:9000
...
[Server] Threshold PRF Server with Device Revocation Support
```

### 2. 启动设备（分别在各自机器上）

**在192.168.1.101上：**
```bash
cd build
./device_main 1
```

**在192.168.1.102上：**
```bash
cd build
./device_main 2
```

**在192.168.1.103上：**
```bash
cd build
./device_main 3
```

每个设备输出应该显示：
```
[Device X] 配置的监听端口: 9101
[Device X] Starting device server
```

### 3. 运行用户客户端（任意机器）

确保该机器也有编译好的程序和正确的 `network.conf`：

```bash
cd build
./user_main
```

按提示输入：
- `n_vector`: 向量维度（如3）
- `n_devices`: 设备数量（如3）
- `threshold t`: 阈值（如2）
- 密码等其他参数

## 防火墙配置

确保各机器间端口开放：

```bash
# 在服务器上（192.168.1.100）
sudo ufw allow 9000/tcp

# 在每个设备上
sudo ufw allow 9101/tcp

# 或临时关闭防火墙测试
sudo ufw disable
```

## 使用环境变量（可选）

除了配置文件，也可以使用环境变量：

```bash
# 服务器
export SERVER_IP=192.168.1.100
export SERVER_PORT=9000
./server_main

# 用户端
export SERVER_IP=192.168.1.100
export SERVER_PORT=9000
./user_main
```

## 快速部署脚本

使用提供的 `deploy.sh` 脚本自动化部署（需要SSH免密登录）：

```bash
# 编辑deploy.sh中的机器列表
./deploy.sh
```

## 测试连接

使用 `test_network.sh` 测试网络连通性：

```bash
./test_network.sh
```

## 故障排查

### 1. 连接超时
- 检查IP地址是否正确
- 检查防火墙设置
- 使用 `telnet <IP> <端口>` 测试连通性

### 2. 配置不一致
- 确保所有机器的 `network.conf` 完全相同
- 检查配置文件是否有多余空格或错误

### 3. 端口占用
```bash
# 检查端口占用
sudo netstat -tulpn | grep <端口号>

# 杀死占用进程
sudo kill -9 <PID>
```

## 本地测试模式

如果只想在单机测试，使用默认的 `network.conf`：

```conf
SERVER_IP 127.0.0.1
SERVER_PORT 9000
DEVICE 1 127.0.0.1 9101
DEVICE 2 127.0.0.1 9102
DEVICE 3 127.0.0.1 9103
```

然后在同一台机器上启动所有组件（不同终端）。

## 注意事项

1. **时钟同步**：建议使用NTP同步各机器时钟
2. **网络稳定性**：确保网络连接稳定，延迟低
3. **数据备份**：重要的密钥份额应当备份
4. **安全性**：生产环境建议使用TLS加密通信 