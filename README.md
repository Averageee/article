# ThresholdPRF - 阈值伪随机函数系统

基于Boost.Asio的分布式阈值PRF系统，支持设备撤销和密钥更新功能。

## 功能特性

- ✅ **阈值PRF计算**：分布式计算伪随机函数，无单点故障
- ✅ **秘密分享**：使用(t-1, n-1)和(2,2)秘密分享方案
- ✅ **设备撤销**：动态撤销受损设备
- ✅ **密钥更新**：支持在线密钥更新
- ✅ **分布式部署**：支持在不同Ubuntu 25.04设备上运行
- ✅ **灵活配置**：支持配置文件和环境变量配置

## 快速开始

### 本地测试（单机）

```bash
# 1. 编译
./build_ubuntu.sh

# 2. 启动组件（不同终端）
cd build

# 终端1: 服务器
./server_main

# 终端2-4: 设备
./device_main 1
./device_main 2
./device_main 3

# 终端5: 用户客户端
./user_main
```

### 分布式部署

详见 [DEPLOYMENT.md](DEPLOYMENT.md) 完整部署指南。

简要步骤：

```bash
# 1. 编辑网络配置
vim network.conf

# 2. 部署到所有机器
./deploy.sh

# 3. 启动所有组件
./start_all.sh

# 4. 测试网络连通性
./test_network.sh
```

## 系统架构

```
┌─────────────┐
│   User      │ ← 发起PRF请求
│   Client    │
└──────┬──────┘
       │
       ├──────────────┐
       │              │
       v              v
┌─────────────┐  ┌──────────────┐
│   Server    │  │   Device 1   │ ← 持有密钥份额
│             │  │   Device 2   │
│  (协调者)   │  │   Device 3   │
└─────────────┘  └──────────────┘
```

## 依赖项

- Ubuntu 25.04
- CMake >= 3.16
- C++17 编译器
- Boost (libboost-all-dev)
- OpenSSL (libssl-dev)
- NTL (libntl-dev)
- GMP (libgmp-dev)

## 网络配置

### 配置文件 `network.conf`

```conf
# 服务器配置
SERVER_IP 192.168.1.100
SERVER_PORT 9000

# 设备配置
DEVICE 1 192.168.1.101 9101
DEVICE 2 192.168.1.102 9101
DEVICE 3 192.168.1.103 9101
```

### 环境变量（可选）

```bash
export SERVER_IP=192.168.1.100
export SERVER_PORT=9000
```

配置优先级: **环境变量** > **配置文件** > **默认值**

## 使用示例

启动用户客户端后，按提示输入：

```
Enter n_vector: 3
Enter n_devices: 3
Enter threshold t: 2
Enter user password pw: mypassword
```

系统将执行：
1. 秘密生成和分发
2. PRF计算和加密
3. 密钥验证
4. 设备撤销（可选）
5. 密钥更新（可选）

## 部署脚本

| 脚本 | 功能 |
|------|------|
| `build_ubuntu.sh` | 编译项目 |
| `deploy.sh` | 自动化部署到多台机器 |
| `start_all.sh` | 启动所有组件 |
| `stop_all.sh` | 停止所有组件 |
| `test_network.sh` | 测试网络连通性 |

## 文档

- [DEPLOYMENT.md](DEPLOYMENT.md) - 分布式部署详细指南
- [DISTRIBUTED_CHANGES.md](DISTRIBUTED_CHANGES.md) - 代码改动说明
- [network.conf.example](network.conf.example) - 配置文件示例

## 技术细节

### 密码学基础

- **有限域运算**：基于NTL库，模素数p = 2147483647
- **PRF构造**：内积PRF，两阶段舍入（q→q1→p）
- **秘密分享**：加性秘密分享变体
- **哈希函数**：SHA256

### 网络通信

- **框架**：Boost.Asio
- **协议**：TCP/IP
- **消息格式**：JSON（通过Boost.PropertyTree）

## 故障排查

### 连接失败

```bash
# 检查端口占用
sudo netstat -tulpn | grep 9000

# 测试连通性
telnet 192.168.1.100 9000

# 检查防火墙
sudo ufw status
```

### 配置问题

```bash
# 验证配置
cat network.conf

# 测试网络
./test_network.sh
```

## 安全注意事项

⚠️ **本项目为研究/教学用途**

生产环境建议：
- 使用TLS加密通信
- 实施访问控制和认证
- 安全存储密钥份额
- 定期进行安全审计

## 许可证

根据项目需求设定。

## 贡献

欢迎提交Issue和Pull Request。

## 更新日志

### 2025-09-30
- ✨ 新增：分布式部署支持
- ✨ 新增：配置文件系统
- ✨ 新增：部署和管理脚本
- 📝 新增：完整部署文档
- 🔧 改进：网络配置灵活性

### 初始版本
- ✅ 基础阈值PRF功能
- ✅ 设备撤销机制
- ✅ 密钥更新功能 