# 分布式部署改动说明

## 概述

本次改动使ThresholdPRF系统支持在不同的Ubuntu 25.04设备上运行，而不仅限于单机模拟。**所有原有的计算逻辑和数学实现保持不变**，仅改变了网络通信方式。

## 改动内容

### 1. 新增文件

#### `common/config.hpp`
- 网络配置管理模块
- 支持从配置文件和环境变量读取IP/端口
- 提供全局配置对象 `g_config`

#### `network.conf`
- 默认网络配置文件（本地测试模式）
- 可修改为实际的分布式IP地址

#### `network.conf.example`
- 配置文件示例，包含详细注释
- 展示分布式部署的配置方式

#### `DEPLOYMENT.md`
- 完整的分布式部署指南
- 包含故障排查和最佳实践

#### 部署脚本
- `deploy.sh`: 自动化部署到多台机器
- `start_all.sh`: 一键启动所有组件
- `stop_all.sh`: 停止所有组件
- `test_network.sh`: 网络连通性测试

### 2. 修改的文件

#### `user/user_main.cpp`
**改动点：**
1. 包含 `common/config.hpp`
2. 在 `main()` 开始调用 `init_config()` 初始化配置
3. 所有 `send_json()` 调用从硬编码 `"127.0.0.1"` 改为使用配置：
   - 发送到服务器: `g_config.server_ip`, `g_config.server_port`
   - 发送到设备: `g_config.get_device_ip(dev)`, `g_config.get_device_port(dev)`

**代码变化示例：**
```cpp
// 之前
send_json("127.0.0.1", 9000, pt, &reply);

// 之后
send_json(g_config.server_ip, g_config.server_port, pt, &reply);
```

#### `server/server_main.cpp`
**改动点：**
1. 包含 `common/config.hpp`
2. 在 `main()` 开始调用 `init_config()` 初始化配置
3. `tcp::acceptor` 使用 `g_config.server_port` 而不是硬编码 `9000`
4. `send_json_to_device()` 使用配置的设备IP/端口

**代码变化示例：**
```cpp
// 之前
tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 9000));
sock.connect({boost::asio::ip::make_address("127.0.0.1"), (unsigned short)(9100 + device_id)});

// 之后
tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), g_config.server_port));
sock.connect({boost::asio::ip::make_address(g_config.get_device_ip(device_id)), 
              (unsigned short)g_config.get_device_port(device_id)});
```

#### `device/device_main.cpp`
**改动点：**
1. 包含 `common/config.hpp`
2. 在 `main()` 开始调用 `init_config()` 初始化配置
3. `tcp::acceptor` 使用 `g_config.get_device_port(device_id)` 而不是 `9100 + device_id`

**代码变化示例：**
```cpp
// 之前
tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 9100 + device_id));

// 之后
tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), g_config.get_device_port(device_id)));
```

## 未改动的内容

✅ **所有数学算法和密码学逻辑完全不变**
✅ 秘密分享机制（`share.hpp`）
✅ PRF计算逻辑（`crypto.hpp`）
✅ 通信协议和消息格式（`net.hpp`）
✅ 数据结构和状态管理

## 配置优先级

系统支持灵活的配置方式，优先级从高到低：

1. **环境变量** - 运行时设置
2. **配置文件** - `network.conf`
3. **默认值** - 127.0.0.1 本地地址

## 使用示例

### 本地测试（保持原有行为）
```bash
# 默认 network.conf 配置为本地地址
./build_ubuntu.sh
cd build

# 终端1
./server_main

# 终端2
./device_main 1

# 终端3
./device_main 2

# 终端4
./user_main
```

### 分布式部署

1. **编辑配置文件** `network.conf`:
```conf
SERVER_IP 192.168.1.100
SERVER_PORT 9000
DEVICE 1 192.168.1.101 9101
DEVICE 2 192.168.1.102 9101
DEVICE 3 192.168.1.103 9101
```

2. **复制到各机器并编译**:
```bash
# 使用部署脚本
./deploy.sh
```

3. **启动各组件**:
```bash
# 或手动启动
# 在 192.168.1.100 上
./server_main

# 在 192.168.1.101 上
./device_main 1

# 在 192.168.1.102 上
./device_main 2

# 在任意机器上
./user_main
```

## 兼容性

- ✅ 完全向后兼容：默认配置仍为本地模式
- ✅ 代码结构保持不变，只是通信地址可配置
- ✅ 所有原有功能正常工作
- ✅ 支持 Ubuntu 25.04（根据项目要求）

## 验证改动

测试改动未破坏原有功能：

```bash
# 使用默认本地配置测试
./build_ubuntu.sh
cd build

# 按原有方式启动并测试所有功能
# - 密钥注册
# - PRF计算
# - 设备撤销
# - 密钥更新
```

## 技术细节

### 配置文件格式
```
# 注释行
SERVER_IP <IP地址>
SERVER_PORT <端口号>
DEVICE <设备ID> <IP地址> <端口号>
```

### 环境变量
```bash
export SERVER_IP=192.168.1.100
export SERVER_PORT=9000
./server_main
```

### 默认值
- 服务器: 127.0.0.1:9000
- 设备N: 127.0.0.1:(9100+N)

## 总结

本次改动**最小化侵入性**，通过引入配置层实现了分布式部署能力，同时：
- 保持所有计算逻辑不变
- 保持代码结构清晰
- 支持灵活配置
- 向后兼容原有单机模式 