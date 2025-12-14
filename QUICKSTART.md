# 快速部署指南 - 每个设备需要什么

## 📦 必需文件清单

### 所有设备都需要的文件（共用）

```
项目根目录/
├── CMakeLists.txt          # 编译配置
├── build_ubuntu.sh         # 编译脚本
├── network.conf            # ⚠️ 网络配置（所有设备必须相同！）
│
├── common/                 # 公共库（所有设备必需）
│   ├── config.hpp         # 配置管理
│   ├── crypto.hpp         # 密码学函数
│   ├── share.hpp          # 秘密分享
│   └── net.hpp            # 网络通信
│
├── user/                   # 用户客户端源码
│   └── user_main.cpp
│
├── server/                 # 服务器源码
│   └── server_main.cpp
│
└── device/                 # 设备源码
    └── device_main.cpp
```

### 可选文件（方便管理）
```
├── README.md              # 项目说明
├── DEPLOYMENT.md          # 部署文档
├── network.conf.example   # 配置示例
```

## 🎯 三种部署场景

---

### 场景1：完整复制到每个设备（推荐）

**适用于**：所有设备都是Ubuntu 25.04，需要完整功能

**操作步骤**：

#### 步骤1：打包整个项目
```bash
# 在开发机上
cd /home/average
tar czf code.tar.gz code/ --exclude=code/build --exclude=code/.git
```

#### 步骤2：复制到每个设备
```bash
# 复制到服务器设备 (192.168.1.100)
scp code.tar.gz user@192.168.1.100:~/

# 复制到设备1 (192.168.1.101)
scp code.tar.gz user@192.168.1.101:~/

# 复制到设备2 (192.168.1.102)
scp code.tar.gz user@192.168.1.102:~/

# ... 其他设备
```

#### 步骤3：在每个设备上解压和编译
```bash
# 在每台设备上执行
cd ~
tar xzf code.tar.gz
cd code
./build_ubuntu.sh
```

#### 步骤4：启动对应组件

**在服务器设备上 (192.168.1.100)**：
```bash
cd ~/code/build
./server_main
```

**在设备1上 (192.168.1.101)**：
```bash
cd ~/code/build
./device_main 1
```

**在设备2上 (192.168.1.102)**：
```bash
cd ~/code/build
./device_main 2
```

**在用户客户端机器上**：
```bash
cd ~/code/build
./user_main
```

---

### 场景2：最小化部署（仅部署需要的）

**适用于**：资源受限设备，只部署需要运行的组件

#### 服务器设备最小文件集
```bash
# 在服务器设备上需要
code/
├── CMakeLists.txt
├── build_ubuntu.sh
├── network.conf
├── common/              # 全部文件
├── server/              # 服务器源码
│   └── server_main.cpp
├── user/                # 需要（因为CMakeLists.txt会编译）
│   └── user_main.cpp
└── device/              # 需要（因为CMakeLists.txt会编译）
    └── device_main.cpp
```

#### 设备节点最小文件集
```bash
# 在每个设备节点上需要
code/
├── CMakeLists.txt
├── build_ubuntu.sh
├── network.conf
├── common/              # 全部文件
├── device/              # 设备源码
│   └── device_main.cpp
├── user/                # 需要（因为CMakeLists.txt会编译）
│   └── user_main.cpp
└── server/              # 需要（因为CMakeLists.txt会编译）
    └── server_main.cpp
```

> **注意**：由于CMakeLists.txt会编译所有三个组件，所以所有源码都需要，但运行时只启动对应的可执行文件。

---

### 场景3：使用自动化脚本部署

**前提条件**：
- 所有设备已配置SSH免密登录
- 开发机可以访问所有设备

**操作步骤**：

#### 步骤1：编辑部署脚本配置
```bash
vim deploy.sh
```

修改这些变量：
```bash
SERVER_HOST="192.168.1.100"
SERVER_USER="average"
DEVICE_HOSTS=("192.168.1.101" "192.168.1.102" "192.168.1.103")
DEVICE_USER="average"
REMOTE_DIR="/home/average/code"
```

#### 步骤2：执行自动部署
```bash
./deploy.sh
```

脚本会自动：
- 将代码同步到所有设备
- 在每个设备上执行编译

#### 步骤3：一键启动
```bash
# 启动所有组件
./start_all.sh

# 或查看日志
ssh average@192.168.1.100 'tail -f ~/code/build/server.log'
```

---

## ⚠️ 关键注意事项

### 1. network.conf 必须一致
**所有设备的 `network.conf` 文件必须完全相同！**

示例配置：
```conf
# 这个文件在所有设备上都要一样
SERVER_IP 192.168.1.100
SERVER_PORT 9000
DEVICE 1 192.168.1.101 9101
DEVICE 2 192.168.1.102 9101
DEVICE 3 192.168.1.103 9101
```

### 2. 确保所有依赖已安装
在每台设备上运行：
```bash
sudo apt update
sudo apt install -y cmake build-essential libboost-all-dev \
                    libssl-dev libntl-dev libgmp-dev pkg-config
```

### 3. 防火墙配置
```bash
# 在服务器上
sudo ufw allow 9000/tcp

# 在每个设备上
sudo ufw allow 9101/tcp

# 或临时关闭防火墙测试
sudo ufw disable
```

---

## 📝 快速检查清单

部署前检查：
- [ ] 所有设备已安装Ubuntu 25.04
- [ ] 所有设备已安装依赖包
- [ ] network.conf 在所有设备上一致
- [ ] 防火墙已配置或关闭
- [ ] 网络连通性已测试

启动前检查：
- [ ] 所有设备上代码已编译成功
- [ ] 先启动服务器
- [ ] 再启动所有设备
- [ ] 最后运行用户客户端

---

## 🔧 故障排查

### 问题1：找不到配置文件
```bash
# 确保 network.conf 在项目根目录
ls -l /home/average/code/network.conf

# 如果不存在，复制示例文件
cp network.conf.example network.conf
```

### 问题2：连接被拒绝
```bash
# 测试端口是否开放
telnet 192.168.1.100 9000

# 检查程序是否运行
ps aux | grep server_main
```

### 问题3：编译失败
```bash
# 检查依赖
dpkg -l | grep -E "boost|ssl|ntl|gmp"

# 重新安装依赖
./build_ubuntu.sh
```

---

## 🎯 推荐工作流程

### 初次部署
1. 在一台机器上完整测试（本地模式）
2. 确认功能正常后，修改 network.conf 为分布式配置
3. 使用 deploy.sh 或手动复制到各设备
4. 按顺序启动：服务器 → 设备 → 用户

### 日常使用
```bash
# 启动
./start_all.sh

# 停止
./stop_all.sh

# 测试连通性
./test_network.sh
``` 