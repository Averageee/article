# Quick Deployment Guide - What Each Device Needs

## Required Files
### Files needed on all devices (shared)

```
project-root/
|-- CMakeLists.txt          # Build configuration
|-- build_ubuntu.sh         # Build script
|-- network.conf            # Network config (must be identical on all devices)
|-- common/                 # Shared library (required on all devices)
|   |-- config.hpp          # Configuration management
|   |-- crypto.hpp          # Cryptographic functions
|   |-- share.hpp           # Secret sharing
|   `-- net.hpp             # Networking
|-- user/                   # User client source
|-- server/                 # Server source
`-- device/                 # Device source
```

### Optional files (for convenience)

```
|-- README.md              # Project overview
|-- DEPLOYMENT.md          # Deployment guide
`-- network.conf.example   # Configuration example
```

## Three Deployment Scenarios

### Scenario 1: Full copy to every device (recommended)
Best for: all devices are Ubuntu 25.04 and need full functionality

Steps:

#### Step 1: Package the entire project

```bash
# On the dev machine
tar -czf thresholdprf.tar.gz article-master
```

#### Step 2: Copy to each device

```bash
# Copy to server device (192.168.1.100)
scp thresholdprf.tar.gz user@192.168.1.100:/home/user/

# Copy to device 1 (192.168.1.101)
scp thresholdprf.tar.gz user@192.168.1.101:/home/user/

# Copy to device 2 (192.168.1.102)
scp thresholdprf.tar.gz user@192.168.1.102:/home/user/

# ... other devices
```

#### Step 3: Extract and build on each device

```bash
# On each device
tar -xzf thresholdprf.tar.gz
cd article-master
./build_ubuntu.sh
```

#### Step 4: Start the corresponding component

On the server device (192.168.1.100):

```bash
cd build
./server_main
```

On device 1 (192.168.1.101):

```bash
cd build
./device_main 1
```

On device 2 (192.168.1.102):

```bash
cd build
./device_main 2
```

On the user client machine:

```bash
cd build
./user_main
```

### Scenario 2: Minimal deployment (only what is needed)
Best for: resource-limited devices, only deploy what runs locally

#### Minimal file set for the server device

```
project-root/
|-- common/              # all files
|-- server/              # server source
|-- user/                # required because CMake builds all targets
`-- device/              # required because CMake builds all targets
```

#### Minimal file set for each device node

```
project-root/
|-- common/              # all files
|-- device/              # device source
|-- user/                # required because CMake builds all targets
`-- server/              # required because CMake builds all targets
```

Note: CMake builds all three components, so all source directories are needed even
if you only run one executable.

### Scenario 3: Automated deployment with scripts
Prerequisites:
- SSH key login is configured for all devices
- The dev machine can access all devices

Steps:

#### Step 1: Edit deployment script configuration

Update these variables:

```
SERVER_HOST, SERVER_USER
DEVICE_HOSTS, DEVICE_USER
REMOTE_DIR
```

#### Step 2: Run automated deployment

```bash
./deploy.sh
```

The script will:
- Sync code to all devices
- Build on each device

#### Step 3: One-command start

```bash
# Start all components
./start_all.sh

# Or view logs
tail -f build/server.log
```

## Key Notes
### 1. network.conf must be identical
All devices must use the exact same `network.conf`.

### 2. Build once per machine
Each machine must build locally to generate executables for its environment.

### 3. Start order
Start in this order: server -> devices -> user client

## Troubleshooting
### Problem 1: Config file not found

```bash
# Ensure network.conf is in the project root
ls network.conf

# If missing, copy the example
cp network.conf.example network.conf
```

### Problem 2: Connection refused

```bash
# Test whether the port is open
telnet 192.168.1.100 9000

# Check whether processes are running
ps aux | grep server_main
```

### Problem 3: Build failure

```bash
# Check dependencies
./build_ubuntu.sh

# Reinstall dependencies
sudo apt install -y cmake build-essential libboost-all-dev libssl-dev libntl-dev libgmp-dev pkg-config
```

## Recommended Workflow
### Initial deployment
1. Fully test on one machine (local mode)
2. After confirming functionality, update network.conf for distributed mode
3. Use deploy.sh or copy manually
4. Start in order: server -> devices -> user

### Day-to-day use

```bash
# Start
./start_all.sh

# Stop
./stop_all.sh

# Test connectivity
./test_network.sh
```
