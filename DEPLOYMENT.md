# ThresholdPRF Distributed Deployment Guide

This document explains how to deploy ThresholdPRF across Ubuntu 25.04 devices.

## System Architecture
The system has three component types:
- Server: coordinator, 1 instance
- Device: compute nodes, n instances (one per machine)
- User client: initiates requests, can run on any machine

## Pre-deployment
### 1. Network planning
Example topology:

```
Server:      <YOUR_SERVER_IP>:9000
Device 1:    <YOUR_DEVICE1_IP>:9101
Device 2:    <YOUR_DEVICE2_IP>:9101
Device 3:    <YOUR_DEVICE3_IP>:9101
User client: any location
```

### 2. Prepare each machine
On each Ubuntu 25.04 device:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y cmake build-essential libboost-all-dev libssl-dev libntl-dev libgmp-dev pkg-config

# Clone or copy the project
# If using git:
git clone <your-repo>

# Or copy from the dev machine via scp
```

## Configuration Steps
### 1. Create network configuration file
On all machines, edit `network.conf` (every machine must use the same config):

```conf
# Server address
SERVER_IP <YOUR_SERVER_IP>
SERVER_PORT 9000

# Device list (device ID, device IP, device port)
DEVICE 1 <YOUR_DEVICE1_IP> 9101
DEVICE 2 <YOUR_DEVICE2_IP> 9101
DEVICE 3 <YOUR_DEVICE3_IP> 9101
```

Important: `network.conf` must be identical on all machines.

### 2. Build the project
On each machine:

```bash
./build_ubuntu.sh
```

## Start the System
### 1. Start the server (<YOUR_SERVER_IP>)

```bash
cd build
./server_main
```

Output should include:

```
=== Network Configuration ===
Server: <YOUR_SERVER_IP>:9000
```

### 2. Start devices (on each machine)

On <YOUR_DEVICE1_IP>:

```bash
cd build
./device_main 1
```

On <YOUR_DEVICE2_IP>:

```bash
cd build
./device_main 2
```

On <YOUR_DEVICE3_IP>:

```bash
cd build
./device_main 3
```

Each device should show:

```
[Device X] Configured listen port: 9101
```

### 3. Run the user client (any machine)
Ensure this machine has the built binaries and the correct `network.conf`:

```bash
cd build
./user_main
```

Follow the prompts:
- `n_vector`: vector dimension (e.g., 3)
- `n_devices`: number of devices (e.g., 3)
- `threshold t`: threshold (e.g., 2)
- other parameters such as password

## Firewall Configuration
Ensure required ports are open between machines:

```bash
# On the server (<YOUR_SERVER_IP>)
sudo ufw allow 9000/tcp

# On each device
sudo ufw allow 9101/tcp

# Or temporarily disable firewall for testing
sudo ufw disable
```

## Environment Variables (Optional)
Besides the config file, you can use environment variables:

```bash
# Server
export SERVER_IP=<YOUR_SERVER_IP>
export SERVER_PORT=9000

# User client
export N_DEVICES=3
```

## Quick Deployment Script
Use `deploy.sh` for automated deployment (SSH key login required):

```bash
# Edit machine list in deploy.sh
vim deploy.sh
```

## Test Connectivity
Use `test_network.sh` to test connectivity:

```bash
./test_network.sh
```

## Troubleshooting
### 1. Connection timeout
- Check IP addresses
- Check firewall settings
- Test connectivity with `telnet <IP> <PORT>`

### 2. Configuration mismatch
- Ensure all machines have the exact same `network.conf`
- Check for extra spaces or formatting errors

### 3. Port in use

```bash
# Check port usage
sudo netstat -tulpn | grep <PORT>

# Kill the process
sudo kill <PID>
```

## Local Test Mode
If you only want to test on a single machine, use the default `network.conf`:

```bash
./build_ubuntu.sh
cd build
./server_main
./device_main 1
./device_main 2
./device_main 3
./user_main
```

## Notes
1. Clock sync: use NTP to synchronize machine clocks
2. Network stability: ensure low latency and stable connectivity
3. Backups: back up key shares
4. Security: use TLS in production
