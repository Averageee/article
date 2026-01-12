# ThresholdPRF - Threshold Pseudorandom Function System

A distributed threshold PRF system based on Boost.Asio, supporting device revocation
and key update.

## Features
- Threshold PRF evaluation: distributed computation without a single point of failure
- Secret sharing: (t-1, n-1) and (2,2) secret sharing schemes
- Device revocation: revoke compromised devices dynamically
- Key update: online key updates
- Distributed deployment: run across Ubuntu 25.04 devices
- Flexible configuration: config files and environment variables

## Quick Start
### Local test (single machine)

```bash
# 1. Build
./build_ubuntu.sh

# 2. Start components (separate terminals)
cd build

# Terminal 1: server
./server_main

# Terminal 2-4: devices
./device_main 1
./device_main 2
./device_main 3

# Terminal 5: user client
./user_main
```

### Distributed deployment
See [DEPLOYMENT.md](DEPLOYMENT.md) for the full guide.

Brief steps:

```bash
# 1. Edit network configuration
vim network.conf

# 2. Deploy to all machines
./deploy.sh

# 3. Start all components
./start_all.sh

# 4. Test network connectivity
./test_network.sh
```

## System Architecture

```
+----------------+          +----------------+    +----------------+
| User Client    |  ---->   | Server         |    | Device 1        |
| (initiates PRF)|          | (coordinator)  |    | (key share)     |
+----------------+          |                |    +----------------+
                            |                |    +----------------+
                            |                |    | Device 2        |
                            |                |    | (key share)     |
                            |                |    +----------------+
                            |                |    +----------------+
                            |                |    | Device 3        |
                            |                |    | (key share)     |
                            +----------------+    +----------------+
```

## Dependencies
- Ubuntu 25.04
- CMake >= 3.16
- C++17 compiler
- Boost (libboost-all-dev)
- OpenSSL (libssl-dev)
- NTL (libntl-dev)
- GMP (libgmp-dev)

## Network Configuration

### Config file `network.conf`

```conf
# Server configuration
SERVER_IP 192.168.1.100
SERVER_PORT 9000

# Device configuration
DEVICE 1 192.168.1.101 9101
DEVICE 2 192.168.1.102 9101
DEVICE 3 192.168.1.103 9101
```

### Environment variables (optional)

```bash
export SERVER_IP=192.168.1.100
export SERVER_PORT=9000
```

Priority: **environment variables** > **config file** > **defaults**

## Example Usage

After starting the user client, follow the prompts:

```
Enter n_vector: 3
Enter n_devices: 3
Enter threshold t: 2
Enter user password pw: mypassword
```

The system will execute:
1. Secret generation and distribution
2. PRF computation and encryption
3. Key verification
4. Device revocation (optional)
5. Key update (optional)

## Deployment Scripts

| Script | Purpose |
|------|------|
| `build_ubuntu.sh` | Build the project |
| `deploy.sh` | Automated deployment to multiple machines |

## Documentation

- [DEPLOYMENT.md](DEPLOYMENT.md) - Detailed distributed deployment guide

## Technical Details
### Cryptographic foundations

- Finite-field arithmetic: based on NTL, modulus p = 2147483647
- PRF construction: inner-product PRF with two-stage rounding (q -> q1 -> p)
- Secret sharing: additive secret sharing variant
- Hash function: SHA256

### Networking

- Framework: Boost.Asio
- Protocol: TCP/IP
- Message format: JSON (via Boost.PropertyTree)

## Troubleshooting

### Connection failed

```bash
# Check port usage
sudo netstat -tulpn | grep 9000

# Test connectivity
telnet 192.168.1.100 9000

# Check firewall
sudo ufw status
```

### Configuration issues

```bash
# Verify configuration
cat network.conf

# Test network
./test_network.sh
```

## Security Notes

WARNING: This project is for research/teaching purposes only.

Production recommendations:
- Use TLS for encrypted communication
- Enforce access control and authentication
- Store key shares securely
- Perform regular security audits

## License
Set according to project needs.

## Contributing
Issues and pull requests are welcome.

