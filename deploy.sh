#!/bin/bash

# ThresholdPRF distributed deployment script
# This script syncs code and config to each node and builds remotely.
set -e

echo "=== ThresholdPRF distributed deployment ==="
echo ""

# Configuration - adjust for your environment
SERVER_HOST="192.168.1.100"
SERVER_USER="average"

DEVICE_HOSTS=("192.168.1.101" "192.168.1.102" "192.168.1.103")
DEVICE_USER="average"

REMOTE_DIR="/home/average/code"
LOCAL_DIR="$(pwd)"

# Check network.conf exists
if [ ! -f "network.conf" ]; then
    echo "Error: network.conf not found. Please create the configuration file first."
    exit 1
fi

echo "Current configuration:"
cat network.conf
echo ""
read -p "Proceed with deployment using the configuration above? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment canceled."
    exit 0
fi

# Function: deploy to a single node
deploy_to_node() {
    local host=$1
    local user=$2
    local node_type=$3

    echo ">>> Deploying to $node_type: $user@$host"

    # Create remote directory
    ssh $user@$host "mkdir -p $REMOTE_DIR"

    # Sync code (exclude build directory)
    rsync -avz --exclude 'build' --exclude '.git' \
          $LOCAL_DIR/ $user@$host:$REMOTE_DIR/

    # Remote build
    ssh $user@$host "cd $REMOTE_DIR && ./build_ubuntu.sh"

    echo ">>> $node_type ($host) deployment complete"
    echo ""
}

# Deploy to server
echo "=== Deploy server ==="
deploy_to_node $SERVER_HOST $SERVER_USER "Server"

# Deploy to devices
echo "=== Deploy device nodes ==="
for i in "${!DEVICE_HOSTS[@]}"; do
    device_id=$((i+1))
    deploy_to_node ${DEVICE_HOSTS[$i]} $DEVICE_USER "Device$device_id"
done

echo "=== Deployment complete ==="
echo ""
echo "Next steps:"
echo "1. Start server: ssh $SERVER_USER@$SERVER_HOST 'cd $REMOTE_DIR/build && ./server_main'"
for i in "${!DEVICE_HOSTS[@]}"; do
    device_id=$((i+1))
    echo "$((i+2)). Start device ${device_id}: ssh $DEVICE_USER@${DEVICE_HOSTS[$i]} 'cd $REMOTE_DIR/build && ./device_main $device_id'"
done
echo ""
echo "Or use start_all.sh to start all components in one command."
