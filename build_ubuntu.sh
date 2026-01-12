#!/bin/bash

echo "Building Threshold PRF System for Ubuntu 25.04..."

# Check dependencies
echo "Checking dependencies..."

# Install required packages (if needed)
sudo apt update
sudo apt install -y cmake build-essential libboost-all-dev libssl-dev libntl-dev libgmp-dev pkg-config

# Create build directory
mkdir -p build
cd build

# Configure CMake
echo "Configuring CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
echo "Building..."
make -j$(nproc)

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo ""
    echo "Executables created:"
    echo "  - user_main"
    echo "  - server_main"
    echo "  - device_main"
    echo ""
    echo "To run the system:"
    echo "  1. Start server: ./server_main"
    echo "  2. Start devices: ./device_main 1, ./device_main 2, etc."
    echo "  3. Run user client: ./user_main"
else
    echo "Build failed!"
    exit 1
fi
