#!/bin/bash

# 打包项目文件用于分发到其他设备

echo "=== ThresholdPRF 项目打包脚本 ==="
echo ""

# 输出文件名
OUTPUT_FILE="ThresholdPRF-$(date +%Y%m%d-%H%M%S).tar.gz"

# 需要包含的文件和目录
FILES_TO_PACK=(
    "CMakeLists.txt"
    "build_ubuntu.sh"
    "network.conf"
    "common/"
    "user/"
    "server/"
    "device/"
    "README.md"
    "DEPLOYMENT.md"
    "QUICKSTART.md"
    "network.conf.example"
)

echo "将打包以下文件和目录："
for item in "${FILES_TO_PACK[@]}"; do
    echo "  ✓ $item"
done
echo ""

# 检查文件是否存在
echo "检查文件..."
missing_files=0
for item in "${FILES_TO_PACK[@]}"; do
    if [ ! -e "$item" ]; then
        echo "  ✗ 警告: $item 不存在"
        missing_files=$((missing_files + 1))
    fi
done

if [ $missing_files -gt 0 ]; then
    echo ""
    read -p "有 $missing_files 个文件不存在，是否继续？(y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "打包已取消"
        exit 0
    fi
fi

echo ""
echo "正在打包..."

# 创建压缩包
tar czf "$OUTPUT_FILE" "${FILES_TO_PACK[@]}" 2>/dev/null

if [ $? -eq 0 ]; then
    size=$(du -h "$OUTPUT_FILE" | cut -f1)
    echo ""
    echo "✓ 打包成功！"
    echo ""
    echo "文件名: $OUTPUT_FILE"
    echo "大小:   $size"
    echo ""
    echo "下一步操作："
    echo "1. 将此文件复制到目标设备："
    echo "   scp $OUTPUT_FILE user@192.168.1.XXX:~/"
    echo ""
    echo "2. 在目标设备上解压："
    echo "   tar xzf $OUTPUT_FILE"
    echo "   cd code"
    echo "   ./build_ubuntu.sh"
    echo ""
else
    echo "✗ 打包失败！"
    exit 1
fi 