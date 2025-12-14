#pragma once
#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>

// 配置管理类
class NetworkConfig {
public:
    std::string server_ip;
    int server_port;
    std::map<int, std::string> device_ips;  // device_id -> IP
    std::map<int, int> device_ports;         // device_id -> port
    
    // 从配置文件加载
    bool load_from_file(const std::string &config_file) {
        std::ifstream file(config_file);
        if (!file.is_open()) {
            std::cerr << "无法打开配置文件: " << config_file << std::endl;
            return false;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            // 跳过空行和注释
            if (line.empty() || line[0] == '#') continue;
            
            std::istringstream iss(line);
            std::string key;
            iss >> key;
            
            if (key == "SERVER_IP") {
                iss >> server_ip;
            } else if (key == "SERVER_PORT") {
                iss >> server_port;
            } else if (key == "DEVICE") {
                int device_id;
                std::string ip;
                int port;
                iss >> device_id >> ip >> port;
                device_ips[device_id] = ip;
                device_ports[device_id] = port;
            }
        }
        
        file.close();
        return true;
    }
    
    // 从环境变量加载（优先级高于配置文件）
    void load_from_env() {
        const char* srv_ip = std::getenv("SERVER_IP");
        if (srv_ip) server_ip = srv_ip;
        
        const char* srv_port = std::getenv("SERVER_PORT");
        if (srv_port) server_port = std::atoi(srv_port);
    }
    
    // 打印配置信息
    void print() const {
        std::cout << "=== 网络配置 ===" << std::endl;
        std::cout << "服务器: " << server_ip << ":" << server_port << std::endl;
        std::cout << "设备列表:" << std::endl;
        for (const auto &pair : device_ips) {
            int dev_id = pair.first;
            std::cout << "  设备 " << dev_id << ": " 
                      << device_ips.at(dev_id) << ":" 
                      << device_ports.at(dev_id) << std::endl;
        }
        std::cout << "=================" << std::endl;
    }
    
    // 获取设备IP（如果不存在返回默认值）
    std::string get_device_ip(int device_id) const {
        auto it = device_ips.find(device_id);
        if (it != device_ips.end()) {
            return it->second;
        }
        return "127.0.0.1";  // 默认本地
    }
    
    // 获取设备端口
    int get_device_port(int device_id) const {
        auto it = device_ports.find(device_id);
        if (it != device_ports.end()) {
            return it->second;
        }
        return 9100 + device_id;  // 默认端口
    }
};

// 全局配置实例
inline NetworkConfig g_config;

// 初始化配置（优先级：环境变量 > 配置文件 > 默认值）
inline bool init_config(const std::string &config_file = "network.conf") {
    // 默认值
    g_config.server_ip = "127.0.0.1";
    g_config.server_port = 9000;
    
    // 尝试从配置文件加载
    if (!g_config.load_from_file(config_file)) {
        std::cout << "使用默认配置或环境变量" << std::endl;
    }
    
    // 环境变量覆盖
    g_config.load_from_env();
    
    return true;
} 