#pragma once
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <map>
#include <vector>
#include <set>
#include <algorithm>

using u64 = uint64_t;
using namespace NTL;

// 从crypto.hpp导入需要的函数声明
extern std::map<std::pair<u64,u64>, u64> ncr_cache;
u64 ncr(u64 n, u64 r);
void findParties(std::vector<u64>& pt, u64 gid, u64 t, u64 T);
u64 findGroupId(std::vector<u64> parties, u64 t, u64 T);
void shareSecrettTL(int t, int T, const vec_ZZ_p &key, int n, std::map<int, std::map<int, vec_ZZ_p>> &shared_key_repo_tT);

// 根据require.txt：使用(t-1,n-1)秘密分享将Sd分成n-1个份额
// 这里t是原始的门限值，所以我们需要(t-1, n-1)分享
// 严格按照tool.cpp中shareSecrettTL的逻辑实现
inline void shareSecret_t1_n1(int t, int n_devices, const vec_ZZ_p &Sd, 
                               std::map<int, vec_ZZ_p> &device_shares){
    int n_vector = Sd.length();
    
    // 按照tool.cpp第118-122行的逻辑：
    // shared_key_repo_tT[parties[0]][gid] = key副本
    // 然后 shared_key_repo_tT[parties[0]][gid] += shared_key_repo_tT[parties[i]][gid] (对所有i>0)
    // 所以第0个存储：key + random1 + random2 + ...
    // 其他存储：random_i
    // 恢复：key = 第0个 - 其他所有
    
    if(t < 2){
        // 如果t<2，直接将原始秘密给第一个设备
        device_shares[1] = Sd;
        return;
    }
    
    // 对于(t-1, n)分享，我们实际上需要t-1个设备来恢复
    // 设备1存储：Sd + random1 + random2 + ... + random(t-2)
    // 设备2到设备t-1存储：random_i
    // 这样任意t-1个设备可以恢复
    
    int num_random_shares = t - 2;  // 需要的随机份额数量
    
    if(num_random_shares <= 0){
        // 如果t=2，那么只需要1个设备就能恢复
        // 这种情况下，简单地给所有设备相同的秘密
        for(int dev = 1; dev <= n_devices; dev++){
            device_shares[dev] = Sd;
        }
        return;
    }
    
    // 正常情况：生成随机份额
    std::vector<vec_ZZ_p> random_shares(num_random_shares);
    
    // 生成随机份额
    for(int i = 0; i < num_random_shares; i++){
        random_shares[i].SetLength(n_vector);
        for(int j = 0; j < n_vector; j++){
            random_shares[i][j] = random_ZZ_p();
        }
    }
    
    // 第一个设备存储：Sd加上所有随机份额
    vec_ZZ_p first_share = Sd;  // 从原始秘密开始
    for(int i = 0; i < num_random_shares; i++){
        for(int j = 0; j < n_vector; j++){
            first_share[j] += random_shares[i][j];
        }
    }
    device_shares[1] = first_share;
    
    // 其他设备存储随机份额
    for(int i = 0; i < num_random_shares && i+2 <= n_devices; i++){
        device_shares[i+2] = random_shares[i];
    }
    
    // 如果还有剩余设备，给它们分配零份额
    vec_ZZ_p zero_share; zero_share.SetLength(n_vector);
    for(int j = 0; j < n_vector; j++) zero_share[j] = ZZ_p(0);
    
    for(int dev = num_random_shares + 2; dev <= n_devices; dev++){
        device_shares[dev] = zero_share;
    }
}

// 从t-1个设备份额恢复Sd
// 严格按照tool.cpp中shareSecrettTL的恢复逻辑
inline bool recoverSecret_t1_n1(int t, const std::map<int, vec_ZZ_p> &selected_shares,
                                 vec_ZZ_p &recovered_secret){
    if(selected_shares.size() < static_cast<size_t>(t-1)) return false;
    
    int n_vector = selected_shares.begin()->second.length();
    recovered_secret.SetLength(n_vector);
    
    // 按照tool.cpp的逻辑：恢复 = 第一个份额 - 其他所有份额
    // 因为：第一个份额 = Sd + random1 + random2 + ...
    // 其他份额 = random_i
    // 所以：Sd = 第一个份额 - random1 - random2 - ...
    
    // 找到第一个设备（通常是设备1）
    auto first_it = selected_shares.find(1);
    if(first_it == selected_shares.end()){
        // 如果没有设备1，取第一个可用的
        first_it = selected_shares.begin();
    }
    
    // 从第一个份额开始
    for(int i = 0; i < n_vector; i++){
        recovered_secret[i] = first_it->second[i];
    }
    
    // 减去其他所有份额
    for(auto it = selected_shares.begin(); it != selected_shares.end(); it++){
        if(it != first_it){
            for(int j = 0; j < n_vector; j++){
                recovered_secret[j] -= it->second[j];
            }
        }
    }
    
    return true;
}

// 设备撤销管理器
struct DeviceManager {
    std::set<int> active_devices;
    std::set<int> revoked_devices;
    int n_devices;
    int threshold;
    
    DeviceManager(int n, int t) : n_devices(n), threshold(t) {
        for(int i = 1; i <= n_devices; i++){
            active_devices.insert(i);
        }
    }
    
    void revokeDevice(int device_id){
        active_devices.erase(device_id);
        revoked_devices.insert(device_id);
    }
    
    std::vector<int> getActiveDevices() const {
        return std::vector<int>(active_devices.begin(), active_devices.end());
    }
    
    bool canOperate() const {
        return active_devices.size() >= static_cast<size_t>(threshold - 1);  // 需要t-1个设备
    }
    
    std::vector<int> selectDevicesForVerification(int count) const {
        std::vector<int> active_list(active_devices.begin(), active_devices.end());
        if(active_list.size() < static_cast<size_t>(count)) return active_list;
        
        // 简单选择前count个活跃设备
        return std::vector<int>(active_list.begin(), active_list.begin() + count);
    }
}; 
