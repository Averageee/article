#include <iostream>
#include <math.h>
#include <algorithm>
#include <map>
#include <vector>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/vector.h>
#include <NTL/SmartPtr.h>
#include <sstream>
#include <cstdint>

typedef std::uint64_t u64;
using namespace NTL;

// ----------------- Global variables and cache -----------------
std::map<std::pair<int, int>, int> ncr_cache;

// ----------------- Utility functions -----------------
/* This function rounds an integer in modulo q to an integer in modulo p */
u64 round_toL(u64 x, u64 q, u64 p){
    __uint128_t num = ( __uint128_t )x * p + (q / 2);
    return (u64)( num / q );
}

/* This function calculates x modulo q */
u64 moduloL(u64 x, u64 q){
    if(x >= 0){
        return x%q;
    } else{
        x = (-x)%q;
        return (x ? (q-x) : x);
    }
}

/* This function calculates nCr, (n Combination r) */
u64 ncr(u64 n, u64 r){
    if (ncr_cache.find({n, r}) == ncr_cache.end()){
        if (r > n || n < 0 || r < 0) return 0;
        else{
            if (r == 0 || r == n){
                ncr_cache[{n, r}] = 1;
            } else if (r == 1 || r == n - 1){
                ncr_cache[{n, r}] = n;
            } else{
                ncr_cache[{n, r}] = ncr(n - 1, r) + ncr(n - 1, r - 1);
            }
        }
    }
    return ncr_cache[{n, r}];
}

/* Given a group_id, find the party_ids present in (group_id)^th combination out of TCt combinations */
void findParties(std::vector<u64>& pt, u64 gid, u64 t, u64 T){
    u64 mem = 0, tmp;
    pt.clear();
    for(u64 i = 1; i < T; i++){
        tmp = ncr(T - i, t - mem -1);
        if(gid > tmp){
            gid -= tmp;
        } else{
            pt.push_back(i);
            mem += 1;
        }
        if(mem + (T-i) == t){
            for(u64 j = i + 1; j <= T; j++){
                pt.push_back(j);
            }
            break;
        }
    }
}

/* Given a t-sized list of party-ids compute its rank among total TCt combinations */
u64 findGroupId(std::vector<u64> parties, u64 t, u64 T){
    u64 mem = 0;
    u64 group_count = 1;
    for(u64 i = 1; i <= T; i++){
        if(std::find(parties.begin(), parties.end(), i) != parties.end()){
            mem += 1;
        } else{
            group_count += ncr(T - i, t - mem - 1);
        }
        if(mem == t){
            break;
        }
    }
    return group_count;
}

/* This function performs (t,T)-threshold secret sharing */
void shareSecrettTL(int t, int T, NTL::vec_ZZ_p key, int n, std::map<int, std::map<int, NTL::vec_ZZ_p>> &shared_key_repo_tT){
    u64 group_count = ncr(T,t);
    std::vector<u64> parties;
    
    for(u64 gid = 1; gid <= group_count; gid++){
        findParties(parties, gid, t, T);
        VectorCopy(shared_key_repo_tT[parties[0]][gid], key, n);
        for(int i = 1; i < t; i++){
            random(shared_key_repo_tT[parties[i]][gid], n);
            shared_key_repo_tT[parties[0]][gid] += shared_key_repo_tT[parties[i]][gid];
        }
    }
}

/* This function calculates the direct PRF evaluation using secret k */
u64 direct_PRF_eval(NTL::vec_ZZ_p x, NTL::vec_ZZ_p key, u64 n, u64 q, u64 p){
    NTL::ZZ_p eval;
    u64 res;
    NTL::InnerProduct(eval, x, key);
    u64 interim = NTL::conv<ulong>(eval);
    res = round_toL(interim, q, p);
    return res;
}

/* This function calculates threshold PRF evaluation */
u64 threshold_PRF_eval(NTL::vec_ZZ_p x, u64 n, u64 group_id, u64 t, u64 T, u64 q, u64 q1, u64 p, std::map<int, std::map<int, NTL::vec_ZZ_p>> &shared_key_repo_tT){
    std::vector<u64> parties;
    findParties(parties, group_id, t, T);
    NTL::ZZ_p tmp1;
    u64 tmp2, tmp3;
    u64 interim = 0;
    u64 res;
    NTL::vec_ZZ_p cur_share;
    
    for(int i = 0; i < t; i++){
        NTL::VectorCopy(cur_share, shared_key_repo_tT[parties[i]][group_id], n);
        NTL::InnerProduct(tmp1, x, cur_share);
        tmp2 = NTL::conv<ulong>(tmp1);
        tmp3 = round_toL(tmp2, q, q1);
        if(i == 0){
            interim += tmp3;
            interim = moduloL(interim, q1);
        } else{
            interim -= tmp3;
            interim = moduloL(interim, q1);
        }
    }
    res = round_toL(interim, q1, p);
    return res;
}

// helper to convert ZZ_p to u64 (consistent with user/server)
static u64 zzp_to_u64(const ZZ_p &z){
    ZZ t = rep(z);
    unsigned long ul = conv<unsigned long>(t);
    return (u64)ul;
}

// ----------------- Device state and configuration -----------------
struct DeviceState {
    vec_ZZ_p SDi;          // Device's secret share
    int device_id;         // Device ID
    bool is_revoked;       // Whether revoked
    bool is_selected;      // Whether selected for verification
    ZZ_p session2;         // Session2 from user
    ZZ_p alpha;            // Alpha value from user
    ZZ_p session1;         // Session1 from server (for key update)
    vec_ZZ_p SDi_updated;  // Updated secret share
    
    // Secret sharing related parameters
    int t;                 // Threshold
    int T;                 // Total devices
    int n;                 // Vector length
    u64 q;                 // Modulus q
    u64 p;                 // Modulus p
};

// ----------------- Device utility functions -----------------
// String to ZZ_p conversion
ZZ_p string_to_zzp(const std::string& s) {
    std::hash<std::string> hasher;
    size_t hash_val = hasher(s);
    return conv<ZZ_p>(ZZ((unsigned long)hash_val));
}

// Get ZZ_p input from user
ZZ_p get_zzp_input(const std::string& prompt) {
    std::string input;
    std::cout << prompt;
    std::getline(std::cin, input);
    return string_to_zzp(input);
}

// Get vec_ZZ_p input from user
vec_ZZ_p get_vec_zzp_input(int n, const std::string& prompt) {
    vec_ZZ_p result;
    result.SetLength(n);
    std::cout << prompt << " (enter " << n << " values separated by space): ";
    
    std::string input;
    std::getline(std::cin, input);
    std::stringstream ss(input);
    
    for (int i = 0; i < n; i++) {
        std::string token;
        ss >> token;
        if (token.empty()) {
            random(result[i]);
        } else {
            result[i] = string_to_zzp(token);
        }
    }
    return result;
}

// Print vec_ZZ_p
void print_vec_zzp(const vec_ZZ_p& vec, const std::string& name) {
    std::cout << name << ": ";
    for (int i = 0; i < vec.length(); i++) {
        std::cout << rep(vec[i]) << " ";
    }
    std::cout << std::endl;
}

// ----------------- Device operation functions -----------------
// Phase 1: Registration
void device_registration(DeviceState& device) {
    std::cout << "\n=== Device Registration Phase ===" << std::endl;
    std::cout << "Device ID: " << device.device_id << std::endl;
    
    // 1. Receive secret share SDi from User
    device.SDi = get_vec_zzp_input(device.n, "Enter secret share SDi");
    print_vec_zzp(device.SDi, "SDi");
    
    std::cout << "Registration completed!" << std::endl;
}

// Phase 2: Verification
void device_verification(DeviceState& device) {
    std::cout << "\n=== Verification Phase ===" << std::endl;
    
    if (!device.is_selected) {
        std::cout << "Device not selected for verification" << std::endl;
        return;
    }
    
    std::cout << "Device selected for verification" << std::endl;
    
    // 1. Receive session2 parameter from User
    device.session2 = get_zzp_input("Enter session2: ");
    std::cout << "session2: " << rep(device.session2) << std::endl;
    
    // 2. Receive alpha value from User
    device.alpha = get_zzp_input("Enter alpha value: ");
    std::cout << "alpha: " << rep(device.alpha) << std::endl;

    // 3. Receive x' vector from User (length n)
    vec_ZZ_p xprime = get_vec_zzp_input(device.n, "Enter x' vector");

    // 4. Compute betaDi = round_toL(<x', SDi>, q, q)
    ZZ_p dot = ZZ_p(0);
    for (int i = 0; i < device.SDi.length(); i++) {
        dot += xprime[i] * device.SDi[i];
    }
    u64 tmp2 = zzp_to_u64(dot);
    u64 betaDi = round_toL(tmp2, device.q, device.q);

    std::cout << "Computed betaDi: " << betaDi << std::endl;
    std::cout << "Sending betaDi to User and Server..." << std::endl;
    
    std::cout << "Verification phase completed!" << std::endl;
}

// Phase 3: Key Update
void device_key_update(DeviceState& device) {
    std::cout << "\n=== Key Update Phase ===" << std::endl;
    
    if (device.is_revoked) {
        // 2. Revoked devices receive session1 = 1
        device.session1 = conv<ZZ_p>(ZZ(1));
        std::cout << "Device revoked, received session1 = 1" << std::endl;
    } else {
        // 1. Non-revoked devices receive session1 from Server
        device.session1 = get_zzp_input("Enter session1: ");
        std::cout << "Received session1: " << rep(device.session1) << std::endl;
    }
    
    // 3. Device performs key update: SDi' = SDi * session1
    device.SDi_updated.SetLength(device.SDi.length());
    for (int i = 0; i < device.SDi.length(); i++) {
        device.SDi_updated[i] = device.SDi[i] * device.session1;
    }
    
    print_vec_zzp(device.SDi_updated, "Updated SDi'");
    
    // 4. If selected by Server, send updated share to Server
    if (!device.is_revoked) {
        std::cout << "Selected by Server to send updated share? (y/n): ";
        std::string choice;
        std::getline(std::cin, choice);
        
        if (choice == "y" || choice == "Y") {
            std::cout << "Sending updated SDi' to Server..." << std::endl;
            std::cout << "Sent content: ";
            for (int i = 0; i < device.SDi_updated.length(); i++) {
                std::cout << rep(device.SDi_updated[i]) << " ";
            }
            std::cout << std::endl;
        }
    }
    
    std::cout << "Key update completed!" << std::endl;
}

// ----------------- Main function -----------------
int main() {
    // Initialize field modulus
    long q_mod = 2147483647;
    ZZ qzz = ZZ(q_mod);
    ZZ_p::init(qzz);
    
    std::cout << "=== Device Demo Program ===" << std::endl;
    
    // Device configuration
    DeviceState device;
    device.device_id = 1;
    device.is_revoked = false;
    device.is_selected = true;
    
    // Set parameters consistent with User side
    device.n = 4;    // Vector length
    device.t = 3;    // Threshold
    device.T = 5;    // Total devices
    device.q = 2147483647;  // Modulus q
    device.p = 2;    // Modulus p
    
    // Display device information
    std::cout << "Device ID: " << device.device_id << std::endl;
    std::cout << "Vector length n: " << device.n << std::endl;
    std::cout << "Threshold t: " << device.t << std::endl;
    std::cout << "Total devices T: " << device.T << std::endl;
    
    // User selects device status
    std::cout << "Is device revoked? (y/n): ";
    std::string revoked_choice;
    std::getline(std::cin, revoked_choice);
    device.is_revoked = (revoked_choice == "y" || revoked_choice == "Y");
    
    std::cout << "Is device selected for verification? (y/n): ";
    std::string selected_choice;
    std::getline(std::cin, selected_choice);
    device.is_selected = (selected_choice == "y" || selected_choice == "Y");
    
    // Execute three phases
    device_registration(device);
    
    if (device.is_selected) {
        device_verification(device);
    } else {
        std::cout << "\nDevice not selected, skipping verification phase" << std::endl;
    }
    
    device_key_update(device);
    
    // Display final state
    std::cout << "\n=== Device Final State ===" << std::endl;
    std::cout << "Device ID: " << device.device_id << std::endl;
    std::cout << "Revoked: " << (device.is_revoked ? "Yes" : "No") << std::endl;
    std::cout << "Selected: " << (device.is_selected ? "Yes" : "No") << std::endl;
    print_vec_zzp(device.SDi, "Original SDi");
    print_vec_zzp(device.SDi_updated, "Updated SDi'");
    std::cout << "session2: " << rep(device.session2) << std::endl;
    std::cout << "alpha: " << rep(device.alpha) << std::endl;
    std::cout << "session1: " << rep(device.session1) << std::endl;
    
    std::cout << "\nDevice demo completed!" << std::endl;
    return 0;
}