#include <bits/stdc++.h>
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include "common/crypto.hpp"
#include "common/share.hpp"
#include "common/net.hpp"
#include <chrono>

using namespace std;
using namespace NTL;
using boost::asio::ip::tcp;

static void send_json(const string &/*host*/, int port, const boost::property_tree::ptree &pt, boost::property_tree::ptree *out=nullptr){
    boost::asio::io_context io; tcp::socket sock(io);
    sock.connect({boost::asio::ip::make_address("127.0.0.1"), (unsigned short)port});
    net::write_line(sock, net::ptree_to_json(pt));
    if(out){ string line = net::read_line(sock); *out = net::json_to_ptree(line); }
}

int main(){
    ZZ_p::init(ZZ(2147483647));
    cout<<"[User] Threshold PRF System with Device Revocation\n";
    
    // 变量声明
    int n_vector, n_devices, t;
    string pw;
    
    // 输入参数
    cout<<"Enter n_vector: "; cin>>n_vector;
    cout<<"Enter n_devices: "; cin>>n_devices;
    cout<<"Enter threshold t: "; cin>>t;
    cout<<"Enter user password pw: "; cin>>pw;

    // ============= 注册阶段开始 =============
    cout<<"\n==================== REGISTRATION PHASE ====================\n";
    auto registration_phase_start = chrono::high_resolution_clock::now();

    // 一：秘密份额分发
    cout<<"\n=== [User] Step 1: Secret Generation and Sharing ===\n";
    
    // 1. 生成随机秘密S
    auto step1_start = chrono::high_resolution_clock::now();
    vec_ZZ_p S; S.SetLength(n_vector); 
    for(int i=0;i<n_vector;i++) S[i] = random_ZZ_p();
    cout<<"Generated secret S: "; 
    for(int i=0;i<n_vector;i++) cout<<rep(S[i])<<" "; 
    cout<<"\n";
    
    // 2. 使用(2,2)秘密共享将S分为Sd和Ss
    vec_ZZ_p Sd, Ss;
    share_2_2(S, Sd, Ss);
    cout<<"(2,2) sharing completed:\n";
    cout<<"  Sd: "; for(int i=0;i<n_vector;i++) cout<<rep(Sd[i])<<" "; cout<<"\n";
    cout<<"  Ss: "; for(int i=0;i<n_vector;i++) cout<<rep(Ss[i])<<" "; cout<<"\n";
    
    // 3. 将Ss发给服务器
    {
        boost::property_tree::ptree pt; 
        pt.put("kind","register_server"); 
        pt.put("n_vector", n_vector); 
        pt.put("n_devices", n_devices); 
        pt.put("t", t);
        
        boost::property_tree::ptree ss_pt;
        for(int i=0;i<n_vector;i++) {
            ss_pt.put(to_string(i), conv<unsigned long>(rep(Ss[i])));
        }
        pt.add_child("Ss", ss_pt);
        
        boost::property_tree::ptree reply; 
        send_json("127.0.0.1", 9000, pt, &reply); 
        cout<<"[User] Server registration ok="<<reply.get<int>("ok",0)<<"\n";
    }
    
    // 4. 使用(t-1,n-1)秘密共享将Sd分成n-1个份额
    map<int, vec_ZZ_p> device_shares;
    shareSecret_t1_n1(t, n_devices, Sd, device_shares);
    cout<<"(t-1,n-1) sharing of Sd completed.\n";
    
    // 5. 将这n-1个份额发给n-1个设备
    for(int dev = 1; dev <= n_devices; ++dev){
        boost::property_tree::ptree pt; 
        pt.put("kind","register_device"); 
        pt.put("device_id", dev);
        pt.put("n_vector", n_vector); 
        pt.put("t", t);
        
        boost::property_tree::ptree sdi_pt;
        for(int i=0;i<n_vector;i++) {
            sdi_pt.put(to_string(i), conv<unsigned long>(rep(device_shares[dev][i])));
        }
        pt.add_child("SDi", sdi_pt);
        
        boost::property_tree::ptree reply; 
        send_json("127.0.0.1", 9100 + dev, pt, &reply); 
        cout<<"[User] Device "<<dev<<" registration ok="<<reply.get<int>("ok",0)<<"\n";
    }

    auto step1_end = chrono::high_resolution_clock::now();
    auto step1_duration = chrono::duration_cast<chrono::microseconds>(step1_end - step1_start);
    cout<<"[Time] Step 1 completed in: "<<step1_duration.count()<<" μs ("<<step1_duration.count()/1000.0<<" ms)\n";

    // 二：PRF计算（用于生成基准密文）
    cout<<"\n=== [User] Step 2: PRF Calculation and Encryption ===\n";
    auto step2_start = chrono::high_resolution_clock::now();
    
    // 计算直接PRF值（严格按照tool.cpp的direct_PRF_eval）
    vec_ZZ_p x = hash_to_vecZZp(pw, n_vector);
    
    // 模拟threshold_PRF_eval的两阶段过程：
    // 1. 计算<H(pw), Sd>和<H(pw), Ss>，分别进行第一阶段round_toL
    // 2. 将结果相加，进行第二阶段round_toL
    ZZ_p inner_Sd_result, inner_Ss_result;
    InnerProduct(inner_Sd_result, x, Sd);
    InnerProduct(inner_Ss_result, x, Ss);
    
    u64 inner_Sd_u64 = conv<unsigned long>(inner_Sd_result);
    u64 inner_Ss_u64 = conv<unsigned long>(inner_Ss_result);
    
    // 第一阶段round_toL
    u64 tmp3_Sd = round_toL(inner_Sd_u64, 2147483647, 1073741824);  // q -> q1
    u64 tmp3_Ss = round_toL(inner_Ss_u64, 2147483647, 1073741824);  // q -> q1
    
    cout<<"  tmp3_Sd = "<<tmp3_Sd<<", tmp3_Ss = "<<tmp3_Ss<<"\n";
    
    // 第二阶段：组合tmp3值
    u64 tmp3_sum = tmp3_Sd + tmp3_Ss;
    tmp3_sum = moduloL(tmp3_sum, 1073741824);
    
    // 第二阶段round_toL
    u64 rw = round_toL(tmp3_sum, 1073741824, 65536);  // q1 -> p
    cout<<"Direct PRF rw = "<<rw<<" (using direct_PRF_eval parameters)\n";
    
    // 调试信息：显示各个组件
    cout<<"Debug info for verification:\n";
    cout<<"  Password hash: "; for(int i=0;i<min(3,n_vector);i++) cout<<rep(x[i])<<" "; cout<<"...\n";
    cout<<"  Secret S: "; for(int i=0;i<min(3,n_vector);i++) cout<<rep(S[i])<<" "; cout<<"...\n";
    cout<<"  Secret Sd: "; for(int i=0;i<min(3,n_vector);i++) cout<<rep(Sd[i])<<" "; cout<<"...\n";
    cout<<"  Secret Ss: "; for(int i=0;i<min(3,n_vector);i++) cout<<rep(Ss[i])<<" "; cout<<"...\n";
    
    // 用rw加密"Hello"
    unsigned char aeskey[32]; 
    derive_aes_key_from_u64(rw, aeskey); 
    vector<unsigned char> plain((unsigned char*)"Hello", (unsigned char*)"Hello"+5);
    vector<unsigned char> cipher, iv;
    aes_encrypt(aeskey, plain, cipher, iv);
    cout<<"Encrypted 'Hello' with rw\n";
    
    // 发送密文给服务器存储
    {
        boost::property_tree::ptree pt; 
        pt.put("kind","store_cipher");
        
        boost::property_tree::ptree cpt; 
        for(size_t i=0;i<cipher.size();++i) cpt.put(to_string(i), (int)cipher[i]); 
        pt.add_child("cipher", cpt);
        
        boost::property_tree::ptree ivpt; 
        for(size_t i=0;i<iv.size();++i) ivpt.put(to_string(i), (int)iv[i]); 
        pt.add_child("iv", ivpt);
        
        boost::property_tree::ptree reply; 
        send_json("127.0.0.1", 9000, pt, &reply); 
        cout<<"[User] Cipher stored at server\n";
    }

    auto step2_end = chrono::high_resolution_clock::now();
    auto step2_duration = chrono::duration_cast<chrono::microseconds>(step2_end - step2_start);
    cout<<"[Time] Step 2 completed in: "<<step2_duration.count()<<" μs ("<<step2_duration.count()/1000.0<<" ms)\n";

    // ============= 注册阶段结束 =============
    auto registration_phase_end = chrono::high_resolution_clock::now();
    auto registration_phase_duration = chrono::duration_cast<chrono::microseconds>(registration_phase_end - registration_phase_start);
    cout<<"\n[PHASE TIME] *** REGISTRATION PHASE TOTAL: "<<registration_phase_duration.count()<<" μs ("<<registration_phase_duration.count()/1000.0<<" ms) ***\n";
    cout<<"========================================================\n";

    // 主循环：验证、密钥协商和设备撤销
    bool continue_system = true;
    int round = 1;
    
    while(continue_system) {
        cout<<"\n==================== Round "<<round<<" ====================\n";
        
        // ============= 验证阶段开始 =============
        cout<<"\n================ VERIFICATION PHASE ================\n";
        
        // 三：验证阶段
        cout<<"\n=== [User] Step 3: Verification Phase ===\n";
    
    // 1. 生成session2
    string session2 = "session2_" + to_string(time(nullptr));
    cout<<"Generated session2: "<<session2<<"\n";
    
    // 2. 查询服务器状态，获取活跃设备列表
    vector<int> active_devices;
    int total_active = 0;
    {
        boost::property_tree::ptree status_req;
        status_req.put("kind", "status");
        boost::property_tree::ptree status_resp;
        send_json("127.0.0.1", 9000, status_req, &status_resp);
        
        total_active = status_resp.get<int>("active_devices", n_devices);
        int total_revoked = status_resp.get<int>("revoked_devices", 0);
        cout<<"Active devices: "<<total_active<<" out of "<<n_devices<<" (Revoked: "<<total_revoked<<")\n";
        
        // 获取活跃设备列表
        if(status_resp.count("active_device_list") > 0){
            auto active_pt = status_resp.get_child("active_device_list");
            for(auto &kv : active_pt){
                active_devices.push_back(kv.second.get_value<int>());
            }
        } else {
            // 备用：假设所有设备都活跃
            for(int i = 1; i <= n_devices; i++) {
                active_devices.push_back(i);
            }
        }
        
        // 显示被撤销的设备（如果有）
        if(status_resp.count("revoked_device_list") > 0){
            auto revoked_pt = status_resp.get_child("revoked_device_list");
            if(revoked_pt.size() > 0){
                cout<<"Revoked devices: ";
                bool first = true;
                for(auto &kv : revoked_pt){
                    if(!first) cout<<", ";
                    cout<<kv.second.get_value<int>();
                    first = false;
                }
                cout<<"\n";
            }
        }
    }
    
    // 3. 选择参与验证的设备（从活跃设备中选择t-1个）
    vector<int> chosen_devices;
    cout<<"Choose "<<(t-1)<<" devices from active devices (";
    for(size_t i = 0; i < active_devices.size(); i++) {
        cout<<active_devices[i];
        if(i < active_devices.size()-1) cout<<", ";
    }
    cout<<"): ";
    for(int i=0;i<t-1;i++){ 
        int d; 
        bool valid_choice = false;
        while(!valid_choice) {
            cin>>d;
            // 检查设备是否在活跃列表中
            if(find(active_devices.begin(), active_devices.end(), d) != active_devices.end()) {
                chosen_devices.push_back(d);
                valid_choice = true;
            } else {
                cout<<"Device "<<d<<" is not active. Please choose from active devices: ";
            }
        }
    }
    
    // ============= 验证阶段计算开始（排除用户输入时间）=============
    auto verification_phase_start = chrono::high_resolution_clock::now();
    
    // 开始计时验证阶段的计算部分（排除用户输入时间）
    auto step3_start = chrono::high_resolution_clock::now();
    
    // 4. 计算α = H(pw)/session2（根据require.txt第19行）
    vec_ZZ_p alpha = compute_alpha(pw, session2, n_vector);
    cout<<"Computed alpha: "; 
    for(int i=0;i<n_vector;i++) cout<<rep(alpha[i])<<" "; 
    cout<<"\n";
    
    // 5. 将session2和α发送给选择的设备和服务器
    vector<ZZ_p> betas_from_devices;
    
    // 发送给选择的设备
    for(int dev : chosen_devices){
        boost::property_tree::ptree req; 
        req.put("kind","verification_request"); 
        req.put("session2", session2);
        
        boost::property_tree::ptree alpha_pt;
        for(int i=0;i<n_vector;i++) {
            alpha_pt.put(to_string(i), conv<unsigned long>(rep(alpha[i])));
        }
        req.add_child("alpha", alpha_pt);
        
        boost::property_tree::ptree resp; 
        send_json("127.0.0.1", 9100 + dev, req, &resp);
        
        u64 beta_raw = resp.get<u64>("beta");
        ZZ_p beta = conv<ZZ_p>(ZZ(beta_raw));
        betas_from_devices.push_back(beta);
        cout<<"Beta from device "<<dev<<": "<<rep(beta)<<"\n";
    }
    
    // 发送给服务器
    ZZ_p beta_server;
    {
        boost::property_tree::ptree req; 
        req.put("kind","verification_request"); 
        req.put("session2", session2);
        
        boost::property_tree::ptree alpha_pt;
        for(int i=0;i<n_vector;i++) {
            alpha_pt.put(to_string(i), conv<unsigned long>(rep(alpha[i])));
        }
        req.add_child("alpha", alpha_pt);
        
        boost::property_tree::ptree resp; 
        send_json("127.0.0.1", 9000, req, &resp);
        
        u64 beta_raw = resp.get<u64>("beta");
        beta_server = conv<ZZ_p>(ZZ(beta_raw));
        cout<<"Beta from server: "<<rep(beta_server)<<"\n";
    }
    
    // 请求服务器进行验证和密钥恢复
    {
        boost::property_tree::ptree req; 
        req.put("kind","server_verification");
        req.put("pw", pw);
        req.put("session2", session2);
        req.put("expected_rw", rw);  // 添加期望的PRF值用于调试
        
        boost::property_tree::ptree chosen_pt;
        for(size_t i=0;i<chosen_devices.size();i++){
            chosen_pt.put(to_string(i), chosen_devices[i]);
        }
        req.add_child("chosen_devices", chosen_pt);
        
        boost::property_tree::ptree resp; 
        send_json("127.0.0.1", 9000, req, &resp);
        
        bool verification_ok = resp.get<bool>("verification_ok");
        cout<<"[User] Server verification result: "<<(verification_ok?"SUCCESS":"FAILED")<<"\n";
        
        auto step3_end = chrono::high_resolution_clock::now();
        auto step3_duration = chrono::duration_cast<chrono::microseconds>(step3_end - step3_start);
        cout<<"[Time] Step 3 (Verification) completed in: "<<step3_duration.count()<<" μs ("<<step3_duration.count()/1000.0<<" ms)\n";
        
        // ============= 验证阶段结束 =============
        auto verification_phase_end = chrono::high_resolution_clock::now();
        auto verification_phase_duration = chrono::duration_cast<chrono::microseconds>(verification_phase_end - verification_phase_start);
        cout<<"\n[PHASE TIME] *** VERIFICATION PHASE TOTAL: "<<verification_phase_duration.count()<<" μs ("<<verification_phase_duration.count()/1000.0<<" ms) ***\n";
        
        if(!verification_ok){
            cout<<"[User] Verification failed in round "<<round<<".\n";
            cout<<"Key Agreement Phase skipped due to verification failure.\n";
        } else {
            cout<<"[User] Verification successful in round "<<round<<".\n";
            
            // ============= 密钥协商阶段开始 =============
            cout<<"\n============== KEY AGREEMENT PHASE ==============\n";
            auto key_agreement_phase_start = chrono::high_resolution_clock::now();
            
            // 四：密钥协商阶段（仅在验证成功后进行）
            cout<<"\n=== [User] Step 4: Key Agreement Phase ===\n";
            auto step4_start = chrono::high_resolution_clock::now();
            cout<<"Negotiated Key (rw): "<<rw<<"\n";
            cout<<"Key agreement completed successfully.\n";
            cout<<"Key can be used for secure communication.\n";
            auto step4_end = chrono::high_resolution_clock::now();
            auto step4_duration = chrono::duration_cast<chrono::microseconds>(step4_end - step4_start);
            cout<<"[Time] Step 4 (Key Agreement) completed in: "<<step4_duration.count()<<" μs ("<<step4_duration.count()/1000.0<<" ms)\n";
            
            // ============= 密钥协商阶段结束 =============
            auto key_agreement_phase_end = chrono::high_resolution_clock::now();
            auto key_agreement_phase_duration = chrono::duration_cast<chrono::microseconds>(key_agreement_phase_end - key_agreement_phase_start);
            cout<<"\n[PHASE TIME] *** KEY AGREEMENT PHASE TOTAL: "<<key_agreement_phase_duration.count()<<" μs ("<<key_agreement_phase_duration.count()/1000.0<<" ms) ***\n";
        }
    }

        // 五：密钥更新阶段 - 设备撤销
        // ============= 密钥更新阶段开始 =============
        cout<<"\n============== KEY UPDATE PHASE ================\n";
        cout<<"\n=== [User] Step 5: Key Update Phase (Device Revocation) ===\n";
    cout<<"Enter device IDs to revoke (comma-separated, or press Enter to skip): ";
    
    string input_line;
    cin.ignore(); // 清除之前的换行符
    getline(cin, input_line);
    
    // 开始计时密钥更新阶段的计算部分（排除用户输入时间）
    auto key_update_phase_start = chrono::high_resolution_clock::now();
    auto step5_start = chrono::high_resolution_clock::now();
    
    vector<int> revoked_devices;
    if(!input_line.empty() && input_line != "\n"){
        stringstream ss(input_line);
        string token;
        while(getline(ss, token, ',')){
            // 去除空格
            token.erase(remove_if(token.begin(), token.end(), ::isspace), token.end());
            if(!token.empty()){
                try {
                    int device_id = stoi(token);
                    if(device_id >= 1 && device_id <= n_devices){
                        revoked_devices.push_back(device_id);
                    } else {
                        cout<<"Warning: Device "<<device_id<<" is out of range (1-"<<n_devices<<"), skipping.\n";
                    }
                } catch(const exception &e) {
                    cout<<"Warning: Invalid device ID '"<<token<<"', skipping.\n";
                }
            }
        }
    }
    
    if(!revoked_devices.empty()){
        cout<<"Devices to revoke: ";
        for(size_t i = 0; i < revoked_devices.size(); i++){
            cout<<revoked_devices[i];
            if(i < revoked_devices.size()-1) cout<<", ";
        }
        cout<<"\n";
        
        // 执行密钥更新
        cout<<"Performing key update...\n";
        
        // 1. 生成session1参数
        string session1 = "session1_" + to_string(time(nullptr));
        cout<<"Generated session1 for key update: "<<session1<<"\n";
        
        // 2. 向服务器发送撤销请求
        boost::property_tree::ptree revoke_req;
        revoke_req.put("kind","revoke_devices");
        revoke_req.put("session1", session1);
        
        boost::property_tree::ptree revoked_pt;
        for(size_t i=0;i<revoked_devices.size();i++){
            revoked_pt.put(to_string(i), revoked_devices[i]);
        }
        revoke_req.add_child("revoked_devices", revoked_pt);
        
        boost::property_tree::ptree revoke_resp;
        send_json("127.0.0.1", 9000, revoke_req, &revoke_resp);
        
        bool revoke_ok = revoke_resp.get<bool>("revoke_ok");
        cout<<"[User] Device revocation result: "<<(revoke_ok?"SUCCESS":"FAILED")<<"\n";
        
        if(revoke_ok){
            cout<<"[User] Key update completed. System ready with revoked devices.\n";
            
            // 用户端也需要更新密钥：S, Sd, Ss都乘以session1因子
            ZZ_p session1_elem = hash_to_ZZp_single(session1);
            cout<<"Updating user-side keys with session1...\n";
            
            // 更新S, Sd, Ss
            for(int i = 0; i < n_vector; i++){
                S[i] *= session1_elem;
                Sd[i] *= session1_elem; 
                Ss[i] *= session1_elem;
            }
            
            // 重新计算PRF值，供下一轮验证使用
            ZZ_p inner_Sd_result, inner_Ss_result;
            vec_ZZ_p x = hash_to_vecZZp(pw, n_vector);
            InnerProduct(inner_Sd_result, x, Sd);
            InnerProduct(inner_Ss_result, x, Ss);
            
            u64 inner_Sd_u64 = conv<unsigned long>(inner_Sd_result);
            u64 inner_Ss_u64 = conv<unsigned long>(inner_Ss_result);
            
            u64 tmp3_Sd = round_toL(inner_Sd_u64, 2147483647, 1073741824);
            u64 tmp3_Ss = round_toL(inner_Ss_u64, 2147483647, 1073741824);
            
            u64 tmp3_sum = tmp3_Sd + tmp3_Ss;
            tmp3_sum = moduloL(tmp3_sum, 1073741824);
            
            rw = round_toL(tmp3_sum, 1073741824, 65536);
            cout<<"Updated PRF value (rw): "<<rw<<"\n";
            
            // 重新生成和存储测试密文（用新的PRF值）
            cout<<"Updating test cipher with new PRF value...\n";
            unsigned char new_aeskey[32];
            derive_aes_key_from_u64(rw, new_aeskey);
            vector<unsigned char> new_plain((unsigned char*)"Hello", (unsigned char*)"Hello"+5);
            vector<unsigned char> new_cipher, new_iv;
            aes_encrypt(new_aeskey, new_plain, new_cipher, new_iv);
            
            // 发送新密文给服务器存储
            boost::property_tree::ptree store_pt;
            store_pt.put("kind","store_cipher");
            
            boost::property_tree::ptree new_cpt;
            for(size_t i=0;i<new_cipher.size();++i) new_cpt.put(to_string(i), (int)new_cipher[i]);
            store_pt.add_child("cipher", new_cpt);
            
            boost::property_tree::ptree new_ivpt;
            for(size_t i=0;i<new_iv.size();++i) new_ivpt.put(to_string(i), (int)new_iv[i]);
            store_pt.add_child("iv", new_ivpt);
            
            boost::property_tree::ptree store_reply;
            send_json("127.0.0.1", 9000, store_pt, &store_reply);
            cout<<"Updated test cipher stored at server.\n";
        }
    } else {
        cout<<"No devices to revoke in round "<<round<<".\n";
    }
    
    auto step5_end = chrono::high_resolution_clock::now();
    auto step5_duration = chrono::duration_cast<chrono::microseconds>(step5_end - step5_start);
    cout<<"[Time] Step 5 (Key Update/Device Revocation) completed in: "<<step5_duration.count()<<" μs ("<<step5_duration.count()/1000.0<<" ms)\n";
    
    // ============= 密钥更新阶段结束 =============
    auto key_update_phase_end = chrono::high_resolution_clock::now();
    auto key_update_phase_duration = chrono::duration_cast<chrono::microseconds>(key_update_phase_end - key_update_phase_start);
    cout<<"\n[PHASE TIME] *** KEY UPDATE PHASE TOTAL: "<<key_update_phase_duration.count()<<" μs ("<<key_update_phase_duration.count()/1000.0<<" ms) ***\n";
    cout<<"================================================\n";
    
    // 询问用户是否继续
    cout<<"\nDo you want to continue to next round? (y/n): ";
    char choice;
    cin >> choice;
    if(choice == 'y' || choice == 'Y') {
        round++;
        continue_system = true;
    } else {
        continue_system = false;
    }
    
    } // end while loop
    
    cout<<"\n=== [User] System Terminated ===\n";
    return 0;
} 
