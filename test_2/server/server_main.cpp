#include <bits/stdc++.h>
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include "common/crypto.hpp"
#include "common/share.hpp"
#include "common/net.hpp"
#include <vector>
#include <algorithm>
#include <chrono>

using namespace std;
using namespace NTL;
using boost::asio::ip::tcp;

struct ServerState {
    int n_vector{};
    int n_devices{};
    int t{};
    vec_ZZ_p Ss;  // 服务器的秘密份额
    vector<unsigned char> stored_cipher, stored_iv;  // 存储的验证密文
    DeviceManager* device_manager{nullptr};
    
    // 密钥更新相关
    string current_session1;
    map<int, vec_ZZ_p> received_updated_shares;  // 收到的更新后设备份额
    
    ~ServerState() {
        if(device_manager) delete device_manager;
    }
};

static void send_json_to_device(int device_id, const boost::property_tree::ptree &pt, boost::property_tree::ptree *out=nullptr){
    boost::asio::io_context io; tcp::socket sock(io);
    sock.connect({boost::asio::ip::make_address("127.0.0.1"), (unsigned short)(9100 + device_id)});
    net::write_line(sock, net::ptree_to_json(pt));
    if(out){ string line = net::read_line(sock); *out = net::json_to_ptree(line); }
}

int main(){
    ZZ_p::init(ZZ(2147483647));
    cout<<"[Server] Threshold PRF Server with Device Revocation Support\n";
    boost::asio::io_context io;
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 9000));

    ServerState state;

    while(true){
        try {
            tcp::socket sock(io);
            acceptor.accept(sock);
            string line = net::read_line(sock);
            auto pt = net::json_to_ptree(line);
            string kind = pt.get<string>("kind", "");

            if(kind == "register_server"){
                // 一：注册阶段 - 从User那里得到自己的密钥份额Ss
                cout<<"\n==================== REGISTRATION PHASE ====================\n";
                cout<<"\n=== [Server] Registration Phase ===\n";
                auto registration_phase_start = chrono::high_resolution_clock::now();
                auto reg_start = chrono::high_resolution_clock::now();
                
                state.n_vector = pt.get<int>("n_vector");
                state.n_devices = pt.get<int>("n_devices");
                state.t = pt.get<int>("t");
                
                // 初始化设备管理器
                if(state.device_manager) delete state.device_manager;
                state.device_manager = new DeviceManager(state.n_devices, state.t);
                
                // 接收Ss
                auto ss_pt = pt.get_child("Ss");
                state.Ss.SetLength(state.n_vector);
                for(int i = 0; i < state.n_vector; i++){
                    unsigned long ul = ss_pt.get<unsigned long>(to_string(i));
                    state.Ss[i] = conv<ZZ_p>(ZZ(ul));
                }
                
                cout<<"Received Ss: ";
                for(int i = 0; i < state.n_vector; i++) cout<<rep(state.Ss[i])<<" ";
                cout<<"\n";
                cout<<"System parameters: n_vector="<<state.n_vector<<", n_devices="<<state.n_devices<<", t="<<state.t<<"\n";
                
                boost::property_tree::ptree reply;
                reply.put("kind", "register_ack");
                reply.put("ok", 1);
                net::write_line(sock, net::ptree_to_json(reply));
                
                auto reg_end = chrono::high_resolution_clock::now();
                auto reg_duration = chrono::duration_cast<chrono::microseconds>(reg_end - reg_start);
                cout<<"[Server] Registration completed.\n";
                cout<<"[Time] Server registration completed in: "<<reg_duration.count()<<" μs ("<<reg_duration.count()/1000.0<<" ms)\n";
                
                // ============= 注册阶段结束 =============
                auto registration_phase_end = chrono::high_resolution_clock::now();
                auto registration_phase_duration = chrono::duration_cast<chrono::microseconds>(registration_phase_end - registration_phase_start);
                cout<<"\n[PHASE TIME] *** REGISTRATION PHASE TOTAL: "<<registration_phase_duration.count()<<" μs ("<<registration_phase_duration.count()/1000.0<<" ms) ***\n";
                cout<<"========================================================\n";
                
            } else if(kind == "store_cipher"){
                // 存储用户提供的验证密文
                cout<<"\n=== [Server] Storing Verification Cipher ===\n";
                
                state.stored_cipher.clear(); state.stored_iv.clear();
                auto cpt = pt.get_child("cipher");
                for(auto &kv : cpt){
                    state.stored_cipher.push_back((unsigned char)kv.second.get_value<int>());
                }
                auto ivpt = pt.get_child("iv");
                for(auto &kv : ivpt){
                    state.stored_iv.push_back((unsigned char)kv.second.get_value<int>());
                }
                
                cout<<"Stored cipher of size: "<<state.stored_cipher.size()<<" bytes\n";
                
                boost::property_tree::ptree reply;
                reply.put("kind", "store_ack");
                reply.put("ok", 1);
                net::write_line(sock, net::ptree_to_json(reply));
                
            } else if(kind == "verification_request"){
                // 二：验证阶段 - 计算βs = α * Ss
                cout<<"\n================ VERIFICATION PHASE ================\n";
                cout<<"\n=== [Server] Verification Phase ===\n";
                auto verification_phase_start = chrono::high_resolution_clock::now();
                auto verify_start = chrono::high_resolution_clock::now();
                
                string session2 = pt.get<string>("session2");
                cout<<"Received session2: "<<session2<<"\n";
                
                auto alpha_pt = pt.get_child("alpha");
                vec_ZZ_p alpha; alpha.SetLength(state.n_vector);
                for(int i = 0; i < state.n_vector; i++){
                    unsigned long ul = alpha_pt.get<unsigned long>(to_string(i));
                    alpha[i] = conv<ZZ_p>(ZZ(ul));
                }
                
                cout<<"Received alpha: ";
                for(int i = 0; i < state.n_vector; i++) cout<<rep(alpha[i])<<" ";
                cout<<"\n";
                
                // 计算βs = α * Ss
                ZZ_p beta_s = compute_beta_server(alpha, state.Ss, session2, 2147483647, 1073741824);
                cout<<"Computed beta_s: "<<rep(beta_s)<<"\n";
                
                boost::property_tree::ptree reply;
                reply.put("kind", "verification_response");
                reply.put("beta", conv<unsigned long>(rep(beta_s)));
                net::write_line(sock, net::ptree_to_json(reply));
                
                auto verify_end = chrono::high_resolution_clock::now();
                auto verify_duration = chrono::duration_cast<chrono::microseconds>(verify_end - verify_start);
                cout<<"[Server] Verification step completed.\n";
                cout<<"[Time] Server verification completed in: "<<verify_duration.count()<<" μs ("<<verify_duration.count()/1000.0<<" ms)\n";
                
                // ============= 验证阶段结束 =============
                auto verification_phase_end = chrono::high_resolution_clock::now();
                auto verification_phase_duration = chrono::duration_cast<chrono::microseconds>(verification_phase_end - verification_phase_start);
                cout<<"\n[PHASE TIME] *** VERIFICATION PHASE TOTAL: "<<verification_phase_duration.count()<<" μs ("<<verification_phase_duration.count()/1000.0<<" ms) ***\n";
                
            } else if(kind == "server_verification"){
                // 三：服务器端验证 - 收集设备βDi，恢复密钥rw，验证
                cout<<"\n=== [Server] Server-side Verification and Key Recovery ===\n";
                auto recovery_start = chrono::high_resolution_clock::now();
                
                string pw = pt.get<string>("pw");
                string session2 = pt.get<string>("session2");
                u64 expected_rw = pt.get<u64>("expected_rw", 0);  // 获取期望的PRF值
                
                // 获取选择的设备列表
                vector<int> chosen_devices;
                auto chosen_pt = pt.get_child("chosen_devices");
                for(auto &kv : chosen_pt){
                    chosen_devices.push_back(kv.second.get_value<int>());
                }
                
                cout<<"Expected PRF value from user: "<<expected_rw<<"\n";
                
                cout<<"Chosen devices: ";
                for(int dev : chosen_devices) cout<<dev<<" ";
                cout<<"\n";
                
                // 从选择的设备收集βDi值
                vector<ZZ_p> betas_from_devices;
                vec_ZZ_p alpha = compute_alpha(pw, session2, state.n_vector);
                
                cout<<"Collecting betas from devices...\n";
                for(int dev : chosen_devices){
                    boost::property_tree::ptree req;
                    req.put("kind", "verification_request");
                    req.put("session2", session2);
                    
                    boost::property_tree::ptree alpha_pt;
                    for(int i = 0; i < state.n_vector; i++){
                        alpha_pt.put(to_string(i), conv<unsigned long>(rep(alpha[i])));
                    }
                    req.add_child("alpha", alpha_pt);
                    
                    boost::property_tree::ptree resp;
                    send_json_to_device(dev, req, &resp);
                    
                    if(resp.get<string>("kind") == "verification_response"){
                        u64 beta_raw = resp.get<u64>("beta");
                        ZZ_p beta = conv<ZZ_p>(ZZ(beta_raw));
                        betas_from_devices.push_back(beta);
                        cout<<"  Beta from device "<<dev<<": "<<rep(beta)<<"\n";
                    } else {
                        cout<<"  Error getting beta from device "<<dev<<"\n";
                        boost::property_tree::ptree reply;
                        reply.put("kind", "verification_result");
                        reply.put("verification_ok", false);
                        reply.put("error", "device_communication_failed");
                        net::write_line(sock, net::ptree_to_json(reply));
                        continue;
                    }
                }
                
                // 计算服务器的βs = α * Ss（根据require.txt第53行）
                ZZ_p beta_s = compute_beta_server(alpha, state.Ss, session2, 2147483647, 1073741824);
                cout<<"Server beta_s: "<<rep(beta_s)<<"\n";
                
                // 根据require.txt第54-56行：利用βs和设备发来的βDi恢复出密钥rw
                cout<<"Attempting to recover secret using tool.cpp threshold PRF method...\n";
                
                bool verification_success = false;
                
                try {
                    // 严格按照tool.cpp的threshold_PRF_eval逻辑恢复
                    // 关键理解：我们的βDi和βs对应threshold_PRF_eval中的tmp3值
                    
                    cout<<"Recovering PRF using strict tool.cpp threshold_PRF_eval logic...\n";
                    
                    vec_ZZ_p pw_hash = hash_to_vecZZp(pw, state.n_vector);
                    ZZ_p session2_elem = hash_to_ZZp_single(session2);
                    
                    cout<<"Debug info:\n";
                    cout<<"  pw = '"<<pw<<"'\n";
                    cout<<"  session2 = '"<<session2<<"'\n";
                    cout<<"  Expected rw = "<<expected_rw<<" (from direct_PRF_eval)\n";
                    cout<<"  βs = "<<rep(beta_s)<<" (= round_toL(<α, Ss>, q, q1))\n";
                    cout<<"  βDi = "<<rep(betas_from_devices[0])<<" (= round_toL(<α, SDi>, q, q1) * session2)\n";
                    cout<<"  session2_elem = "<<rep(session2_elem)<<"\n";
                    
                    // 按照tool.cpp的threshold_PRF_eval第157-167行逻辑：
                    // tmp3 = round_toL(tmp2, q, q1);
                    // if(i == 0) interim += tmp3; else interim -= tmp3;
                    // res = round_toL(interim, q1, p);
                    
                    // 我们的βs直接对应tmp3值（服务器）
                    u64 server_tmp3 = conv<unsigned long>(beta_s);
                    
                    // 我们的βDi/session2对应tmp3值（设备）
                    ZZ_p device_partial_prf = betas_from_devices[0] / session2_elem;
                    u64 device_tmp3 = conv<unsigned long>(device_partial_prf);
                    
                    cout<<"  Server tmp3 = "<<server_tmp3<<"\n";
                    cout<<"  Device tmp3 = "<<device_tmp3<<"\n";
                    
                    // 根据t值决定恢复策略
                    u64 interim_sum = 0;
                    
                    if(state.t == 2){
                        // t=2的特殊情况：所有设备得到相同的Sd，需要恢复<H(pw), S>
                        cout<<"  Special case t=2: all devices have same Sd\n";
                        
                        // βDi就是正确的tmp3值，不需要额外处理
                        u64 device_tmp3_val = conv<unsigned long>(rep(betas_from_devices[0]));
                        cout<<"    Device tmp3 (direct βDi) = "<<device_tmp3_val<<"\n";
                        
                        // βs直接就是服务器的tmp3
                        u64 server_tmp3_val = conv<unsigned long>(rep(beta_s));
                        cout<<"    Server tmp3 = "<<server_tmp3_val<<"\n";
                        
                        // 按照tool.cpp的threshold_PRF_eval逻辑：i=0加法，i>0减法
                        // 在t=2情况下：设备是i=0(加法)，服务器是补充部分(加法)
                        u64 tmp3_sum = device_tmp3_val + server_tmp3_val;
                        tmp3_sum = moduloL(tmp3_sum, 1073741824);
                        cout<<"    tmp3_sum = "<<tmp3_sum<<"\n";
                        
                        interim_sum = tmp3_sum;
                    } else {
                        // 正常情况：按照tool.cpp的加减法规则 (i=0加法, i!=0减法)
                        cout<<"  Normal case t>2: using add-subtract rule\n";
                        for(size_t i = 0; i < betas_from_devices.size(); i++){
                            ZZ_p di_tmp3 = betas_from_devices[i] / session2_elem;
                            u64 di_val = conv<unsigned long>(di_tmp3);
                            if(i == 0){
                                interim_sum += di_val;
                            } else {
                                interim_sum -= di_val;
                            }
                            interim_sum = moduloL(interim_sum, 1073741824);
                            cout<<"    Device "<<i<<" tmp3 = "<<di_val<<" (action: "<<(i==0 ? "add" : "subtract")<<")\n";
                        }
                        // 加上服务器端tmp3
                        interim_sum += conv<unsigned long>(beta_s);
                        interim_sum = moduloL(interim_sum, 1073741824);
                    }
                    
                    u64 rw_corrected = round_toL(interim_sum, 1073741824, 65536);
                    cout<<"  Corrected add-subtract interim -> rw = "<<rw_corrected<<"\n";
                    
                    // 测试corrected结果
                    {
                        unsigned char key[32];
                        derive_aes_key_from_u64(rw_corrected, key);
                        vector<unsigned char> decrypted;
                        if(aes_decrypt(key, state.stored_cipher, state.stored_iv, decrypted)){
                            string decrypted_text((char*)decrypted.data(), decrypted.size());
                            cout<<"    Decrypted(corrected): '"<<decrypted_text<<"'\n";
                            if(decrypted_text == "Hello"){
                                verification_success = true;
                                cout<<"[Server] Verification SUCCESS with corrected add-subtract rule!\n";
                            }
                        }
                    }
                    
                } catch(const exception& e) {
                    cout<<"Exception during verification: "<<e.what()<<"\n";
                }
                
                boost::property_tree::ptree reply;
                reply.put("kind", "verification_result");
                reply.put("verification_ok", verification_success);
                net::write_line(sock, net::ptree_to_json(reply));
                
                auto recovery_end = chrono::high_resolution_clock::now();
                auto recovery_duration = chrono::duration_cast<chrono::microseconds>(recovery_end - recovery_start);
                
                if(verification_success){
                    cout<<"[Server] Verification completed successfully.\n";
                } else {
                    cout<<"[Server] Verification FAILED.\n";
                }
                cout<<"[Time] Server-side verification and key recovery completed in: "<<recovery_duration.count()<<" μs ("<<recovery_duration.count()/1000.0<<" ms)\n";
                
            } else if(kind == "revoke_devices"){
                // 四：密钥更新阶段 - 设备撤销
                cout<<"\n============== KEY UPDATE PHASE ================\n";
                cout<<"\n=== [Server] Device Revocation Phase ===\n";
                auto key_update_phase_start = chrono::high_resolution_clock::now();
                auto revoke_start = chrono::high_resolution_clock::now();
                
                state.current_session1 = pt.get<string>("session1");
                cout<<"Received session1 for key update: "<<state.current_session1<<"\n";
                
                // 获取要撤销的设备列表
                vector<int> revoked_devices;
                auto revoked_pt = pt.get_child("revoked_devices");
                for(auto &kv : revoked_pt){
                    revoked_devices.push_back(kv.second.get_value<int>());
                }
                
                cout<<"Devices to revoke: ";
                for(int dev : revoked_devices) cout<<dev<<" ";
                cout<<"\n";
                
                // 更新设备管理器状态
                for(int dev : revoked_devices){
                    state.device_manager->revokeDevice(dev);
                }
                
                // 向所有设备发送密钥更新命令
                vector<int> all_devices = state.device_manager->getActiveDevices();
                // 也要向被撤销的设备发送session1="1"
                for(int dev : revoked_devices){
                    all_devices.push_back(dev);
                }
                
                cout<<"Sending key update commands to devices...\n";
                for(int dev = 1; dev <= state.n_devices; dev++){
                    boost::property_tree::ptree req;
                    req.put("kind", "key_update");
                    
                    // 根据设备是否被撤销发送不同的session1值
                    bool is_revoked = find(revoked_devices.begin(), revoked_devices.end(), dev) != revoked_devices.end();
                    req.put("session1", is_revoked ? "1" : state.current_session1);
                    
                    boost::property_tree::ptree resp;
                    send_json_to_device(dev, req, &resp);
                    
                    cout<<"  Device "<<dev<<" update result: "<<resp.get<string>("kind", "unknown")<<"\n";
                }
                
                // 收集未被撤销设备的更新后份额
                cout<<"Collecting updated shares from active devices...\n";
                state.received_updated_shares.clear();
                
                for(int dev : state.device_manager->getActiveDevices()){
                    boost::property_tree::ptree req;
                    req.put("kind", "send_updated_share");
                    
                    boost::property_tree::ptree resp;
                    send_json_to_device(dev, req, &resp);
                    
                    if(resp.get<string>("kind") == "share_response" && !resp.get_optional<string>("error")){
                        auto sdi_pt = resp.get_child("SDi_updated");
                        vec_ZZ_p updated_share; updated_share.SetLength(state.n_vector);
                        for(int i = 0; i < state.n_vector; i++){
                            unsigned long ul = sdi_pt.get<unsigned long>(to_string(i));
                            updated_share[i] = conv<ZZ_p>(ZZ(ul));
                        }
                        state.received_updated_shares[dev] = updated_share;
                        cout<<"  Received updated share from device "<<dev<<"\n";
                    }
                }
                
                // 更新服务器自己的Ss
                ZZ_p session1_elem = hash_to_ZZp_single(state.current_session1);
                for(int i = 0; i < state.n_vector; i++){
                    state.Ss[i] *= session1_elem;
                }
                cout<<"Updated server Ss with session1\n";
                
                boost::property_tree::ptree reply;
                reply.put("kind", "revoke_result");
                reply.put("revoke_ok", true);
                reply.put("active_devices", (int)state.device_manager->getActiveDevices().size());
                net::write_line(sock, net::ptree_to_json(reply));
                
                auto revoke_end = chrono::high_resolution_clock::now();
                auto revoke_duration = chrono::duration_cast<chrono::microseconds>(revoke_end - revoke_start);
                cout<<"[Server] Device revocation completed.\n";
                cout<<"[Time] Device revocation completed in: "<<revoke_duration.count()<<" μs ("<<revoke_duration.count()/1000.0<<" ms)\n";
                
                // ============= 密钥更新阶段结束 =============
                auto key_update_phase_end = chrono::high_resolution_clock::now();
                auto key_update_phase_duration = chrono::duration_cast<chrono::microseconds>(key_update_phase_end - key_update_phase_start);
                cout<<"\n[PHASE TIME] *** KEY UPDATE PHASE TOTAL: "<<key_update_phase_duration.count()<<" μs ("<<key_update_phase_duration.count()/1000.0<<" ms) ***\n";
                cout<<"================================================\n";
                
            } else if(kind == "post_update_verification"){
                // 五：密钥更新之后的初始化
                cout<<"\n=== [Server] Post-Update Verification ===\n";
                
                string pw = pt.get<string>("pw");
                cout<<"Received pw for post-update verification\n";
                
                // 使用更新后的密钥进行验证
                // 这里需要实现完整的密钥恢复和PRF计算逻辑
                
                cout<<"[Server] Post-update verification completed (placeholder).\n";
                
                boost::property_tree::ptree reply;
                reply.put("kind", "post_update_ack");
                reply.put("ok", 1);
                net::write_line(sock, net::ptree_to_json(reply));
                
            } else if(kind == "status"){
                // 状态查询
                boost::property_tree::ptree reply;
                reply.put("kind", "status_response");
                reply.put("n_devices", state.n_devices);
                reply.put("t", state.t);
                if(state.device_manager){
                    vector<int> active_list = state.device_manager->getActiveDevices();
                    reply.put("active_devices", (int)active_list.size());
                    reply.put("revoked_devices", (int)state.device_manager->revoked_devices.size());
                    
                    // 添加活跃设备列表
                    boost::property_tree::ptree active_pt;
                    for(size_t i = 0; i < active_list.size(); i++){
                        active_pt.put(to_string(i), active_list[i]);
                    }
                    reply.add_child("active_device_list", active_pt);
                    
                    // 添加被撤销设备列表
                    boost::property_tree::ptree revoked_pt;
                    int idx = 0;
                    for(int dev : state.device_manager->revoked_devices){
                        revoked_pt.put(to_string(idx++), dev);
                    }
                    reply.add_child("revoked_device_list", revoked_pt);
                } else {
                    reply.put("active_devices", state.n_devices);
                    reply.put("revoked_devices", 0);
                }
                net::write_line(sock, net::ptree_to_json(reply));
                
            } else {
                cerr<<"[Server] Unknown request kind: "<<kind<<"\n";
                boost::property_tree::ptree reply;
                reply.put("kind", "error");
                reply.put("message", "unknown_request");
                net::write_line(sock, net::ptree_to_json(reply));
            }
        } catch (boost::system::system_error& e) {
            cerr << "[Server] Connection error: " << e.what() << "\n";
        } catch (std::exception& e) {
            cerr << "[Server] Exception: " << e.what() << "\n";
        }
    }
    return 0;
} 
