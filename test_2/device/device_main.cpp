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

struct DeviceState {
    int device_id{};
    int n_vector{};
    int t{};
    vec_ZZ_p SDi;  // 设备的秘密份额
    bool is_revoked{false};
    string last_session1{"1"};  // 默认为"1"表示被撤销
};

int main(int argc, char* argv[]){
    if(argc < 2){ cerr<<"Usage: device_main <device_id>\n"; return 1; }
    int device_id = atoi(argv[1]);
    
    ZZ_p::init(ZZ(2147483647));
    cout<<"[Device "<<device_id<<"] Starting device server\n";
    
    boost::asio::io_context io;
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 9100 + device_id));
    
    DeviceState state;
    state.device_id = device_id;
    
    while(true){
        tcp::socket sock(io);
        acceptor.accept(sock);
        string line = net::read_line(sock);
        auto pt = net::json_to_ptree(line);
        string kind = pt.get<string>("kind", "");
        
        if(kind == "register_device"){
            // 一：注册阶段 - 从User那里收到自己的秘密份额SDi
            cout<<"\n==================== REGISTRATION PHASE ====================\n";
            cout<<"\n=== [Device "<<device_id<<"] Registration Phase ===\n";
            auto registration_phase_start = chrono::high_resolution_clock::now();
            
            state.device_id = pt.get<int>("device_id");
            state.n_vector = pt.get<int>("n_vector");
            state.t = pt.get<int>("t");
            
            // 接收SDi
            auto sdi_pt = pt.get_child("SDi");
            state.SDi.SetLength(state.n_vector);
            for(int i = 0; i < state.n_vector; i++){
                unsigned long ul = sdi_pt.get<unsigned long>(to_string(i));
                state.SDi[i] = conv<ZZ_p>(ZZ(ul));
            }
            
            cout<<"Received SDi: ";
            for(int i = 0; i < state.n_vector; i++) cout<<rep(state.SDi[i])<<" ";
            cout<<"\n";
            
            boost::property_tree::ptree reply;
            reply.put("kind", "register_ack");
            reply.put("ok", 1);
            net::write_line(sock, net::ptree_to_json(reply));
            
            cout<<"[Device "<<device_id<<"] Registration completed.\n";
            
            // ============= 注册阶段结束 =============
            auto registration_phase_end = chrono::high_resolution_clock::now();
            auto registration_phase_duration = chrono::duration_cast<chrono::microseconds>(registration_phase_end - registration_phase_start);
            cout<<"\n[PHASE TIME] *** REGISTRATION PHASE TOTAL: "<<registration_phase_duration.count()<<" μs ("<<registration_phase_duration.count()/1000.0<<" ms) ***\n";
            cout<<"========================================================\n";
            
        } else if(kind == "verification_request"){
            // 二：验证阶段
            cout<<"\n================ VERIFICATION PHASE ================\n";
            cout<<"\n=== [Device "<<device_id<<"] Verification Phase ===\n";
            auto verification_phase_start = chrono::high_resolution_clock::now();
            auto verify_start = chrono::high_resolution_clock::now();
            
            if(state.is_revoked){
                cout<<"Device is revoked, rejecting verification request.\n";
                boost::property_tree::ptree reply;
                reply.put("kind", "verification_response");
                reply.put("error", "device_revoked");
                net::write_line(sock, net::ptree_to_json(reply));
                continue;
            }
            
            // 1. 接收session2和α值
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
            
            // 2. 计算βDi = α * SDi * session2（根据require.txt第40行）
            // 使用正确的PRF计算方式
            ZZ_p beta_di = compute_beta_device(alpha, state.SDi, session2, 2147483647, 1073741824, 65536);
            cout<<"Computed beta_di: "<<rep(beta_di)<<"\n";
            
            // 3. 将βDi发给User
            boost::property_tree::ptree reply;
            reply.put("kind", "verification_response");
            reply.put("beta", conv<unsigned long>(rep(beta_di)));
            net::write_line(sock, net::ptree_to_json(reply));
            
            auto verify_end = chrono::high_resolution_clock::now();
            auto verify_duration = chrono::duration_cast<chrono::microseconds>(verify_end - verify_start);
            cout<<"[Device "<<device_id<<"] Verification step completed.\n";
            cout<<"[Time] Device "<<device_id<<" verification completed in: "<<verify_duration.count()<<" μs ("<<verify_duration.count()/1000.0<<" ms)\n";
            
            // ============= 验证阶段结束 =============
            auto verification_phase_end = chrono::high_resolution_clock::now();
            auto verification_phase_duration = chrono::duration_cast<chrono::microseconds>(verification_phase_end - verification_phase_start);
            cout<<"\n[PHASE TIME] *** VERIFICATION PHASE TOTAL: "<<verification_phase_duration.count()<<" μs ("<<verification_phase_duration.count()/1000.0<<" ms) ***\n";
            
        } else if(kind == "key_update"){
            // 三：密钥更新阶段
            cout<<"\n============== KEY UPDATE PHASE ================\n";
            cout<<"\n=== [Device "<<device_id<<"] Key Update Phase ===\n";
            auto key_update_phase_start = chrono::high_resolution_clock::now();
            auto update_start = chrono::high_resolution_clock::now();
            
            // 1. 接收密钥更新参数session1
            string session1 = pt.get<string>("session1", "1");
            cout<<"Received session1: "<<session1<<"\n";
            
            // 2. 检查是否被撤销
            if(session1 == "1"){
                cout<<"Device "<<device_id<<" is being revoked (session1 = 1)\n";
                state.is_revoked = true;
            } else {
                cout<<"Device "<<device_id<<" is active, updating key\n";
                state.is_revoked = false;
            }
            
            // 3. 设备自身完成密钥更新操作：SDi' = SDi * session1
            ZZ_p session1_elem = hash_to_ZZp_single(session1);
            for(int i = 0; i < state.n_vector; i++){
                state.SDi[i] *= session1_elem;
            }
            state.last_session1 = session1;
            
            cout<<"Updated SDi': ";
            for(int i = 0; i < state.n_vector; i++) cout<<rep(state.SDi[i])<<" ";
            cout<<"\n";
            
            boost::property_tree::ptree reply;
            reply.put("kind", "key_update_ack");
            reply.put("ok", 1);
            reply.put("is_revoked", state.is_revoked);
            
            // 4. 如果未被撤销，发送更新后的密钥份额给Server（通过User请求）
            if(!state.is_revoked){
                boost::property_tree::ptree sdi_updated_pt;
                for(int i = 0; i < state.n_vector; i++){
                    sdi_updated_pt.put(to_string(i), conv<unsigned long>(rep(state.SDi[i])));
                }
                reply.add_child("SDi_updated", sdi_updated_pt);
            }
            
            net::write_line(sock, net::ptree_to_json(reply));
            
            auto update_end = chrono::high_resolution_clock::now();
            auto update_duration = chrono::duration_cast<chrono::microseconds>(update_end - update_start);
            cout<<"[Device "<<device_id<<"] Key update completed.\n";
            cout<<"[Time] Device "<<device_id<<" key update completed in: "<<update_duration.count()<<" μs ("<<update_duration.count()/1000.0<<" ms)\n";
            
            // ============= 密钥更新阶段结束 =============
            auto key_update_phase_end = chrono::high_resolution_clock::now();
            auto key_update_phase_duration = chrono::duration_cast<chrono::microseconds>(key_update_phase_end - key_update_phase_start);
            cout<<"\n[PHASE TIME] *** KEY UPDATE PHASE TOTAL: "<<key_update_phase_duration.count()<<" μs ("<<key_update_phase_duration.count()/1000.0<<" ms) ***\n";
            cout<<"================================================\n";
            
        } else if(kind == "send_updated_share"){
            // 响应服务器请求，发送更新后的份额
            cout<<"\n=== [Device "<<device_id<<"] Sending Updated Share ===\n";
            
            if(state.is_revoked){
                boost::property_tree::ptree reply;
                reply.put("kind", "share_response");
                reply.put("error", "device_revoked");
                net::write_line(sock, net::ptree_to_json(reply));
                continue;
            }
            
            boost::property_tree::ptree reply;
            reply.put("kind", "share_response");
            reply.put("device_id", state.device_id);
            
            boost::property_tree::ptree sdi_pt;
            for(int i = 0; i < state.n_vector; i++){
                sdi_pt.put(to_string(i), conv<unsigned long>(rep(state.SDi[i])));
            }
            reply.add_child("SDi_updated", sdi_pt);
            
            net::write_line(sock, net::ptree_to_json(reply));
            
            cout<<"[Device "<<device_id<<"] Updated share sent to server.\n";
            
        } else if(kind == "status"){
            // 状态查询
            boost::property_tree::ptree reply;
            reply.put("kind", "status_response");
            reply.put("device_id", state.device_id);
            reply.put("is_revoked", state.is_revoked);
            reply.put("last_session1", state.last_session1);
            net::write_line(sock, net::ptree_to_json(reply));
            
        } else {
            cerr<<"[Device "<<device_id<<"] Unknown request kind: "<<kind<<"\n";
            boost::property_tree::ptree reply;
            reply.put("kind", "error");
            reply.put("message", "unknown_request");
            net::write_line(sock, net::ptree_to_json(reply));
        }
    }
    
    return 0;
} 
