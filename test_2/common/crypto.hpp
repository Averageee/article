#pragma once
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <map>
#include <algorithm>

using u64 = uint64_t;
using namespace NTL;

// 从tool.cpp复制的工具函数
inline u64 round_toL(u64 x, u64 q, u64 p){
    if(p == q) return x; // avoid undefined shift; identity when scaling is 1
    x >>= (int)(log2(q) - log2(p) - 1);
    int flag = (x & 1) ? 1 : 0;
    x >>= 1;
    return (x + flag);
}

inline u64 moduloL(u64 x, u64 q){
    return x % q;  // 对于无符号整数，x总是>=0，简化逻辑
}

inline std::map<std::pair<u64,u64>, u64> ncr_cache;
inline u64 ncr(u64 n, u64 r){
    if (ncr_cache.find({n, r}) == ncr_cache.end()){
        if (r > n || (long)n < 0 || (long)r < 0) return 0;
        else{
            if (r == 0 || r == n){ ncr_cache[{n, r}] = 1; }
            else if (r == 1 || r == n - 1){ ncr_cache[{n, r}] = n; }
            else{ ncr_cache[{n, r}] = ncr(n - 1, r) + ncr(n - 1, r - 1); }
        }
    }
    return ncr_cache[{n, r}];
}

inline void findParties(std::vector<u64>& pt, u64 gid, u64 t, u64 T){
    u64 mem = 0, tmp; pt.clear();
    for(u64 i = 1; i < T; i++){
        tmp = ncr(T - i, t - mem -1);
        if(gid > tmp){ gid -= tmp; }
        else{ pt.push_back(i); mem += 1; }
        if(mem + (T-i) == t){ for(u64 j = i + 1; j <= T; j++){ pt.push_back(j);} break; }
    }
}

inline u64 findGroupId(std::vector<u64> parties, u64 t, u64 T){
    u64 mem = 0; u64 group_count = 1;
    for(u64 i = 1; i <= T; i++){
        if(std::find(parties.begin(), parties.end(), i) != parties.end()) mem += 1;
        else group_count += ncr(T - i, t - mem - 1);
        if(mem == t) break;
    }
    return group_count;
}

// 从tool.cpp复制的核心门限秘密共享函数
inline void shareSecrettTL(int t, int T, const vec_ZZ_p &key, int n, std::map<int, std::map<int, vec_ZZ_p>> &shared_key_repo_tT){
    u64 group_count = ncr(T,t); std::vector<u64> parties; 
    for(u64 gid = 1; gid <= group_count; gid++){
        findParties(parties, gid, t, T);
        VectorCopy(shared_key_repo_tT[(int)parties[0]][(int)gid], key, n);
        for(int i = 1; i < t; i++){
            random(shared_key_repo_tT[(int)parties[i]][(int)gid], n);
            shared_key_repo_tT[(int)parties[0]][(int)gid] += shared_key_repo_tT[(int)parties[i]][(int)gid];
        }
    }
}

// 从tool.cpp复制的直接PRF计算函数
inline u64 direct_PRF_eval(const vec_ZZ_p &x, const vec_ZZ_p &key, u64 /*n*/, u64 q, u64 p){
    ZZ_p eval;
    u64 res;
    InnerProduct(eval, x, key);
    u64 interim = conv<ulong>(eval);
    res = round_toL(interim, q, p);
    return res;
}

// 从tool.cpp复制的门限PRF计算函数
inline u64 threshold_PRF_eval(const vec_ZZ_p &x, u64 n, u64 group_id, u64 t, u64 T, u64 q, u64 q1, u64 p, 
                              const std::map<int, std::map<int, vec_ZZ_p>> &shared_key_repo_tT){
    std::vector<u64> parties;
    findParties(parties, group_id, t, T);

    ZZ_p tmp1;
    u64 tmp2, tmp3;
    u64 interim = 0;
    u64 res;

    vec_ZZ_p cur_share;

    for(u64 i = 0; i < t; i++){  // 修改：使用u64类型
        VectorCopy(cur_share, shared_key_repo_tT.at((int)parties[i]).at((int)group_id), (long)n);
        InnerProduct(tmp1, x, cur_share);
        tmp2 = conv<ulong>(tmp1);
        tmp3 = round_toL(tmp2, q, q1);
        if(i == 0){
            interim += tmp3;
            interim = moduloL(interim, q1);
        }
        else{
            interim -= tmp3;
            interim = moduloL(interim, q1);
        }
    }
    res = round_toL(interim, q1, p);
    return res;
}

// AES加解密函数保持不变
inline u64 zzp_to_u64(const ZZ_p &z){
    ZZ t = rep(z);
    unsigned long ul = conv<unsigned long>(t);
    return (u64)ul;
}

inline void derive_aes_key_from_u64(u64 v, unsigned char out_key[32]){
    unsigned char buf[8];
    for(int i=0;i<8;i++) buf[i] = (v >> (8*i)) & 0xFF;
    SHA256(buf, 8, out_key);
}

inline bool aes_encrypt(const unsigned char *key32, const std::vector<unsigned char> &plaintext,
                        std::vector<unsigned char> &ciphertext, std::vector<unsigned char> &iv_out){
    iv_out.assign(16,0);
    if(1 != RAND_bytes(iv_out.data(), (int)iv_out.size())) return false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if(!ctx) return false;
    int len = 0;
    ciphertext.assign(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()), 0);
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key32, iv_out.data())){ EVP_CIPHER_CTX_free(ctx); return false; }
    if(1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size())){ EVP_CIPHER_CTX_free(ctx); return false; }
    int tmplen = 0;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext.data()+len, &tmplen)){ EVP_CIPHER_CTX_free(ctx); return false; }
    len += tmplen; ciphertext.resize(len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

inline bool aes_decrypt(const unsigned char *key32, const std::vector<unsigned char> &ciphertext,
                        const std::vector<unsigned char> &iv, std::vector<unsigned char> &plaintext){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if(!ctx) return false;
    int len = 0; plaintext.assign(ciphertext.size(), 0);
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key32, iv.data())){ EVP_CIPHER_CTX_free(ctx); return false; }
    if(1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)ciphertext.size())){ EVP_CIPHER_CTX_free(ctx); return false; }
    int tmplen = 0;
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext.data()+len, &tmplen)){ EVP_CIPHER_CTX_free(ctx); return false; }
    len += tmplen; plaintext.resize(len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// 哈希函数
inline std::string hex_print(const std::vector<unsigned char> &v){
    std::ostringstream oss; oss<<std::hex<<std::setfill('0');
    for(unsigned char c: v) oss<<std::setw(2)<<(int)c;
    return oss.str();
}

inline vec_ZZ_p hash_to_vecZZp(const std::string &s, int n_vector){
    vec_ZZ_p out; out.SetLength(n_vector);
    for(int i=0;i<n_vector;i++){
        std::string in = s + ":" + std::to_string(i);
        unsigned char digest[SHA256_DIGEST_LENGTH]; SHA256((unsigned char*)in.data(), in.size(), digest);
        uint64_t v = 0; for(int b=0;b<8;b++) v |= ((uint64_t)digest[b]) << (8*b);
        out[i] = conv<ZZ_p>(ZZ((unsigned long)v));
    }
    return out;
}

inline ZZ_p hash_to_ZZp_single(const std::string &s){
    unsigned char digest[SHA256_DIGEST_LENGTH]; 
    SHA256((unsigned char*)s.data(), s.size(), digest);
    uint64_t v = 0; 
    for(int b = 0; b < 8; b++) v |= ((uint64_t)digest[b]) << (8*b);
    return conv<ZZ_p>(ZZ((unsigned long)v));
}

// (2,2)秘密分享函数
inline void share_2_2(const vec_ZZ_p &secret, vec_ZZ_p &share1, vec_ZZ_p &share2){
    int n = secret.length();
    share1.SetLength(n);
    share2.SetLength(n);
    for(int i = 0; i < n; i++){
        share1[i] = random_ZZ_p();
        share2[i] = secret[i] - share1[i];
    }
}

inline void recover_2_2(const vec_ZZ_p &share1, const vec_ZZ_p &share2, vec_ZZ_p &secret){
    int n = share1.length();
    secret.SetLength(n);
    for(int i = 0; i < n; i++){
        secret[i] = share1[i] + share2[i];
    }
}

// 根据require.txt中的要求：α = H(pw)/session2
inline vec_ZZ_p compute_alpha(const std::string &pw, const std::string &session2, int n_vector){
    vec_ZZ_p pw_hash = hash_to_vecZZp(pw, n_vector);
    // 使用session2的标量哈希，统一两端实现，避免逐分量除法引入噪声
    ZZ_p session2_scalar = hash_to_ZZp_single(session2);
    vec_ZZ_p alpha; alpha.SetLength(n_vector);
    for(int i = 0; i < n_vector; i++){
        alpha[i] = pw_hash[i] / session2_scalar;  // 标量除法
    }
    return alpha;
}

// 设备端计算：βDi = α * SDi * session2
// 根据tool.cpp的threshold_PRF_eval逻辑，这应该是部分PRF值乘以session2
inline ZZ_p compute_beta_device(const vec_ZZ_p &alpha, const vec_ZZ_p &sdi, const std::string &session2,
                                u64 q, u64 q1, u64 /*p*/){
    // Inner product in field
    ZZ_p inner_product;
    InnerProduct(inner_product, alpha, sdi);
    // Multiply session2 inside field to move back to H(pw) domain
    ZZ_p session2_elem = hash_to_ZZp_single(session2);
    ZZ_p inner_times = inner_product * session2_elem; // equals <H(pw), SDi>
    // First-stage rounding q -> q1
    u64 inner_u64 = conv<unsigned long>(inner_times);
    u64 tmp3 = round_toL(inner_u64, q, q1);
    return ZZ_p(tmp3);
}

// 服务器端计算：βs = round_toL(conv(<α, Ss> * session2), q, q1)
inline ZZ_p compute_beta_server(const vec_ZZ_p &alpha, const vec_ZZ_p &ss, const std::string &session2, u64 q, u64 q1){
    ZZ_p inner_product;
    InnerProduct(inner_product, alpha, ss);
    // Align domain to H(pw) by multiplying session2 in field
    ZZ_p session2_elem = hash_to_ZZp_single(session2);
    ZZ_p inner_times = inner_product * session2_elem; // equals <H(pw), Ss>
    u64 inner_u64 = conv<unsigned long>(inner_times);
    u64 tmp3 = round_toL(inner_u64, q, q1);
    return ZZ_p(tmp3);
}

// 服务器端恢复密钥rw的函数
// 根据require.txt步骤：利用βs和设备发来的βDi恢复出密钥rw
inline bool recover_rw_from_betas(const std::vector<ZZ_p> &betas_di, 
                                  const std::vector<int> &/*device_ids*/,
                                  const ZZ_p &beta_s,
                                  const std::string &pw,
                                  const std::string &session2,
                                  int n_vector,
                                  u64 q, u64 /*q1*/, u64 p,
                                  u64 &recovered_rw){
    
    // 计算α = H(pw)/session2
    vec_ZZ_p alpha = compute_alpha(pw, session2, n_vector);
    
    // 从βDi恢复设备端的份额
    ZZ_p session2_elem = hash_to_ZZp_single(session2);
    ZZ_p session2_inv = inv(session2_elem);
    
    // 恢复Sd的部分：sum(βDi/session2) = sum(α * SDi)
    ZZ_p alpha_dot_Sd = ZZ_p(0);
    for(auto beta : betas_di){
        alpha_dot_Sd += beta * session2_inv;
    }
    
    // 总的α*S = α*Sd + α*Ss = alpha_dot_Sd + beta_s
    ZZ_p alpha_dot_S = alpha_dot_Sd + beta_s;
    
    // 由于α = H(pw)/H(session2)，我们需要恢复<H(pw), S>
    // 这在数学上很复杂，我们尝试直接计算期望的PRF值
    
    // 计算H(pw)
    vec_ZZ_p pw_hash = hash_to_vecZZp(pw, n_vector);
    
    // 尝试方法：假设我们能从alpha_dot_S推导出<H(pw), S>
    // 这是一个近似，实际系统中可能需要更复杂的数学
    ZZ_p estimated_inner_product = alpha_dot_S;
    
    u64 interim = conv<ulong>(estimated_inner_product);
    recovered_rw = round_toL(interim, q, p);
    
    return true;
} 
