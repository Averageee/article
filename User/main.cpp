// threshold_prf_full_final.cpp
// Full implementation (no simplification) using shareSecrettTL-style secret distribution.
// Requires: NTL + GMP + OpenSSL
// Compile example:
// g++ -std=c++17 threshold_prf_full_final.cpp -lntl -lgmp -lcrypto -O2 -o threshold_prf_full_final

#include <bits/stdc++.h>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;
using namespace NTL;
using u64 = uint64_t;

// ---------- Utilities ----------
static u64 round_toL(u64 x, u64 q, u64 p){
    __uint128_t num = ( __uint128_t )x * p + (q / 2);
    return (u64)( num / q );
}
static u64 moduloL(u64 x, u64 q){ return x % q; }

static u64 zzp_to_u64(const ZZ_p &z){
    ZZ t = rep(z);
    unsigned long ul = conv<unsigned long>(t); // caution: relies on t fitting unsigned long
    return (u64)ul;
}

// SHA-256 of a u64 -> 32 bytes key
static void derive_aes_key_from_u64(u64 v, unsigned char out_key[32]){
    unsigned char buf[8];
    for(int i=0;i<8;i++) buf[i] = (v >> (8*i)) & 0xFF;
    SHA256(buf, 8, out_key);
}

// AES-256-CBC using OpenSSL EVP (PKCS7 padding)
static bool aes_encrypt(const unsigned char *key32, const vector<unsigned char> &plaintext,
                        vector<unsigned char> &ciphertext, vector<unsigned char> &iv_out){
    iv_out.assign(16, 0);
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

static bool aes_decrypt(const unsigned char *key32, const vector<unsigned char> &ciphertext,
                        const vector<unsigned char> &iv, vector<unsigned char> &plaintext){
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

// ---------- Combinatorics (nCr, ranking/unranking) ----------
static map<pair<u64,u64>, u64> ncr_cache;
u64 ncr(u64 n, u64 r){
    if(r > n) return 0;
    if(r == 0 || r == n) return 1;
    if(r == 1 || r == n-1) return n;
    if(r > n-r) r = n-r;
    auto key = make_pair(n,r);
    auto it = ncr_cache.find(key);
    if(it != ncr_cache.end()) return it->second;
    u64 val = ncr(n-1, r) + ncr(n-1, r-1);
    ncr_cache.emplace(key, val);
    return val;
}

// Unrank gid -> list of parties (1-indexed) (size t), parties in ascending order
void findParties(vector<u64>& pt, u64 gid, u64 t, u64 T){
    pt.clear();
    u64 mem = 0;
    for(u64 i = 1; i <= T; ++i){
        if(mem == t) break;
        if(i == T){
            pt.push_back(i); mem++; break;
        }
        u64 tmp = ncr(T - i, t - mem - 1);
        if(gid > tmp) gid -= tmp;
        else { pt.push_back(i); mem++; }
    }
}

// Rank (ascending) parties vector to group_id (1-indexed)
u64 findGroupId(const vector<u64> &parties, u64 t, u64 T){
    u64 mem = 0;
    u64 group_count = 1;
    for(u64 i = 1; i <= T; ++i){
        if(mem == t) break;
        if(find(parties.begin(), parties.end(), i) != parties.end()){
            mem += 1;
        } else {
            group_count += ncr(T - i, t - mem - 1);
        }
    }
    return group_count;
}

// ---------- shareSecrettTL (exact-style, per your original design) ----------
// shared_key_repo_tT[party_index][group_id] = vec_ZZ_p share (length n_vector)
// For each t-combination (group id from 1..C(T,t)) generate random vector shares for parties[1..t-1],
// set parties[0] share = key - sum(other_shares).
void shareSecrettTL(int t, int T, const vec_ZZ_p &key, int n_vector, map<int, map<int, vec_ZZ_p>> &shared_repo){
    u64 group_count = ncr(T, t);
    vector<u64> parties;
    for(u64 gid = 1; gid <= group_count; ++gid){
        findParties(parties, gid, t, T); // parties (size t)
        // accum = 0
        vec_ZZ_p accum; accum.SetLength(n_vector);
        for(int k=0;k<n_vector;k++) accum[k] = ZZ_p(0);
        // generate random shares for parties[1..t-1]
        for(int j=1;j<(int)parties.size(); ++j){
            vec_ZZ_p tmp; tmp.SetLength(n_vector);
            for(int k=0;k<n_vector;k++) tmp[k] = random_ZZ_p();
            int pid = (int)parties[j];
            shared_repo[pid][(int)gid] = tmp;
            for(int k=0;k<n_vector;k++) accum[k] += tmp[k];
        }
        // parties[0] gets key - accum
        vec_ZZ_p s0; s0.SetLength(n_vector);
        for(int k=0;k<n_vector;k++) s0[k] = key[k] - accum[k];
        int p0 = (int)parties[0];
        shared_repo[p0][(int)gid] = s0;
    }
}

// ---------- PRF functions (vector inner product) ----------
u64 direct_PRF_eval_vec(const vec_ZZ_p &x, const vec_ZZ_p &key, int n_vector, u64 q, u64 p){
    ZZ_p dot = ZZ_p(0);
    for(int i=0;i<n_vector;i++) dot += x[i] * key[i];
    u64 interim = zzp_to_u64(dot);
    return round_toL(interim, q, p);
}

// Partial PRF evaluation from single share vector
u64 partial_PRF_eval_vec(const vec_ZZ_p &x, const vec_ZZ_p &share, int n_vector, u64 q, u64 q1, u64 p){
    ZZ_p dot = ZZ_p(0);
    for(int i=0;i<n_vector;i++) dot += x[i] * share[i];
    u64 tmp2 = zzp_to_u64(dot);
    u64 tmp3 = round_toL(tmp2, q, q1);
    return tmp3;
}

// threshold PRF eval: given group_id (we will combine t parties' shares stored in shared_repo)
u64 threshold_PRF_eval_vec(const vec_ZZ_p &x, int n_vector, u64 group_id, int t, int T, u64 q, u64 q1, u64 p, map<int,map<int,vec_ZZ_p>> &shared_repo){
    vector<u64> parties; findParties(parties, group_id, t, T);
    u64 interim = 0;
    for(int i=0;i<t;i++){
        int pid = (int)parties[i];
        vec_ZZ_p cur = shared_repo[pid][(int)group_id];
        ZZ_p dot = ZZ_p(0);
        for(int j=0;j<n_vector;j++) dot += x[j] * cur[j];
        u64 tmp2 = zzp_to_u64(dot);
        u64 tmp3 = round_toL(tmp2, q, q1);
        if(i==0) interim = (interim + tmp3) % q1;
        else interim = ((interim + q1 - (tmp3 % q1)) % q1);
    }
    u64 res = round_toL(interim, q1, p);
    return res;
}

// ---------- hash pw/session -> vec_ZZ_p ----------
vec_ZZ_p hash_to_vecZZp(const string &s, int n_vector){
    vec_ZZ_p out; out.SetLength(n_vector);
    for(int i=0;i<n_vector;i++){
        string in = s + ":" + to_string(i);
        unsigned char digest[SHA256_DIGEST_LENGTH]; SHA256((unsigned char*)in.data(), in.size(), digest);
        uint64_t v = 0; for(int b=0;b<8;b++) v |= ((uint64_t)digest[b]) << (8*b);
        out[i] = conv<ZZ_p>(ZZ((unsigned long)v));
    }
    return out;
}

// ---------- Small helpers ----------
string hex_print(const vector<unsigned char> &v){
    std::ostringstream oss;
    oss<<hex<<setfill('0');
    for(unsigned char c: v) oss<<setw(2)<<(int)c;
    return oss.str();
}

// ---------- main: interactive flow ----------
int main(){
    // initialize field modulus q
    const long q_mod = 2147483647; // fits in unsigned long
    ZZ qzz = ZZ(q_mod); ZZ_p::init(qzz);

    cout<<"=== Full interactive Threshold-PRF protocol (shareSecrettTL style) ===\n";

    // Inputs
    int n_vector;
    cout<<"Enter PRF vector length n (e.g. 4): "; cin>>n_vector;
    int n_devices;
    cout<<"Enter number of devices (n_devices): "; cin>>n_devices;
    int t;
    cout<<"Enter threshold t (2 <= t <= n_devices+1): "; cin>>t;
    if(t < 2 || t > n_devices + 1){ cerr<<"Invalid t\n"; return 1; }
    int T;
    cout<<"Enter total parties T (including devices and server). Usually T = n_devices + 1: "; cin>>T;
    if(T < 2){ cerr<<"Invalid T\n"; return 1; }

    string dummy; getline(cin,dummy); // consume newline
    string pw;
    cout<<"Enter user password pw: "; getline(cin, pw);
    if(pw.empty()){ cerr<<"Empty pw\n"; return 1; }

    // 1) Secret generation and (2,2) splitting
    vec_ZZ_p S; S.SetLength(n_vector);
    for(int i=0;i<n_vector;i++) S[i] = random_ZZ_p();
    cout<<"[+] Secret S generated.\n";

    // (2,2) split: choose Sd random, Ss = S - Sd
    vec_ZZ_p Sd; Sd.SetLength(n_vector);
    vec_ZZ_p Ss; Ss.SetLength(n_vector);
    for(int i=0;i<n_vector;i++){ Sd[i] = random_ZZ_p(); Ss[i] = S[i] - Sd[i]; }
    cout<<"[+] (2,2) split done: Sd (for device-distribution) and Ss (server share).\n";

    // 2) Use shareSecrettTL to distribute Sd among T parties
    map<int, map<int, vec_ZZ_p>> shared_repo; // party_index -> (group_id -> vec_ZZ_p)
    shareSecrettTL(t, T, Sd, n_vector, shared_repo);
    // store server's Ss in shared_repo[T][gid] for all group_ids
    u64 group_count = ncr(T, t);
    for(u64 gid = 1; gid <= group_count; ++gid){
        shared_repo[T][(int)gid] = Ss;
    }
    cout<<"[+] shareSecrettTL distributed Sd; server shares stored in shared_repo[T][gid].\n";
    cout<<"    Total groups C(T,t) = "<<group_count<<"\n";

    // 3) Map pw -> x (vec_ZZ_p)
    vec_ZZ_p x = hash_to_vecZZp(pw, n_vector);
    cout<<"[+] pw hashed to x-vector.\n";

    // 4) direct PRF evaluation with full S (just for encryption)
    u64 q = (u64)q_mod; u64 q1 = q; u64 p = 2;
    u64 rw = direct_PRF_eval_vec(x, S, n_vector, q, p);
    cout<<"[+] direct PRF rw = "<<rw<<"\n";

    // 5) AES encrypt "Hello" using rw-derived key (SHA-256)
    unsigned char aeskey[32]; derive_aes_key_from_u64(rw, aeskey);
    vector<unsigned char> plaintext((unsigned char*)"Hello", (unsigned char*)"Hello"+5);
    vector<unsigned char> ciphertext, iv;
    if(!aes_encrypt(aeskey, plaintext, ciphertext, iv)){ cerr<<"AES encrypt failed\n"; return 1; }
    cout<<"[+] Ciphertext (hex): "<<hex_print(ciphertext)<<"\n";

    // 6) Verification phase: get session2 (or auto-gen)
    string session2;
    cout<<"Enter session2 (leave empty to auto-generate): "; getline(cin, session2);
    if(session2.empty()){
        ZZ_p rand_s = random_ZZ_p(); 
        ZZ zz_s = rep(rand_s);
        std::ostringstream oss;
        oss << zz_s;
        std::string session2 = oss.str();
        cout<<"Auto-generated session2: "<<session2<<"\n";
    }
    // compute alpha = H(pw) / session2 in ZZ_p
    unsigned char hbuf[SHA256_DIGEST_LENGTH]; SHA256((unsigned char*)pw.data(), pw.size(), hbuf);
    uint64_t hval = 0; for(int i=0;i<8;i++) hval |= ((uint64_t)hbuf[i]) << (8*i);
    ZZ_p Hpw = conv<ZZ_p>(ZZ((unsigned long)hval));
    unsigned char s2buf[SHA256_DIGEST_LENGTH]; SHA256((unsigned char*)session2.data(), session2.size(), s2buf);
    uint64_t s2val = 0; for(int i=0;i<8;i++) s2val |= ((uint64_t)s2buf[i]) << (8*i);
    ZZ_p session2_elem = conv<ZZ_p>(ZZ((unsigned long)s2val));
    ZZ_p alpha = Hpw * inv(session2_elem);
    cout<<"[+] alpha computed.\n";

    // 7) Let user select devices (t-1 devices)
    int need = t - 1;
    cout<<"Choose "<<need<<" device indices among 1.."<<n_devices<<" (space-separated): ";
    vector<u64> chosen_devices;
    for(int i=0;i<need;i++){ u64 idx; cin>>idx; if(idx < 1 || idx > (u64)n_devices){ cerr<<"Invalid device index\n"; return 1; } chosen_devices.push_back(idx); }
    // We will include server index if not already in chosen set; server index is T if user wants to include server, but protocol expects server also provides partial
    // Build party list of size t by adding server index T
    vector<u64> group_parties = chosen_devices;
    // add server (if not present) to form t parties; if user accidentally selected server index, that's OK
    bool server_present = (find(group_parties.begin(), group_parties.end(), (u64)T) != group_parties.end());
    if(!server_present) group_parties.push_back((u64)T);
    if(group_parties.size() != (size_t)t){ cerr<<"Selected parties count != t after adding server\n"; return 1; }

    // compute group_id from chosen parties
    u64 group_id = findGroupId(group_parties, t, T);
    cout<<"[+] Using group_id = "<<group_id<<" for parties: ";
    for(u64 v: group_parties) cout<<v<<" "; cout<<"\n";

    // 8) Devices and server compute partial PRFs with their shares: input x' = x * alpha (elementwise)
    vec_ZZ_p xprime; xprime.SetLength(n_vector);
    for(int i=0;i<n_vector;i++) xprime[i] = x[i] * alpha;

    vector<u64> betas;
    for(int i=0;i<t;i++){
        int pid = (int)group_parties[i];
        if(shared_repo.find(pid) == shared_repo.end() || shared_repo[pid].find((int)group_id) == shared_repo[pid].end()){
            cerr<<"Missing share for party "<<pid<<" in group "<<group_id<<"\n"; return 1;
        }
        vec_ZZ_p share = shared_repo[pid][(int)group_id];
        u64 beta = partial_PRF_eval_vec(xprime, share, n_vector, q, q1, p);
        betas.push_back(beta);
        cout<<"  party "<<pid<<" -> beta = "<<beta<<"\n";
    }
    // For clarity, we also compute server's beta (should be included above if server is in group_parties)
    // (already computed)


    // 9) Combine partials to reconstruct overall PRF (rw')
    // Correct: sum ALL partials (devices' betas + server beta), then round.
    u64 interim = 0;
    for(size_t i = 0; i < betas.size(); ++i){
        interim = (interim + (betas[i] % q1)) % q1;
    }
    // Note: if server's beta isn't included in betas (it is if server is in group_parties),
    // make sure to add it. In our code server was included in group_parties, so this sums all.
    u64 rw_prime = round_toL(interim, q1, p);
    cout << "[+] Reconstructed rw' = " << rw_prime << "\n";


    // 10) Use rw' to decrypt and verify ciphertext
    unsigned char aeskey2[32]; derive_aes_key_from_u64(rw_prime, aeskey2);
    vector<unsigned char> plain2;
    if(!aes_decrypt(aeskey2, ciphertext, iv, plain2)){
        cerr<<"AES decrypt failed (wrong key?)\n"; // verification fails
        return 1;
    }
    string decstr((char*)plain2.data(), plain2.size());
    cout<<"[+] Decrypted plaintext: "<<decstr<<"\n";
    if(decstr == "Hello") cout<<"[+] Verification succeeded: recovered plaintext matches.\n";
    else cout<<"[!] Verification failed: plaintext mismatch.\n";

    // 11) Key agreement phase - example using X25519 (OpenSSL EVP)
    cout<<"[+] Performing example ephemeral X25519 ECDH (OpenSSL EVP) for KEX...\n";
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
    EVP_PKEY *user_key = NULL, *server_key = NULL;
    if(!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &user_key) <= 0 || EVP_PKEY_keygen(pctx, &server_key) <= 0){
        cerr<<"ECDH keygen failed (OpenSSL)\n";
        if(pctx) EVP_PKEY_CTX_free(pctx);
    } else {
        EVP_PKEY_CTX *ctxu = EVP_PKEY_CTX_new(user_key, NULL);
        EVP_PKEY_derive_init(ctxu); EVP_PKEY_derive_set_peer(ctxu, server_key);
        size_t secret_len; EVP_PKEY_derive(ctxu, NULL, &secret_len);
        vector<unsigned char> secret_user(secret_len); EVP_PKEY_derive(ctxu, secret_user.data(), &secret_len);

        EVP_PKEY_CTX *ctxs = EVP_PKEY_CTX_new(server_key, NULL);
        EVP_PKEY_derive_init(ctxs); EVP_PKEY_derive_set_peer(ctxs, user_key);
        size_t secret_len2; EVP_PKEY_derive(ctxs, NULL, &secret_len2);
        vector<unsigned char> secret_srv(secret_len2); EVP_PKEY_derive(ctxs, secret_srv.data(), &secret_len2);

        bool same = (secret_len == secret_len2) && (memcmp(secret_user.data(), secret_srv.data(), secret_len) == 0);
        cout<<"[+] X25519 derived secrets equal? "<<(same? "yes":"no")<<"\n";

        EVP_PKEY_free(user_key); EVP_PKEY_free(server_key);
        EVP_PKEY_CTX_free(ctxu); EVP_PKEY_CTX_free(ctxs);
        EVP_PKEY_CTX_free(pctx);
    }

    cout<<"=== Protocol run complete ===\n";
    return 0;
}
