// server.cpp
// Server-side simulation: strict inverse/consistency + shareSecrettTL binding.
// Requires NTL + GMP + OpenSSL (libcrypto).
// Compile:
// g++ -std=c++17 server.cpp -lntl -lgmp -lcrypto -O2 -o server

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

// ---------------- utilities ----------------
static u64 round_toL(u64 x, u64 q, u64 p){
    __uint128_t num = ( __uint128_t )x * p + (q / 2);
    return (u64)( num / q );
}
static u64 moduloL(u64 x, u64 q){ return x % q; }

static u64 zzp_to_u64(const ZZ_p &z){
    ZZ t = rep(z);
    unsigned long ul = conv<unsigned long>(t); // small-field assumption
    return (u64)ul;
}

static void derive_aes_key_from_u64(u64 v, unsigned char out_key[32]){
    unsigned char buf[8];
    for(int i=0;i<8;i++) buf[i] = (v >> (8*i)) & 0xFF;
    SHA256(buf, 8, out_key);
}

static bool aes_encrypt(const unsigned char *key32, const vector<unsigned char> &plaintext,
                        vector<unsigned char> &ciphertext, vector<unsigned char> &iv_out){
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

static string hex_print(const vector<unsigned char> &v){
    std::ostringstream oss; oss<<hex<<setfill('0');
    for(unsigned char c: v) oss<<setw(2)<<(int)c;
    return oss.str();
}

// ---------------- combinatorics: nCr, rank/unrank ----------------
static map<pair<u64,u64>, u64> ncr_cache;
u64 ncr(u64 n, u64 r){
    if(r > n) return 0;
    if(r==0 || r==n) return 1;
    if(r==1 || r==n-1) return n;
    if(r > n-r) r = n-r;
    auto key = make_pair(n,r);
    auto it = ncr_cache.find(key);
    if(it != ncr_cache.end()) return it->second;
    u64 val = ncr(n-1,r) + ncr(n-1,r-1);
    ncr_cache.emplace(key,val);
    return val;
}

// unrank gid->combination of size t
void findParties(vector<u64>& pt, u64 gid, u64 t, u64 T){
    pt.clear();
    u64 mem = 0;
    for(u64 i=1;i<=T;i++){
        if(mem == t) break;
        if(i == T){ pt.push_back(i); mem++; break; }
        u64 tmp = ncr(T - i, t - mem - 1);
        if(gid > tmp) gid -= tmp;
        else { pt.push_back(i); mem++; }
    }
}

// rank combination -> gid
u64 findGroupId(const vector<u64> &parties, u64 t, u64 T){
    u64 mem = 0; u64 group_count = 1;
    for(u64 i=1;i<=T;i++){
        if(mem == t) break;
        if(find(parties.begin(), parties.end(), i) != parties.end()) mem++;
        else group_count += ncr(T - i, t - mem - 1);
    }
    return group_count;
}

// ---------------- shareSecrettTL (exact) ----------------
// same semantics as user's function: for each group combination, generate t shares (vectors) summing to key
void shareSecrettTL(int t, int T, const vec_ZZ_p &key, int n_vector, map<int, map<int, vec_ZZ_p>> &shared_repo){
    u64 group_count = ncr(T, t);
    vector<u64> parties;
    for(u64 gid=1; gid<=group_count; ++gid){
        findParties(parties, gid, t, T); // parties size t
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
        // party 0 gets key - accum
        vec_ZZ_p s0; s0.SetLength(n_vector);
        for(int k=0;k<n_vector;k++) s0[k] = key[k] - accum[k];
        int p0 = (int)parties[0];
        shared_repo[p0][(int)gid] = s0;
    }
}

// ---------------- PRF helpers ----------------
u64 direct_PRF_eval_vec_get_interim(const vec_ZZ_p &x, const vec_ZZ_p &key, int n_vector){
    // returns interim = zzp_to_u64(inner_product), caller can round_toL on it
    ZZ_p dot = ZZ_p(0);
    for(int i=0;i<n_vector;i++) dot += x[i] * key[i];
    u64 interim = zzp_to_u64(dot);
    return interim;
}

u64 direct_PRF_eval_vec_round(const vec_ZZ_p &x, const vec_ZZ_p &key, int n_vector, u64 q, u64 p){
    u64 interim = direct_PRF_eval_vec_get_interim(x, key, n_vector);
    return round_toL(interim, q, p);
}

u64 partial_PRF_eval_vec_round(const vec_ZZ_p &x, const vec_ZZ_p &share, int n_vector, u64 q, u64 q1, u64 p){
    ZZ_p dot = ZZ_p(0);
    for(int i=0;i<n_vector;i++) dot += x[i] * share[i];
    u64 tmp2 = zzp_to_u64(dot);
    u64 tmp3 = round_toL(tmp2, q, q1);
    return tmp3;
}

// hash string -> vector field element
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

// ---------------- main: server flow ----------------
int main(){
    // init small field modulus (must match User's)
    const long q_mod = 2147483647;
    ZZ qzz = ZZ(q_mod); ZZ_p::init(qzz);

    cout<<"=== Server: strict simulation with shareSecrettTL binding ===\n";

    // inputs: must match User's choices when running User program
    int n_vector;
    cout<<"Enter PRF vector length n: "; cin>>n_vector;
    int n_devices;
    cout<<"Enter number of devices (n_devices): "; cin>>n_devices;
    int t;
    cout<<"Enter threshold t (2 <= t <= n_devices+1): "; cin>>t;
    if(t < 2 || t > n_devices+1){ cerr<<"invalid t\n"; return 1; }
    int T;
    cout<<"Enter total parties T (including devices and server): "; cin>>T;
    if(T < 2){ cerr<<"invalid T\n"; return 1; }
    string dummy; getline(cin,dummy); // consume newline

    // ---------------- Registration ----------------
    cout<<"\n--- Registration phase (server) ---\n";
    // In real protocol, Server receives Ss from User.
    // For simulation and for binding consistency, we will simulate the whole S, Sd, Ss on server side to match User.
    // Generate S (full key), Sd (device part), Ss = S - Sd
    vec_ZZ_p S; S.SetLength(n_vector);
    for(int i=0;i<n_vector;i++) S[i] = random_ZZ_p();
    vec_ZZ_p Sd; Sd.SetLength(n_vector);
    vec_ZZ_p Ss; Ss.SetLength(n_vector);
    for(int i=0;i<n_vector;i++){
        Sd[i] = random_ZZ_p();
        Ss[i] = S[i] - Sd[i];
    }
    cout<<"[Registration] Generated S, Sd, Ss (server-side simulation).\n";

    // Use shareSecrettTL to distribute Sd among T parties and store in shared_repo
    map<int, map<int, vec_ZZ_p>> shared_repo; // party -> (group_id -> share vector)
    shareSecrettTL(t, T, Sd, n_vector, shared_repo);
    // store server's Ss into shared_repo[T][gid] for all group_ids (so server behaves like earlier user code)
    u64 group_count = ncr(T, t);
    for(u64 gid=1; gid<=group_count; ++gid) shared_repo[T][(int)gid] = Ss;

    cout<<"[Registration] shareSecrettTL distribution completed. C(T,t) = "<<group_count<<" groups.\n";

    // For server to have something to verify later, we simulate a stored ciphertext encrypted under rw_server.
    // Choose a simulated pw_server and compute x_server, compute exact interim and rw_server and store ciphertext.
    string pw_server = "server_store_pw";
    vec_ZZ_p x_server = hash_to_vecZZp(pw_server, n_vector);
    // compute interim_server (exact pre-round integer)
    u64 interim_server = direct_PRF_eval_vec_get_interim(x_server, S, n_vector);
    u64 rw_server = round_toL(interim_server, q_mod, 2);
    cout<<"[Registration] rw_server (rounded) = "<<rw_server<<", interim_server = "<<interim_server<<"\n";
    // derive AES key from rw_server
    unsigned char aeskey_reg[32]; derive_aes_key_from_u64(rw_server, aeskey_reg);
    vector<unsigned char> plain_reg((unsigned char*)"hello", (unsigned char*)"hello"+5);
    vector<unsigned char> ciphertext_reg, iv_reg;
    if(!aes_encrypt(aeskey_reg, plain_reg, ciphertext_reg, iv_reg)){ cerr<<"AES encrypt failed\n"; return 1; }
    cout<<"[Registration] Stored ciphertext (hex): "<<hex_print(ciphertext_reg)<<"\n";

    // ---------------- Verification ----------------
    cout<<" \n--- Verification phase (server) ---\n";
    // 1) Server receives alpha from User; simulate or accept input
    cout<<"Enter alpha? (enter 'r' to simulate random, otherwise paste alpha number): ";
    string alpha_in; getline(cin, alpha_in);
    ZZ_p alpha;
    if(alpha_in.empty() || alpha_in == "r"){
        alpha = random_ZZ_p();
        cout<<"[Verification] Simulated alpha = "<<rep(alpha)<<"\n";
    } else {
        ZZ tmp; std::istringstream iss(alpha_in); iss >> tmp;
        alpha = conv<ZZ_p>(tmp);
    }

    // 2) Server computes beta_s = partial_PRF(x' , Ss) and will (in real protocol) send it to user
    // x' = x_user * alpha. For simulation, assume user used x_server as input x (so we'd multiply x_server by alpha)
    vec_ZZ_p xprime; xprime.SetLength(n_vector);
    for(int i=0;i<n_vector;i++) xprime[i] = x_server[i] * alpha;
    u64 beta_s = partial_PRF_eval_vec_round(xprime, Ss, n_vector, q_mod, q_mod, 2);
    cout<<"[Verification] Server computed beta_s = "<<beta_s<<"\n";
    cout<<"(In real protocol this would be sent to User.)\n";

    // 3) Server receives device betas from user-chosen devices. We'll ask which devices were chosen (t-1 numbers).
    cout<<"Enter the "<<(t-1)<<" chosen device indices (1.."<<n_devices<<") separated by spaces: ";
    vector<int> chosen;
    for(int i=0;i<t-1;i++){ int d; cin>>d; if(d<1 || d>n_devices){ cerr<<"Invalid device index\n"; return 1;} chosen.push_back(d); }
    // form group_parties = chosen + server (T)
    vector<u64> group_parties;
    for(int v: chosen) group_parties.push_back((u64)v);
    if(find(group_parties.begin(), group_parties.end(), (u64)T) == group_parties.end()) group_parties.push_back((u64)T);
    if(group_parties.size() != (size_t)t){ cerr<<"selected parties count != t after adding server\n"; return 1; }
    // compute group_id
    u64 group_id = findGroupId(group_parties, t, T);
    cout<<"[Verification] Using group_id="<<group_id<<" for parties: "; for(auto v:group_parties) cout<<v<<" "; cout<<"\n";

    // 3 cont.) Now, device betas should be computed from the shares that were distributed by shareSecrettTL for that group_id.
    vector<u64> device_betas;
    for(int idx=0; idx<(int)chosen.size(); ++idx){
        int dev = chosen[idx];
        if(shared_repo.find(dev) == shared_repo.end() || shared_repo[dev].find((int)group_id) == shared_repo[dev].end()){
            cerr<<"[Error] device "<<dev<<" has no share for group "<<group_id<<"\n"; return 1;
        }
        vec_ZZ_p share = shared_repo[dev][(int)group_id];
        u64 beta_i = partial_PRF_eval_vec_round(xprime, share, n_vector, q_mod, q_mod, 2);
        device_betas.push_back(beta_i);
        cout<<"[Verification] (simulated) Device "<<dev<<" beta = "<<beta_i<<"\n";
    }

    // 4) Use beta_s and device_betas to reconstruct interim sum EXACTLY equal to interim_server
    // Compute per-share tmp2 (pre-round) and sum them
    vector<u64> device_tmp2;
    u64 sum_tmp2 = 0;
    for(int idx=0; idx<(int)chosen.size(); ++idx){
        int dev = chosen[idx];
        vec_ZZ_p share = shared_repo[dev][(int)group_id];
        ZZ_p dot = ZZ_p(0);
        for(int j=0;j<n_vector;j++) dot += xprime[j] * share[j];
        u64 tmp2 = zzp_to_u64(dot);
        device_tmp2.push_back(tmp2);
        sum_tmp2 = (sum_tmp2 + tmp2);
    }
    // server tmp2 for Ss:
    ZZ_p dot_s = ZZ_p(0);
    for(int j=0;j<n_vector;j++) dot_s += xprime[j] * Ss[j];
    u64 tmp2_server = zzp_to_u64(dot_s);
    cout<<"[Verification] Sum device tmp2 = "<<sum_tmp2<<", server tmp2 = "<<tmp2_server<<"\n";

    u64 reconstructed_interim_exact = sum_tmp2 + tmp2_server;
    cout<<"[Verification] reconstructed_interim_exact = "<<reconstructed_interim_exact<<"\n";
    cout<<"[Verification] interim_server (original) = "<<interim_server<<"\n";

    if(reconstructed_interim_exact == interim_server){
        cout<<"[Verification] exact interim matches registration interim.\n";
    } else {
        cout<<"[Warning] interim mismatch! This indicates inconsistency between shares/S or rounding domain.\n";
        cout<<"Proceeding to round and attempt to recover rw' anyway.\n";
    }

    // 5) Finally compute rw' by applying round_toL to reconstructed_interim_exact
    u64 rw_reconstructed = round_toL(reconstructed_interim_exact, q_mod, 2);
    cout<<"[Verification] rw_reconstructed = "<<rw_reconstructed<<" (registered rw_server = "<<rw_server<<")\n";

    // 6) Use rw_reconstructed to decrypt stored ciphertext and check
    unsigned char aeskey_chk[32]; derive_aes_key_from_u64(rw_reconstructed, aeskey_chk);
    vector<unsigned char> plain_dec;
    bool ok = aes_decrypt(aeskey_chk, ciphertext_reg, iv_reg, plain_dec);
    if(!ok){
        cout<<"[Verification] AES decrypt failed (wrong key?) - verification fails.\n";
    } else {
        string s((char*)plain_dec.data(), plain_dec.size());
        cout<<"[Verification] decrypted plaintext = '"<<s<<"'\n";
        if(s == "hello") cout<<"[Verification] success! plaintext matches.\n";
        else cout<<"[Verification] mismatch.\n";
    }

    // ---------------- Key agreement (example) ----------------
    cout<<"\n--- Key Agreement demo (server) ---\n";
    cout<<"(Skipping detailed KEX; server can derive shared key based on b2*s1 as in your design)\n";

    // ---------------- Key update / post-update initialization ----------------
    cout<<"\n--- Key Update & Post-Update Initialization (server) ---\n";
    string session1 = "session1_example"; string session2;
    { ZZ_p r = random_ZZ_p(); ostringstream oss; oss << rep(r); session2 = oss.str(); }
    cout<<"session1='"<<session1<<"' session2='"<<session2<<"'\n";

    cout<<"Enter number of revoked devices: "; int rcount; cin>>rcount;
    cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); 
    vector<int> revoked;
    for(int i=0;i<rcount;i++){ int d; cin>>d; revoked.push_back(d); }

    std::set<int> revoked_set(revoked.begin(), revoked.end());
    cout<<"Sending session updates (simulated):\n";
    for(int d=1; d<=n_devices; ++d){
        if(revoked_set.count(d)) cout<<"  Device "<<d<<" <- session1\n"; else cout<<"  Device "<<d<<" <- session2\n";
    }

    // Convert session1 -> field element
    unsigned char s1digest[SHA256_DIGEST_LENGTH]; SHA256((unsigned char*)session1.data(), session1.size(), s1digest);
    uint64_t s1val = 0; for(int b=0;b<8;b++) s1val |= ((uint64_t)s1digest[b]) << (8*b);
    ZZ_p s1_elem = conv<ZZ_p>(ZZ((unsigned long)s1val));

    // Simulate receiving sdi' from active (non-revoked) devices: their share for group_id scaled by session1
    vector<vec_ZZ_p> received_sdi_prime;
    for(int d=1; d<=n_devices; ++d){
        if(revoked_set.count(d)) continue;
        if(shared_repo[d].find((int)group_id) == shared_repo[d].end()){
            cerr<<"[PostUpdate] device "<<d<<" has no share for group "<<group_id<<"\n"; continue;
        }
        vec_ZZ_p sdi = shared_repo[d][(int)group_id];
        vec_ZZ_p sdi_prime; sdi_prime.SetLength(n_vector);
        for(int k=0;k<n_vector;k++) sdi_prime[k] = sdi[k] * s1_elem; // scale by session1 element
        received_sdi_prime.push_back(sdi_prime);
        cout<<"[PostUpdate] simulated received sdi' from device "<<d<<"\n";
    }

    // Reconstruct Sd * session1 by summing received scaled shares
    vec_ZZ_p Sd_times_s1; Sd_times_s1.SetLength(n_vector);
    for(int k=0;k<n_vector;k++) Sd_times_s1[k] = ZZ_p(0);
    for(auto &v : received_sdi_prime) for(int k=0;k<n_vector;k++) Sd_times_s1[k] += v[k];
    cout<<"[PostUpdate] Reconstructed Sd * session1 (simulated).\n";

    // Compute Ss * session1 and S * session1
    vec_ZZ_p Ss_times_s1; Ss_times_s1.SetLength(n_vector);
    for(int k=0;k<n_vector;k++) Ss_times_s1[k] = Ss[k] * s1_elem;
    vec_ZZ_p S_times_s1; S_times_s1.SetLength(n_vector);
    for(int k=0;k<n_vector;k++) S_times_s1[k] = Sd_times_s1[k] + Ss_times_s1[k];
    cout<<"[PostUpdate] Computed S * session1.\n";

    // New pw input
    string pw_after;
    getline(cin, dummy); // flush
    cout<<"Enter user's pw after update (or leave empty to use simulated): "; getline(cin, pw_after);
    if(pw_after.empty()) { pw_after = "user_pw_after_update"; cout<<"Using simulated pw: "<<pw_after<<"\n"; }
    vec_ZZ_p x_after = hash_to_vecZZp(pw_after, n_vector);
    u64 interim_new = direct_PRF_eval_vec_get_interim(x_after, S_times_s1, n_vector);
    u64 rw_new = round_toL(interim_new, q_mod, 2);
    cout<<"[PostUpdate] new rw = "<<rw_new<<"\n";
    unsigned char aeskey_new[32]; derive_aes_key_from_u64(rw_new, aeskey_new);
    vector<unsigned char> pnew((unsigned char*)"hello", (unsigned char*)"hello"+5), cipher_new, iv_new;
    if(!aes_encrypt(aeskey_new, pnew, cipher_new, iv_new)){ cerr<<"Encrypt new failed\n"; return 1; }
    cout<<"[PostUpdate] stored new ciphertext (hex) = "<<hex_print(cipher_new)<<"\n";

    cout<<"\n=== Server simulation complete ===\n";
    return 0;
}
