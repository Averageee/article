#include <functional>
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

typedef std::uint64_t u64;


std::map<std::pair<int, int>, int> ncr_cache;

/* 求[x]p的值. 计算方式为 (x*p/q) */
u64 round_toL(u64 x, u64 q, u64 p){
	x >>= (int)(log2(q) - log2(p) - 1);
	int flag = (x & 1) ? 1 : 0;
	x >>= 1;
	return (x + flag);
}

/* 求 x mod q的值 */
u64 moduloL(u64 x, u64 q){
	if(x >= 0){
		return x%q;
	}
	else{
		x = (-x)%q;
		return (x ? (q-x) : x);
	}
}

/* 求nCr的值，也就是n个里面取r个数的结果，返回结果值 */
u64 ncr(u64 n, u64 r){
    if (ncr_cache.find({n, r}) == ncr_cache.end()){
        if (r > n || n < 0 || r < 0)
            return 0;
        else{
            if (r == 0 || r == n){
                ncr_cache[{n, r}] = 1;
            }
            else if (r == 1 || r == n - 1){
                ncr_cache[{n, r}] = n;
            }
            else{
                ncr_cache[{n, r}] = ncr(n - 1, r) + ncr(n - 1, r - 1);
            }
        }
    }

    return ncr_cache[{n, r}];
}

/* 输入一个组编号 gid，输入(t,T)，结果存储在向量 pt 中。

调用 findParties(pt, 4, 3, 5)：
将第 4 种组合的 {1,3,4} 存储到 pt 当中 */
void findParties(std::vector<u64>& pt, u64 gid, u64 t, u64 T){
	u64 mem = 0, tmp;
	pt.clear();
	for(u64 i = 1; i < T; i++){
		tmp = ncr(T - i, t - mem -1);
		if(gid > tmp){
			gid -= tmp;
		}
		else{
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

/* 给定一个大小为 t 的参与方（party）组合 parties，计算它在所有可能的 C(T, t) 个组合中的字典序排名（即第几小的组合）。 

调用 findGroupId({1,3,4}, 3, 5)：
返回 4（因为 {1,3,4} 是第 4 个组合） */
u64 findGroupId(std::vector<u64> parties, u64 t, u64 T){
	u64 mem = 0;
	u64 group_count = 1;
	for(u64 i = 1; i <= T; i++){
		if(std::find(parties.begin(), parties.end(), i) != parties.end()){
			mem += 1;
		}
		else{
			group_count += ncr(T - i, t - mem - 1);
		}
		if(mem == t){
			break;
		}
	}
	return group_count;
}


/* This function performs (t,T)-threshold secret sharing among T parties on a key in Z_q^n. It includes calculation of distribution
matrix, rho matrix, multiplication of distribution matrix and rho matrix theoretically. But for better space utilization, 
we generate partial rho matrix of smaller size for each t-sized subset, and generate shares corresponding to parties in such subset 
one after another. We then distribute the shares among T parties, such that each of the parties gets (T-1)C(t-1) shares to store 
对 Z_q^n 中的密钥执行 (t,T) 门限秘密共享
将生成的份额分发给所有 T 个参与方，使得每个参与方最终存储 (T-1)C(t-1) 个份额。*/
void shareSecrettTL(int t, int T, NTL::vec_ZZ_p key, int n, std::map<int, std::map<int, NTL::vec_ZZ_p>> &shared_key_repo_tT){
	u64 group_count = ncr(T,t);
	std::vector<u64> parties;
	using namespace NTL;
	for(u64 gid = 1; gid <= group_count; gid++){
		findParties(parties, gid, t, T);
		VectorCopy(shared_key_repo_tT[parties[0]][gid], key, n);
		for(int i = 1; i < t; i++){
			random(shared_key_repo_tT[parties[i]][gid], n);
			shared_key_repo_tT[parties[0]][gid] += shared_key_repo_tT[parties[i]][gid];
		}
	}
	//for(int i = 0; i < n; i++){
	//	std::cout << shared_key_repo_tT[1][1][i] << " ";
	//}
	//std::cout << "\n";
}

/* 直接使用完整密钥k计算的整体PRF的值res */
u64 direct_PRF_eval(NTL::vec_ZZ_p x, NTL::vec_ZZ_p key, u64 n, u64 q, u64 p){
	NTL::ZZ_p eval;
	u64 res;
	NTL::InnerProduct(eval, x, key);
	u64 interim = NTL::conv<ulong>(eval);
	res = round_toL(interim, q, p);
	return res;
}

/* 输入密码 x，计算使用部分PRF值进行计算得到的整体PRF的值res */
u64 threshold_PRF_eval(NTL::vec_ZZ_p x, u64 n, u64 group_id, u64 t, u64 T, u64 q, u64 q1, u64 p, std::map<int, std::map<int, NTL::vec_ZZ_p>> &shared_key_repo_tT){
	std::vector<u64> parties;
	findParties(parties, group_id, t, T);

	NTL::ZZ_p tmp1;
	u64 tmp2, tmp3;
	u64 interim;

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
		}
		else{
			interim -= tmp3;
			interim = moduloL(interim, q1);
		}
	}
	res = round_toL(interim, q1, p);
	return res;
}

int main(){
	u64 p = 1024, q = 4294967296, q1 = 268435456;
	u64 n = 512, t = 5, T = 10;
	std::cout << "[Base 2] log(p): " << log2(p) << ", log(q1): " << log2(q1) << ", log(q): " << log2(q) << "\n";
	std::cout << "Dimension: " << n << ", Threshold no of parties: " << t << ", Total no of parties: " << T << "\n";

	using namespace NTL;

	// Set ZZ_p modulus equal to q
	ZZ_p::init(conv<ZZ>(q));

	vec_ZZ_p x, key;

	/* shared_key_repo_tT stores all t*C(T,t) number of key shares, shared_key_repo_tT[i][j] stores key share of party i corresponding to group j */
	std::map<int, std::map<int, vec_ZZ_p>> shared_key_repo_tT;

	random(key, n);
	// std::cout << "LWR Key:\n";
	// for(int i = 0; i < n; i++){
	// 	std::cout << key[i] << " ";
	// }
	// std::cout << "\n";

	shareSecrettTL(t, T, key, n, shared_key_repo_tT);
	
	/* We will check the correctness of evaluation of threshold PRF for "iter" number of random values of x */ 
	u64 iter = 1000;

	/* group_count is the number of t-sized subsets among T parties */
	u64 group_count = ncr(T,t);

	u64 group_itr;
	int flag;
	std::vector<u64> validset;

	/* threshold_evals is the array containing the evaluated threshold PRF value w.r.t to all possible C(T,t) number of t-sized subset and for a particular value of x */
	// long long int *threshold_evals = (long long int*)malloc(group_count*sizeof(long long int));
	std::vector<u64> threshold_evals;
	threshold_evals.resize(group_count);

	long long int count = 0;
	long long int inconsistency_count = 0;
	long long int direct_eval, distributed_eval, diff, diff2, non_zero_count = 0, non_zero_count2 = 0, diff_bits, max_diff_bits = -1;
	
	while(count < iter){
		/* Choose a random x for each iteration */
		random(x, n);
		
		direct_eval = direct_PRF_eval(x, key, n, q, p);
		
		flag = 0;

		/* Iterate over all C(T,t) number of t-sized subsets and threshold_eval temporarily stores evaluation of threshold PRF w.r.t a specific t-sized subset/group. If the
		evaluated threshold PRF value by at least one t-sized subset differs from the directly evaluated PRF value, we will print the threshold evaluated value of all t-sized subsets. */
		group_itr = 1;
		while(group_itr <= group_count){
			distributed_eval = threshold_PRF_eval(x, n, group_itr, t, T, q, q1, p, shared_key_repo_tT);
			threshold_evals[group_itr-1] = distributed_eval;
			if(distributed_eval != direct_eval){
				flag = 1;
				inconsistency_count++;
			}
			group_itr++;
		}
		// std::cout << "\n";
		if(flag){
			std::cout << "\nDirect eval: " << direct_eval << "\n";
			for(int i = 1; i <= group_count; i++){
				std::cout << threshold_evals[i-1] << " ";
			}
			std::cout << "\n";
		}
		count++;
	}
	std::cout << "inconsistency_count: " << inconsistency_count << "\n";
    std::cout << "total_count: " << iter * group_count << "\n";
	std::cout << "fraction (inconsistency count/total testcases): " << inconsistency_count/(double)(iter * group_count) << "\n";
}


/*    User 需要做的事
一：秘密份额分发
	1. 生成一个随机数--秘密 S
	2. 使用一个(2,2)秘密共享将S分为Sd和 Ss俩个部分
	3. 将 Ss 发给服务器(Server)
	4. 使用 (t-1,n-1) 秘密共享将Sd分成 n-1 个份额
	5. 将这 n-1 个份额发给 n-1 个设备(Device)----如果集齐 t-1 个份额就可以恢复出 Sd

二：PRF计算
	1. 输入一个值作为用户的 pw----作为 PRF 的 输入x
	2. 之前 User 随机生成的秘密 S----作为 PRF 的 key
	3. 计算得到 PRF 的值 rw--原 pw 的高熵升级版
	4. 用 rw 作为对称加密的密钥，对("Hello")加密得到密文 C

三：验证阶段
	1. 用户生成一个随机数----选择参数 session2
	2. 用户决定选择哪几个设备来参与这次认证（可能从外部输入）
	3. 将 session2 发送给选择的 Device，以及服务器 Server
	4. 用户计算一个 α = H(pw)/session_2，然后将这个发给选择的设备和服务器
	5. 设备调用计算部分PRF值的函数，将自己的 Sdi 作为 PRF 的 key，并将计算出来的 β 值发回给 User
	6. 服务器调用计算部分PRF值的函数，将自己的 Ss 作为 PRF 的 key，也将算出来的 β 发回给 User
	7. 使用拥有的部分 PRF 的值，计算得到整体 PRF的值----rw'
	8。 利用 rw' 的值来解密 C，看得到的明文是不是（“Hello”）----如果是，验证阶段完成，进入密钥协商阶段，否则中止

四：密钥协商阶段
	1. 将 rw hash一下得到公钥向量 a
	2. 将选择参数 session2 hash一下的到秘密向量 s2
	3. 计算 b2 = a*s2 + e1
	4. 将 b2 发给server
	5. 接收从 server 发来的 b1
	6. 利用 b1*s2 得到协商的密钥
*/

/ #include <random>
int User_main() {
    // 1. 生成一个Z_q^n类型的随机向量作为密钥
	vec_ZZ_p random_vector_NTL(long n, long q) {
    ZZ_p::init(ZZ(q));  // 初始化模数 q
    vec_ZZ_p v;
    v.SetLength(n);
    for (long i = 0; i < n; i++) {
        v[i] = random_ZZ_p(); // 自动在 [0, q-1] 范围
    }
    return v;
	}
    key_S = random_vector_NTL(n,q);


	//2. 秘密共享
	shareSecrettTL(2, 2, key_S, n, shared_key_repo_tT);
	发送给服务器:shared_key_repo_tT[0][1];

	shareSecrettTL(t-1, T-1, shared_key_repo_tT[1][1], n, shared_key_repo_tT_Sd);-----shared_key_repo_tT_Sd需要单独定义
	发送给设备:shared_key_repo_tT_Sd[i][1];

	//3. User输入一个值作为pw
	vec_ZZ_p pw; // 定义一个变量 pw
    cout << "请输入一个值: ";
    cin >> pw; // 从键盘输入赋值给 pw

	//4. 直接计算PRF的值
	rw = direct_PRF_eval(pw, key_S, n, q, p);

	//5. 利用rw加密hello
	string plaintext = "hello";
	byte iv[12] = {0}; // 可以随机生成，这里为演示使用全0
    string ciphertext, decryptedtext;
    try {
        // 加密
        ChaCha20::Encryption encryptor;
        encryptor.SetKeyWithIV((byte*)key_S.c_str(), key_S.size(), iv, sizeof(iv));

        StringSource ss1(plaintext, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(ciphertext)
            )
        );
		}catch (const Exception& e) {
        cerr << e.what() << endl;
        return 1;
    }
	ciphertext发送给服务器;

	//6. 随机生成选择参数session2
	random_device rd;           // 获取随机种子
    mt19937 gen(rd());          // 梅森旋转算法生成器
    uniform_int_distribution<int> dist(0, 10000); // 生成 [0,10000] 范围整数
    int session2 = dist(gen); // 生成随机数

	//7. 将session2发给被选中的 Device 和 Server

	//8. 用户计算α = H(pw)/session_2
	
	/*#include <iostream>
	#include <string>
	#include <functional> // std::hash*/
	using namespace std;

	hash<string> hasher;      // 创建 hash 对象
    size_t hash_pw = hasher(pw);
	int α = hash_pw/session_2;

	//9. 将计算结果发给被选中的 Device 和 Server

	//10. 收到被选中的 Device 和 Server发来的 β 值，以此来计算rw
	NTL::ZZ_p tmp1;
	u64 tmp2, tmp3;
	u64 interim;
	u64 rw_n;

	for(i=0;i<t;i++){
	tmp1 = NTL::conv<ulong>(βDi);
		tmp2 = round_toL(tmp1, q, q1);
		if(i == 0){
			interim += tmp2;
			interim = moduloL(interim, q1);
		}
		else{
			interim -= tmp3;
			interim = moduloL(interim, q1);
		}
	}
	βD = round_toL(interim, q1, p);

	tmp1 = NTL::conv<ulong>(βs);
	tmp2 = round_toL(tmp1, q, q1);
	interim += tmp2;
	interim = moduloL(interim, q1);

	tmp1 = NTL::conv<ulong>(βD);
	tmp2 = round_toL(tmp1, q, q1);
	interim -= tmp2;
	interim = moduloL(interim, q1);

	rw_n = round_toL(interim, q1, p);



	//11. 验证rw正确性----ciphertext是由服务器存储，所以这一步也可以由服务器来进行
        ChaCha20::Decryption decryptor;
        decryptor.SetKeyWithIV((byte*)rw_n.c_str(), rw_n.size(), iv, sizeof(iv));
        StringSource ss3(ciphertext, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decryptedtext)
            )
        );

		if(decryptedtext=="hello"){
			验证通过
		}else{
			验证失败
		}
	
	//12. 密钥协商
	hash<string> hasher;      // 创建 hash 对象
    size_t hash_rw = hasher(rw_n);
	size_t hash_session2 = hasher(session2);
	e2 = random_vector_NTL(n,q);
	b2 = hash_rw*hash_session2 + e1
	
	//将b2发给server，接收从server发来的b1
	key_res = b1*hash_session2;





/* Device需要做的事情
一：注册阶段
	1.从User那里收到自己的秘密份额SDi
二：验证阶段
	1.User决定带哪几个设备，被选中的设备会受到User发来的选择参数session2
	2.接收由User发送过来的 α 值
	3.计算一个βDi=α*SDi*session2，将这个值发给User和Server
三：密钥更新阶段
	1.未被撤销的设备会收到从Server发来的密钥更新参数session1
	2.被撤销的设备会收到一个session1 = 1
	3.设备自身完成密钥更新操作：SDi'=SDi*session1
	4.服务器选择 t-1 个设备，这些设备将自己更新后的秘密份额发给 Server
*/


/ 
//1. 接收从User发来的秘密份额
	接收 SDi = shared_key_repo_tT_Sd[i][1]----i是设备Sdi的下标

//2. 被 User 选中的设备会接收由 User 发来的选择参数session2
	接收session2

//3. 接收由 User 计算并发来的 α 值
	接收 α

//4. 计算自己的部分PRF的值
	βDi=α*SDi*session2
	并且发送给 User 和 Server

//5. 密钥更新：
	//6. 未被撤销的设备接收密钥更新参数session1

	//7. 被撤销的参数接收 session=1

	//8. 设备进行密钥更新：
	SDi_new=SDi*session1

	//9. 重新初始化
	服务器或者用户选出t-1个Device，这些设备会将自己更新后的 SDi_new 发给 server










/* Server需要做的事情
一：注册阶段
	1.从User那里得到自己的密钥份额 Ss
二：验证阶段
	1.从User处得到 α 值
	2.用 Ss 与 α 进行计算得到 βs，将这个值发送给User
	3.从被 User 选择的设备那里得到一组βi的值
	4.利用 βs 和设备发来的 βDi 恢复出密钥 rw
	5.用这个密钥 rw 来解密密文C,判断明文是不是hello？来判断验证是否成功
	6.验证成功进入下一步，否则报错
三：密钥协商阶段
	1. 将 rw hash一下得到公钥向量 a
	2. 将密钥更新参数 session1 hash一下的到秘密向量 s1
	3. 计算 b1 = a*s1 + e2
	4. 将 b1 发给server
	5. 接收从 server 发来的 b2
	6. 利用 b2*s1 得到协商的密钥
四：密钥更新阶段
	1. 生成一个随机数(密钥更新参数--session2)
	2. User指定有哪些设备被撤销，向没被撤销的 Device 发送 session2，向被撤销的 Device 发送 session1
	
五：密钥更新之后的初始化：
	3. 收到密钥更新之后的 Device 发来的密钥sdi‘
	4. 收到用户发来的pw
	5. 先将 Device 发来的密钥进行秘密恢复得到 Sd*session1
	6. 将 Sd*session1 与自己的 Ss*session1 进行秘密恢复得到 S*session1
	7. 将 S*session1 作为 PRF 的 Key，将 pw 作为 PRF的输入x，计算的到一个新的 rw
	8. 用这个 rw 加密一个简单明文（如“hello”），将密文存储在服务器端，用于后续验证。
*/

/ 
//1. 从 User 那里得到 Ss
	Ss = shared_key_repo_tT[0][1];

//2. 从 User 那里得到 α 值
	α = hash_pw/session_2;

//3. 计算自己的部分 PRF值,将这个值发送给 User
	βs=α*Ss*session2;

//4. 从被 User选择的 Device那里收到一组（多个） βDi 的值
	接收 βDi;

//5. 恢复秘密
	NTL::ZZ_p tmp1;
	u64 tmp2, tmp3;
	u64 interim;
	u64 rw_n;

	for(i=0;i<t;i++){
	tmp1 = NTL::conv<ulong>(βDi);
		tmp2 = round_toL(tmp1, q, q1);
		if(i == 0){
			interim += tmp2;
			interim = moduloL(interim, q1);
		}
		else{
			interim -= tmp3;
			interim = moduloL(interim, q1);
		}
	}
	βD = round_toL(interim, q1, p);

	tmp1 = NTL::conv<ulong>(βs);
	tmp2 = round_toL(tmp1, q, q1);
	interim += tmp2;
	interim = moduloL(interim, q1);

	tmp1 = NTL::conv<ulong>(βD);
	tmp2 = round_toL(tmp1, q, q1);
	interim -= tmp2;
	interim = moduloL(interim, q1);

	rw_n = round_toL(interim, q1, p);

//6. 解密密文 C来验证 认证是否通过（见 User的第11步）

//7. 密钥协商
	hash<string> hasher;      // 创建 hash 对象
		size_t hash_rw = hasher(rw_n);
		size_t hash_session1 = hasher(session1);
		e1 = random_vector_NTL(n,q);
		b1 = hash_rw*hash_session1 + e1;
		
		//将 b1发给 User，接收从 User发来的 b2
		key_res = b2*hash_session1;

//8. 随机生成密钥更新参数 session1
	random_device rd;           // 获取随机种子
    mt19937 gen(rd());          // 梅森旋转算法生成器
    uniform_int_distribution<int> dist(0, 10000); // 生成 [0,10000] 范围整数
    int session1 = dist(gen); // 生成随机数

//9. 向未被撤销的 Device发送session1，向被撤销的 Device发送 session1 = 1

//10. 收到密钥更新之后的 Device 发来的密钥sdi‘

//11. 收到用户发来的 pw

//12. 将 Device发来的 SDi' ,以及自己的 Ss，进行秘密恢复
	int SD_session1 = 0;
	for(int i=1;i<t;i++){
		if(i>1){
			int SD_revoke = SD1-SDi;
		}
	}
	int S_session1 = Ss*session1 - SD_session1;

//13. 将 S*session1作为 PRF的 key，pw作为 x，计算一个新的 rw

	rw_revoke = direct_PRF_eval(pw, S_session1, n, q, p);

//14. 用这个 rw 加密一个简单字符串，并将密文 C 存储在服务器端，用于后续验证（与之前使用相同的加密算法）

