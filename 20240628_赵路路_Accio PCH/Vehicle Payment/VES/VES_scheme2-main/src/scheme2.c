#include "../inc/scheme2.h"

void init_CipherText(CipherText_st *ct)
{
	bn_null(ct->r); bn_null(ct->c); bn_null(ct->z1); bn_null(ct->z2);
	bn_new(ct->r); bn_new(ct->c); bn_new(ct->z1); bn_new(ct->z2);
	for (int i = 0; i < 8; i++)
	{
		ep_null(ct->C[i][0]); ep_new(ct->C[i][0]);
		ep_null(ct->C[i][1]); ep_new(ct->C[i][1]);
	}
	ct->bf = "bf.bin";
}

void free_CipherText(CipherText_st *ct)
{
	bn_free(ct->r); bn_free(ct->c); bn_free(ct->z1); bn_free(ct->z2);
	for (int i = 0; i < 8; i++)
	{
		ep_free(ct->C[i][0]);ep_free(ct->C[i][1]);
	}
}

void veriableEnc(CipherText_st *ct, SM2KeyPair_t *sig_kp, ep_t T, uint8_t *msg, int mlen)
{
	ep_t K, A, B, tmpp1, tmpp2, U, V, R1, R2, R3;
	ep_null(K); ep_null(A); ep_null(B); ep_null(tmpp1); ep_null(tmpp2); ep_null(U); ep_null(V); ep_null(R1); ep_null(R2); ep_null(R3);
	ep_new(K); ep_new(A); ep_new(B); ep_new(tmpp1); ep_new(tmpp2); ep_new(U); ep_new(V); ep_new(R1); ep_new(R2); ep_new(R3);
	bn_t  x, y, tmp, rho, temp_rho, s, c;
	bn_null(x);  bn_null(y); bn_null(tmp); bn_null(rho); bn_null(temp_rho); bn_null(s); bn_null(c);
	bn_new(x);  bn_new(y); bn_new(tmp); bn_new(rho); bn_new(temp_rho); bn_new(s); bn_new(c);
	// Twisted ElGamal加密时使用的随机数数组
	bn_t rho_l[8];
	for (int i = 0; i < 8; i++)
	{
		bn_null(rho_l[i]); bn_new(rho_l[i]);
	}
	// 对消息进行签名
	SM2Sign_t sig;
	init_SM2Sign_t(&sig);
	sm2_signV2(&sig, sig_kp, msg, mlen, K, &ct->lsb_y);
	bn_copy(ct->r, sig.r);
	bn_copy(s, sig.s);
	uint32_t s_array[8];
	for (int i = 0; i < 8; i++)
	{
		dig_t temps;
		bn_get_dig(&temps, s);
		s_array[i] = (uint32_t)temps;
		bn_rsh(s, s, 32);
		// 选取随机数rho_i属于[1, n-1]
		bn_rand_mod(rho_l[i], N_1);
		bn_add_dig(rho_l[i], rho_l[i], 1);
		twisted_elgamal_encV2(ct->C[i][0], ct->C[i][1], T, s_array[i], rho_l[i]);
	}
	/*
	生成离散对数零知识证明
	*/
	// 计算公开参数A = K - [r]P, B = G + P
	ep_mul(tmpp1, sig_kp->P, sig.r);
	ep_neg(tmpp1, tmpp1);
	ep_add_basic(A, K, tmpp1);
	ep_add_basic(B, sig_kp->P, G);
	// 随机选取x, y  in [1, n - 1]
	bn_rand_mod(x, N_1);
	bn_rand_mod(y, N_1);
	bn_add_dig(x, x, 1);
	bn_add_dig(y, y, 1);
	// R1 = [x]G1 + [y]G2
	ep_mul(tmpp1, G1, x);
	ep_mul(tmpp2, G2, y);
	ep_add_basic(R1, tmpp1, tmpp2);
	// R2 = [y]T
	ep_mul(R2, T, y);
	// R3 = [x]B
	ep_mul(R3, B, x);
	// 计算U = sum [2*{32*i}]Ui; V = sum [2*{32*i}]Vi; rho = sum rho_i * 2*{32*i}
	bn_set_dig(tmp, 1);
	ep_set_infty(U);
	ep_set_infty(V);
	bn_set_dig(rho, 0);
	for (int i = 0; i < 8; i++)
	{
		ep_mul(tmpp1, ct->C[i][0], tmp);
		ep_add_basic(U, U, tmpp1);
		ep_mul(tmpp2, ct->C[i][1], tmp);
		ep_add_basic(V, V, tmpp2);
		// FIXME:
		bn_lsh(temp_rho, rho_l[i], 32 * i);
		bn_add(rho, rho, temp_rho);
		bn_lsh(tmp, tmp, 32);
	}
	// c = H(R1, R2, R3, A, B, U, V), 需要哈希的数据总共需要33 * 7 = 231字节
	uint8_t *hashin = (uint8_t *)malloc(sizeof(uint8_t) * 231);
	memset(hashin, 0, 231);
	ep_write_bin(hashin, 33, R1, 1);
	ep_write_bin(hashin + 33 * 1, 33, R2, 1);
	ep_write_bin(hashin + 33 * 2, 33, R3, 1);
	ep_write_bin(hashin + 33 * 3, 33, A, 1);
	ep_write_bin(hashin + 33 * 4, 33, B, 1);
	ep_write_bin(hashin + 33 * 5, 33, U, 1);
	ep_write_bin(hashin + 33 * 6, 33, V, 1);
	hash2bn(c, hashin, 231);
	free(hashin);
	bn_copy(ct->c, c);
	// z1 = y - c * rho mod N
	bn_mul(tmp, ct->c, rho);
	bn_sub(tmp, y, tmp);
	bn_mod(ct->z1, tmp, N);
	// z2 = x - c * s mod N
	bn_mul(tmp, ct->c, sig.s);
	bn_sub(tmp, x, tmp);
	bn_mod(ct->z2, tmp, N);

	/*
	生成bulletproof范围证明
	*/
	range_prove(s_array, rho_l, 32, 8, ct->bf);

	// 释放变量
	free_SM2KeyPair(&sig);
	ep_free(K); ep_free(A); ep_free(B); ep_free(tmpp1); ep_free(tmpp2); ep_free(U); ep_free(V); ep_free(R1); ep_free(R2); ep_free(R3);
	bn_free(x); bn_free(y); bn_free(tmp); bn_free(rho); bn_free(temp_rho); bn_free(s); bn_free(c);
	for (int i = 0; i < 8; i++)
	{
		bn_free(rho_l[i]);
	}
}

int verify(CipherText_st *ct, ep_t sig_pk, ep_t T, uint8_t *msg, int mlen)
{
	int ret = 1;
	bn_t e, x, c, tmp;
	bn_null(e); bn_null(x); bn_null(c); bn_null(tmp);
	bn_new(e); bn_new(x); bn_new(c); bn_new(tmp);
	fp_t x1;
	fp_null(x1);
	fp_new(x1);
	ep_t K, A, B, tmpp1, tmpp2, U, V, R1, R2, R3;
	ep_null(K); ep_null(A); ep_null(B); ep_null(tmpp1); ep_null(tmpp2); ep_null(U); ep_null(V); ep_null(R1); ep_null(R2); ep_null(R3);
	ep_new(K); ep_new(A); ep_new(B); ep_new(tmpp1); ep_new(tmpp2); ep_new(U); ep_new(V); ep_new(R1); ep_new(R2); ep_new(R3);
	/*
	验证离散对数零知识证明
	*/
	// 计算消息msg的哈希e
	hash2bn(e, msg, mlen);
	// x1 = (r - e) mod N
	bn_sub(x, ct->r, e);
	bn_mod(x, x, N);
	fp_prime_conv(x1, x);
	upk_point(K, x1, ct->lsb_y);
	// 计算公开参数A = K - [r]P, B = G + P
	ep_mul(tmpp1, sig_pk, ct->r);
	ep_neg(tmpp1, tmpp1);
	ep_add_basic(A, K, tmpp1);
	ep_add_basic(B, sig_pk, G);
	// 计算U = sum [2*{32*i}]Ui; V = sum [2*{32*i}]Vi; 
	bn_set_dig(tmp, 1);
	ep_set_infty(U);
	ep_set_infty(V);
	for (int i = 0; i < 8; i++)
	{
		ep_mul(tmpp1, ct->C[i][0], tmp);
		ep_add_basic(U, U, tmpp1);
		ep_mul(tmpp2, ct->C[i][1], tmp);
		ep_add_basic(V, V, tmpp2);
		bn_lsh(tmp, tmp, 32);
	}
	// R1 = [Z2]G1 + [Z1]G2 +[c]U
	ep_mul(tmpp1, G1, ct->z2);
	ep_mul(tmpp2, G2, ct->z1);
	ep_mul(R1, U, ct->c);
	ep_add_basic(R1, R1, tmpp1);
	ep_add_basic(R1, R1, tmpp2);
	// R2 = [z1]T + [c]V
	ep_mul(tmpp1, T, ct->z1);
	ep_mul(R2, V, ct->c);
	ep_add_basic(R2, R2, tmpp1);
	// R3 = [z2]B + [c]A
	ep_mul(tmpp1, B, ct->z2);
	ep_mul(R3, A, ct->c);
	ep_add_basic(R3, R3, tmpp1);
	// c = H(R1, R2, R3, A, B, U, V), 需要哈希的数据总共需要33 * 7 = 231字节
	uint8_t *hashin = (uint8_t *)malloc(sizeof(uint8_t) * 231);
	memset(hashin, 0, 231);
	ep_write_bin(hashin, 33, R1, 1);
	ep_write_bin(hashin + 33 * 1, 33, R2, 1);
	ep_write_bin(hashin + 33 * 2, 33, R3, 1);
	ep_write_bin(hashin + 33 * 3, 33, A, 1);
	ep_write_bin(hashin + 33 * 4, 33, B, 1);
	ep_write_bin(hashin + 33 * 5, 33, U, 1);
	ep_write_bin(hashin + 33 * 6, 33, V, 1);
	hash2bn(c, hashin, 231);
	free(hashin);
	if (bn_cmp(c, ct->c) != RLC_EQ)
	{
		ret = 0;
		goto end;
	}
	/*
	Bulletproof零知识证明验证
	*/
	bn_t coor;
	bn_null(coor);
	bn_new(coor);
	uint8_t *u_l = (uint8_t *)malloc(sizeof(uint8_t) * 33 * 8);
	for (int i = 0; i < 8; i++)
	{
		fp_prime_back(coor, ct->C[i][0]->y);
		u_l[i * 33] = (uint8_t)bn_get_bit(coor, 0);
		fp_prime_back(coor, ct->C[i][0]->x);
		bn_write_bin(u_l + i * 33 + 1, 32, coor);
	}
	bn_free(coor);
	int flag = range_verify(u_l, 32, 8, ct->bf);
	free(u_l);
	if (flag == 0)
	{
		ret = 0;
	}
end:
	// 释放变量
	bn_free(e); bn_free(x); bn_free(c); bn_free(tmp); fp_free(x1);
	ep_free(K); ep_free(A); ep_free(tmpp1); ep_free(tmpp2); ep_free(U); ep_free(V); ep_free(R1); ep_free(R2); ep_free(R3);
	return ret;
}

void veriableDec(const PRE_COMPUTE_TABLE table[1 << 16], SM2Sign_t *sig, CipherText_st *ct, bn_t t)
{
	uint32_t temp_m;
	ep_t U, V;
	ep_null(U); ep_null(V);
	ep_new(U); ep_new(V);
	bn_zero(sig->s);
	for (int i = 7; i >= 0; i--)
	{
		bn_lsh(sig->s, sig->s, 32);
		ep_copy(U, ct->C[i][0]);
		ep_copy(V, ct->C[i][1]);
		twisted_elgamal_dec(table, U, V, t, &temp_m);
		bn_add_dig(sig->s, sig->s, temp_m);
	}
	bn_copy(sig->r, ct->r);
}

void schemeInit()
{
	core_init();
	fp_prime_init();
	ep_curve_init();
	fp_param_set(SM2_256);
	ep_param_set(SM2_P256);
	initGlobal();
	init_twisted_elgamal_PP();
}

void schemeFree()
{
	free_twisted_elgamal_PP();
	freeGlobal();
	ep_curve_clean();
	fp_prime_clean();
	core_clean();
}

void testScheme2()
{
	schemeInit();

	ep_param_print();
	fp_param_print();

	SM2KeyPair_t sig_kp;
	genSM2KeyPair(&sig_kp);

	Twisted_KeyPair_t enc_kp;
	genTwistedKeyPair(&enc_kp);

	CipherText_st ct;
	init_CipherText(&ct);

	SM2Sign_t sig;
	init_SM2Sign_t(&sig);

	// 生成G1的预计算表
	PRE_COMPUTE_TABLE table[1 << 16];
	gen_pre_compute_table(table, G1);

	uint8_t msg[] = { 0xFA, 0xFB, 0xFC };
	bn_t m;
	bn_null(m);
	bn_new(m);
	bn_read_bin(m, msg, 3);
	printf("\nmessage is\n");
	bn_print(m);

	int flag;
	BENCH_TEST(10, veriableEnc(&ct, &sig_kp, enc_kp.T, msg, 3), "Veriable Encrypt");
	BENCH_TEST(10, flag = verify(&ct, sig_kp.P, enc_kp.T, msg, 3), "Verify");
	printf("\n");
	if (flag)
		printf("Valid SM2 signature!\n");
	else
		printf("Invalid SM2 signature! \n");

	veriableDec(table, &sig, &ct, enc_kp.t);
	printf("sig.r is: ");
	bn_print(sig.r);
	printf("sig.s is: ");
	bn_print(sig.s);

	// 打印bulletproof证明
	// print_rangeproof(32, 8, ct.bf);
	// if (sm2_verify(&sig, sig_kp.P, msg, 3))
	// 	printf("验签通过\n");
	// else
	// 	printf("验签失败\n");

	free_SM2KeyPair(&sig_kp);
	free_TwistedKeyPair(&enc_kp);
	free_CipherText(&ct);
	free_SM2Sign_t(&sig);

	schemeFree();
}