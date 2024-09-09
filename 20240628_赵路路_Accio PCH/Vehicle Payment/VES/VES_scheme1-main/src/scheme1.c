#include "../inc/scheme1.h"

void init_CipherText(CipherText_st *ct)
{
	bn_null(ct->r);
	bn_null(ct->C);
	ep_null(ct->R1);
	bn_null(ct->R2);
	bn_null(ct->c);
	bn_null(ct->z1);
	bn_null(ct->z2);
	bn_new(ct->r);
	bn_new(ct->C);
	ep_new(ct->R1);
	bn_new(ct->R2);
	bn_new(ct->c);
	bn_new(ct->z1);
	bn_new(ct->z2);
}

void free_CipherText(CipherText_st *ct)
{
	bn_free(ct->r);
	bn_free(ct->C);
	ep_free(ct->R1);
	bn_free(ct->R2);
	bn_free(ct->c);
	bn_free(ct->z1);
	bn_free(ct->z2);
}

void veriableEnc(CipherText_st *ct, SM2KeyPair_t *kp, bn_t pub, uint8_t *msg, int mlen)
{
	ep_t K, A, B, tmpp;
	ep_null(K); ep_null(A); ep_null(B); ep_null(tmpp);
	ep_new(K); ep_new(A); ep_new(B); ep_new(tmpp);
	bn_t  mu, tmp, rho, gamma;
	bn_null(mu);  bn_null(tmp); bn_null(rho); bn_null(gamma);
	bn_new(mu);  bn_new(tmp); bn_new(rho); bn_new(gamma);
	// 对消息进行签名
	SM2Sign_t sig;
	init_SM2Sign_t(&sig);
	sm2_signV2(&sig, kp, msg, mlen, K, &ct->lsb_y);
	bn_copy(ct->r, sig.r);
	// 随机选取mu in Z_N*
	do
	{
		bn_rand_mod(mu, pub);
	} while (bn_is_zero(mu));
	// 使用随机数mu对s进行加密
	paillier_enc(ct->C, pub, sig.s, mu);
	// 生成零知识证明
	// 计算公开参数A = K - [r]P, B = G + P
	ep_add_basic(B, kp->P, G);
	ep_mul(tmpp, kp->P, sig.r);
	ep_neg(tmpp, tmpp);
	ep_add_basic(A, K, tmpp);
	// 从Zn中随机选取一个随机数rho，但是确保它的比特位长大于512，从而使得(rho - c * s)非负
	do
	{
		bn_rand_mod(rho, pub);
	} while (bn_bits(rho) <= 512);
	// R1 = [rho]B
	ep_mul(ct->R1, B, rho);
	// R2 = (1+N)^rho * gamma^N mod N^2
	do
	{
		bn_rand_mod(gamma, pub);
	} while (bn_is_zero(gamma));
	paillier_enc(ct->R2, pub, rho, gamma);
	// c = H(R1,R2,A,B,C), 需要哈希的数据总共需要33 + 768 + 33 + 33 + 768字节
	uint8_t *hashin = (uint8_t *)malloc(sizeof(uint8_t) * 1635);
	memset(hashin, 0, 1635);
	ep_write_bin(hashin, 33, ct->R1, 1);
	bn_write_bin(hashin + 33, 768, ct->R2);
	ep_write_bin(hashin + 33 + 768, 33, A, 1);
	ep_write_bin(hashin + 33 + 768 + 33, 33, B, 1);
	bn_write_bin(hashin + 33 + 768 + 33 + 33, 768, ct->C);
	hash2bn(ct->c, hashin, 1635);
	free(hashin);
	// z1 = rho - c*s
	bn_mul(tmp, ct->c, sig.s);
	bn_sub(ct->z1, rho, tmp);
	// z2 = gamma / mu^c mod N
	bn_mxp(tmp, mu, ct->c, pub);
	bn_mod_inv(tmp, tmp, pub);
	bn_mul(tmp, gamma, tmp);
	bn_mod(ct->z2, tmp, pub);
	// 释放变量
	free_SM2KeyPair(&sig);
	ep_free(K); ep_free(A); ep_free(B); ep_free(tmpp);
	bn_free(mu); bn_free(tmp); bn_free(rho); bn_free(gamma);
}

int verify(CipherText_st *ct, ep_t ec_pk, bn_t pub, uint8_t *msg, int mlen)
{
	int ret = 1;
	bn_t e, x, c, tmp, R2;
	bn_null(e); bn_null(x); bn_null(c); bn_null(tmp); bn_null(R2);
	bn_new(e); bn_new(x); bn_new(c); bn_new(tmp); bn_new(R2);
	fp_t x1;
	fp_null(x1);
	fp_new(x1);
	ep_t K, A, B, R1, tmpp1, tmpp2;
	ep_null(K); ep_null(A); ep_null(B); ep_null(tmpp1); ep_null(R1); ep_null(tmpp2);
	ep_new(K); ep_new(A); ep_new(B); ep_new(tmpp1); ep_new(R1); ep_new(tmpp2);
	// 计算消息msg的哈希e
	hash2bn(e, msg, mlen);
	// x1 = (r - e) mod N
	bn_sub(x, ct->r, e);
	bn_mod(x, x, N);
	fp_prime_conv(x1, x);
	upk_point(K, x1, ct->lsb_y);
	// 计算公开参数A = K - [r]P, B = G + P
	ep_add_basic(B, ec_pk, G);
	ep_mul(tmpp1, ec_pk, ct->r);
	ep_neg(tmpp1, tmpp1);
	ep_add_basic(A, K, tmpp1);
	// c = H(R1,R2,A,B,C), 需要哈希的数据总共需要33 + 768 + 33 + 33 + 768字节
	uint8_t *hashin = (uint8_t *)malloc(sizeof(uint8_t) * 1635);
	memset(hashin, 0, 1635);
	ep_write_bin(hashin, 33, ct->R1, 1);
	bn_write_bin(hashin + 33, 768, ct->R2);
	ep_write_bin(hashin + 33 + 768, 33, A, 1);
	ep_write_bin(hashin + 33 + 768 + 33, 33, B, 1);
	bn_write_bin(hashin + 33 + 768 + 33 + 33, 768, ct->C);
	hash2bn(c, hashin, 1635);
	free(hashin);
	// 验证hash是否通过
	if (bn_cmp(c, ct->c) != RLC_EQ)
	{
		ret = 0;
		goto end;
	}
	ep_mul(tmpp1, B, ct->z1);
	ep_mul(tmpp2, A, c);
	ep_add_basic(R1, tmpp1, tmpp2);
	paillier_enc(R2, pub, ct->z1, ct->z2);
	bn_t t;
	bn_null(t);
	bn_new(t);
	bn_mul(t, pub, pub);
	bn_mxp(tmp, ct->C, c, t);
	bn_mul(R2, tmp, R2);
	bn_mod(R2, R2, t);
	if (ep_cmp(R1, ct->R1) != RLC_EQ || bn_cmp(R2, ct->R2) != RLC_EQ)
		ret = 0;
end:
	bn_free(e); bn_free(x); bn_free(c); bn_free(tmp); bn_free(R2); fp_free(x1);
	ep_free(K); ep_free(A); ep_free(B); ep_free(tmpp1); ep_free(tmpp2);
	return ret;
}

int veriableDec(SM2Sign_t *sig, CipherText_st *ct, PaillierKeyPair_t *kp)
{
	int ret = cp_ghpe_dec(sig->s, ct->C, kp->pub, kp->prv, 1);
	bn_copy(sig->r, ct->r);
	return ret;
}

void schemeInit()
{
	core_init();
	fp_prime_init();
	ep_curve_init();
	fp_param_set(SM2_256);
	ep_param_set(SM2_P256);
	initGlobal();
}

void schemeFree()
{
	freeGlobal();
	ep_curve_clean();
	fp_prime_clean();
	core_clean();
}

void testScheme1()
{
	schemeInit();

	ep_param_print();
	fp_param_print();

	SM2KeyPair_t sig_kp;
	genSM2KeyPair(&sig_kp);

	PaillierKeyPair_t enc_kp;
	gen_PaillierKeyPair(&enc_kp, 3072);

	CipherText_st ct;
	init_CipherText(&ct);

	SM2Sign_t sig;
	init_SM2Sign_t(&sig);

	uint8_t msg[] = { 0xFA, 0xFB, 0xFC };
	bn_t e;
	bn_null(e);
	bn_new(e);
	bn_read_bin(e, msg, 3);
	printf("\nmessage is\n");
	bn_print(e);
	bn_free(e);

	int flag;
	BENCH_TEST(10, veriableEnc(&ct, &sig_kp, enc_kp.pub, msg, 3), "Veriable Encrypt");
	BENCH_TEST(10, flag = verify(&ct, sig_kp.P, enc_kp.pub, msg, 3), "Verify");

	printf("\n");
	if (flag)
		printf("Valid SM2 signature!\n");
	else
		printf("Invalid SM2 signature! \n");

	veriableDec(&sig, &ct, &enc_kp);
	printf("sig.r is: ");
	bn_print(sig.r);
	printf("sig.s is: ");
	bn_print(sig.s);


	free_SM2KeyPair(&sig_kp);
	free_PaillierKeyPair(&enc_kp);
	free_CipherText(&ct);
	free_SM2Sign_t(&sig);

	schemeFree();

}