#include "../inc/scheme3.h"

void ves_ciphertext_init(CipherText_st *ct)
{
	bn_null(ct->C);
	bn_new(ct->C);

	ves_zkpi_init(&ct->pi);
}

void ves_ciphertext_free(CipherText_st *ct)
{
	bn_free(ct->C);

	ves_zkpi_free(&ct->pi);
}

void ves_enc_s3(CipherText_st *ct, const bn_t N, const bn_t s, const CrsParam_st *cp)
{
	bn_t mu;

	bn_null(mu);
	bn_new(mu);

	/* randomly choosing mu in (0, N) */
	do
	{
		bn_rand_mod(mu, N);
	} while (bn_is_zero(mu));

	ves_paillier_enc(ct->C, N, s, mu);
	nizk_p(&ct->pi, s, mu, cp, N);

	bn_free(mu);
}

int ves_vrf_s3(const CipherText_st *ct, const bn_t N, const CrsParam_st *cp)
{
	return nizk_v(ct->C, &ct->pi, cp, N);
}

void ves_dec_s3(bn_t s, const CipherText_st *ct, const bn_t lambda, const bn_t N)
{
	bn_t tmp_bn1, tmp_bn2;

	bn_null(tmp_bn1);
	bn_null(tmp_bn2);
	bn_new(tmp_bn1);
	bn_new(tmp_bn2);

	/* C^lambda mod N^2 */
	bn_sqr(tmp_bn1, N);
	bn_mxp(tmp_bn2, ct->C, lambda, tmp_bn1);

	/* L(x) = (x-1)/N */
	bn_sub_dig(tmp_bn2, tmp_bn2, 1);
	bn_div(tmp_bn2, tmp_bn2, N);

	/* lambda^(-1) mod N */
	bn_mod_inv(tmp_bn1, lambda, N);

	bn_mul(s, tmp_bn1, tmp_bn2);
	bn_mod(s, s, N);

	bn_free(tmp_bn1);
	bn_free(tmp_bn2);
}

void test_scheme_3()
{
	CipherText_st ct;
	VesKeyPair kp;
	CrsParam_st cp;

	bn_t cipher, plain;

	bn_null(cipher);
	bn_null(plain);

	bn_new(cipher);
	bn_new(plain);

	ves_init();
	fp_param_print();
	ep_param_print();

	ves_ciphertext_init(&ct);
	ves_crsparam_init(&cp);
	ves_key_pair_init(&kp);

	ves_gen_key_pair(&kp, 3072);
	nizk_k(&cp);

	bn_set_dig(plain, 0x3FFFFFFF);
	printf("\nPlain text: ");
	bn_print(plain);


	int flag;
	BENCH_TEST(10, ves_enc_s3(&ct, kp.pub, plain, &cp), "Veriable Encrypt");
	BENCH_TEST(10, flag = ves_vrf_s3(&ct, kp.pub, &cp), "Verify");

	printf("\n");
	if (flag)
		printf("In range [0, 2^30 -1] !\n");
	else
		printf("Out of range [0, 2^30 - 1] !\n");

	ves_dec_s3(cipher, &ct, kp.prv, kp.pub);
	printf("\nDecrypted text: ");
	bn_print(cipher);

	bn_free(cipher);
	bn_free(plain);

	ves_key_pair_free(&kp);
	ves_crsparam_free(&cp);
	ves_ciphertext_free(&ct);

	ves_free();
}