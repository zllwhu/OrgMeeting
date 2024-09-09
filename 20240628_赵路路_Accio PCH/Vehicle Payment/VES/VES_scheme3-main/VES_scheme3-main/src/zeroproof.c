#include "../inc/zeroproof.h"
#include "../inc/common.h"
#include "../inc/paillier.h"
#include "relic.h"

void ves_crsparam_init(CrsParam_st *crs)
{
	g2_null(crs->vk);
	g2_new(crs->vk);

	for (int i = 0; i < u; i++)
	{
		g1_null(crs->sigma[i]);
		g1_null(crs->T[i]);

		g1_new(crs->sigma[i]);
		g1_new(crs->T[i]);
	}
}

void ves_crsparam_free(CrsParam_st *crs)
{
	g2_free(crs->vk);

	for (int i = 0; i < u; i++)
	{
		g1_free(crs->sigma[i]);
		g1_free(crs->T[i]);
	}
}

void ves_zkpi_init(ZkPi_st *crs)
{
	bn_null(crs->R);
	bn_null(crs->c);
	bn_null(crs->z);
	bn_null(crs->r_hat);
	g2_null(crs->theta);

	bn_new(crs->R);
	bn_new(crs->c);
	bn_new(crs->z);
	bn_new(crs->r_hat);
	g2_new(crs->theta);

	for (int i = 0; i < l; i++)
	{
		g1_null(crs->V[i]);
		g1_null(crs->a[i]);
		g1_null(crs->W[i]);

		bn_null(crs->z_v[i]);
		bn_null(crs->z_s[i]);

		g1_new(crs->V[i]);
		g1_new(crs->a[i]);
		g1_new(crs->W[i]);

		bn_new(crs->z_v[i]);
		bn_new(crs->z_s[i]);
	}
}

void ves_zkpi_free(ZkPi_st *crs)
{
	bn_free(crs->R);
	bn_free(crs->c);
	bn_free(crs->z);
	bn_free(crs->r_hat);
	g2_free(crs->theta);

	for (int i = 0; i < l; i++)
	{
		g1_free(crs->V[i]);
		g1_free(crs->a[i]);
		g1_free(crs->W[i]);

		bn_free(crs->z_v[i]);
		bn_free(crs->z_s[i]);
	}
}

void nizk_k(CrsParam_st *crs)
{
	bn_t sk;
	bn_t tmp;

	bn_null(sk);
	bn_null(tmp);
	bn_new(sk);
	bn_new(tmp);

	/* Generating key pair of Boneh-Boyen using short scalars. */
	do
	{
		bn_rand(sk, RLC_POS, 2 * pc_param_level());
		bn_mod(sk, sk, N_Tidle);
	} while (bn_is_zero(sk));

	/* vk = sk * g2. */
	g2_mul_gen(crs->vk, sk);

	/* for j in [0, u-1], computing BB signature */
	for (int j = 0; j < u; j++)
	{
		/* tmp = 1/(sk+j) */
		bn_add_dig(tmp, sk, (dig_t)j);
		bn_mod_inv(tmp, tmp, N_Tidle);

		/* sigma[j] = [1/(sk+j)]G1 */
		g1_mul_gen(crs->sigma[j], tmp);

		/* T[j] = [sk](sigma[j]) */
		g1_mul(crs->T[j], crs->sigma[j], sk);
	}

	bn_free(tmp);
	bn_free(sk);
}

void nizk_p(ZkPi_st *pi, const bn_t s, const bn_t mu, const CrsParam_st *crs, const bn_t N)
{
	bn_t rho[l];
	bn_t rho_sum;

	bn_t gamma;
	bn_t v[l];
	bn_t eta[l];

	bn_t c_hat;

	bn_t tmp_bn;
	g1_t tmp_g1;
	g2_t tmp_g2;

	unsigned int si[l];

	for (int i = 0; i < l; i++)
	{
		bn_null(rho[i]);
		bn_new(rho[i]);

		bn_null(v[i]);
		bn_new(v[i]);

		bn_null(eta[i]);
		bn_new(eta[i]);
	}

	bn_null(rho_sum);
	bn_null(gamma);
	bn_null(c_hat);
	bn_null(tmp_bn);
	g1_null(tmp_g1);
	g2_null(tmp_g2);

	bn_new(rho_sum);
	bn_new(gamma);
	bn_new(c_hat);
	bn_new(tmp_bn);
	g1_new(tmp_g1);
	g2_new(tmp_g2);

	bn_zero(rho_sum);
	/* for all i in [0, l-1], randomly choosing rho[i] in Z_{N}* */
	for (int i = 0; i < l; i++)
	{
		do
		{
			bn_rand_mod(rho[i], N);
		} while (bn_bits(rho[i]) <= 266);

		bn_lsh(tmp_bn, rho[i], u_len * i);
		bn_add(rho_sum, rho_sum, tmp_bn);
	}

	/* randomly choosing gamma in Z_N^*. */
	do
	{
		bn_rand_mod(gamma, N);
	} while (bn_is_zero(gamma));

	/* Computing R = (1+N)^rho * gamma^N mod N^2 */
	ves_paillier_enc(pi->R, N, rho_sum, gamma);


	/* computing si */
	for (int i = 0; i < l; i++)
	{
		dig_t low;

		bn_copy(tmp_bn, s);
		bn_rsh(tmp_bn, tmp_bn, u_len * i);

		bn_get_dig(&low, tmp_bn);

		si[i] = (unsigned int)(low & (u - 1));
	}

	/* for all i in [0, l-1], randomly choosing v_i, n_i in [0, N_Tidle) */
	for (int i = 0; i < l; i++)
	{
		/* choosing v[i] */
		bn_rand_mod(v[i], N_Tidle);
		/* choosing eta[i] */
		bn_rand_mod(eta[i], N_Tidle);

		/* V_i = [v_i]sigma_si */
		g1_mul(pi->V[i], crs->sigma[si[i]], v[i]);

		/* a[i] = [-rho_i]V_i + [eta_i]G1 */
		bn_mod(tmp_bn, rho[i], N_Tidle);
		bn_sub(tmp_bn, N_Tidle, tmp_bn);

		g1_mul(pi->a[i], pi->V[i], tmp_bn);
		g1_mul_gen(tmp_g1, eta[i]);
		// FIXME:这里将g1_add替换成了ep_add_basic
		ep_add_basic(pi->a[i], pi->a[i], tmp_g1);

		/* W_i = [v_i]T_si */
		g1_mul(pi->W[i], crs->T[si[i]], v[i]);
	}

	/* randomly choosing c_hat in Z_q^*, r_hat in Z_q^*. */
	do
	{
		bn_rand_mod(c_hat, N_Tidle);
	} while (bn_is_zero(c_hat));
	do
	{
		bn_rand_mod(pi->r_hat, N_Tidle);
	} while (bn_is_zero(pi->r_hat));
	/* theta = [r_hat]G2 - [c_hat]vk */
	g2_mul_gen(pi->theta, pi->r_hat);
	g2_mul(tmp_g2, crs->vk, c_hat);
	g2_neg(tmp_g2, tmp_g2);
	ep2_add_basic(pi->theta, pi->theta, tmp_g2);

	/* c_tidle = tmp_bn = H(R, {V_i, a_i, W_i}, theta), 768+(49+49+49)*l+97 */
	uint8_t buf[768 + (49 + 49 + 49) * l + 97] = { 0 };
	int p = 0;
	bn_write_bin(buf, 768, pi->R);
	p += 768;
	for (int i = 0; i < l; i++)
	{
		g1_write_bin(buf + p, 49, pi->V[i], 1);
		p += 49;
		g1_write_bin(buf + p, 49, pi->a[i], 1);
		p += 49;
		g1_write_bin(buf + p, 49, pi->W[i], 1);
		p += 49;
	}
	g2_write_bin(buf + p, 97, pi->theta, 1);
	hash2bn(tmp_bn, buf, sizeof(buf));

	/* c = c_hat + c_tidle mod q */
	bn_add(pi->c, c_hat, tmp_bn);
	bn_mod(pi->c, pi->c, N_Tidle);

	/* for all i in [0, l-1], computing z_v_i and z_s_i */
	for (int i = 0; i < l; i++)
	{
		bn_mul(tmp_bn, pi->c, v[i]);
		bn_sub(pi->z_v[i], eta[i], tmp_bn);
		bn_mod(pi->z_v[i], pi->z_v[i], N_Tidle);

		bn_set_dig(tmp_bn, si[i]);
		bn_mul(tmp_bn, pi->c, tmp_bn);
		bn_sub(pi->z_s[i], rho[i], tmp_bn);
	}

	// FIXME:这里修改了模数
	/* Computing z = gamma / (mu^c) */
	bn_mxp(tmp_bn, mu, pi->c, N);
	bn_mod_inv(tmp_bn, tmp_bn, N);
	bn_mul(pi->z, gamma, tmp_bn);
	bn_mod(pi->z, pi->z, N);

	for (int i = 0; i < l; i++)
	{
		bn_free(rho[i]);
		bn_free(v[i]);
		bn_free(eta[i]);
	}
	bn_free(rho_sum);
	bn_free(gamma);
	bn_free(c_hat);

	bn_free(tmp_bn);
	g1_free(tmp_g1);
	g2_free(tmp_g2);
}

int nizk_v(const bn_t C, const ZkPi_st *pi, const CrsParam_st *crs, const bn_t N)
{
	int res = 1;

	bn_t c_hat;
	bn_t z_s;
	bn_t tmp_bn1, tmp_bn2;
	g1_t tmp_g11, tmp_g12;
	g2_t tmp_g21, tmp_g22;

	bn_null(c_hat);
	bn_null(z_s);
	bn_null(tmp_bn1);
	bn_null(tmp_bn2);
	g1_null(tmp_g11);
	g1_null(tmp_g12);
	g2_null(tmp_g21);
	g2_null(tmp_g22);

	bn_new(c_hat);
	bn_new(z_s);
	bn_new(tmp_bn1);
	bn_new(tmp_bn2);
	g1_new(tmp_g11);
	g1_new(tmp_g12);
	g2_new(tmp_g21);
	g2_new(tmp_g22);

	/* c_tidle = tmp_bn1 = H(R, {V_i, a_i, W_i}, theta), 768+(49+49+49)*l+97 */
	uint8_t buf[768 + (49 + 49 + 49) * l + 97] = { 0 };
	int p = 0;
	bn_write_bin(buf, 768, pi->R);
	p += 768;
	for (int i = 0; i < l; i++)
	{
		g1_write_bin(buf + p, 49, pi->V[i], 1);
		p += 49;
		g1_write_bin(buf + p, 49, pi->a[i], 1);
		p += 49;
		g1_write_bin(buf + p, 49, pi->W[i], 1);
		p += 49;
	}
	g2_write_bin(buf + p, 97, pi->theta, 1);
	hash2bn(tmp_bn1, buf, sizeof(buf));

	/* c_hat = c - c_tidle mod q */
	bn_sub(c_hat, pi->c, tmp_bn1);
	bn_mod(c_hat, c_hat, N_Tidle);

	/* z_s = sum(u^i * z_s_i) */
	bn_zero(z_s);
	for (int i = 0; i < l; i++)
	{
		bn_copy(tmp_bn1, pi->z_s[i]);
		bn_lsh(tmp_bn1, tmp_bn1, u_len * i);
		bn_add(z_s, z_s, tmp_bn1);
	}

	/* final */
	/* b1 */
	for (int i = 0; i < l; i++)
	{
		g1_mul(tmp_g11, pi->W[i], pi->c);

		bn_mod(tmp_bn1, pi->z_s[i], N_Tidle);
		bn_sub(tmp_bn1, N_Tidle, tmp_bn1);
		g1_mul(tmp_g12, pi->V[i], tmp_bn1);
		ep_add_basic(tmp_g11, tmp_g11, tmp_g12);

		g1_mul_gen(tmp_g12, pi->z_v[i]);
		ep_add_basic(tmp_g11, tmp_g11, tmp_g12);

		if (g1_cmp(pi->a[i], tmp_g11) != RLC_EQ)
		{
			res = 0;
			goto END;
		}
	}

	/* b2 */
	bn_sqr(tmp_bn1, N);
	bn_mxp(tmp_bn2, C, pi->c, tmp_bn1);
	ves_paillier_enc(tmp_bn1, N, z_s, pi->z);
	bn_mul(tmp_bn1, tmp_bn1, tmp_bn2);
	bn_sqr(tmp_bn2, N);
	bn_mod(tmp_bn1, tmp_bn1, tmp_bn2);

	if (bn_cmp(pi->R, tmp_bn1) != RLC_EQ)
	{
		res = 0;
		goto END;
	}

	/* b3 */
	g2_mul_gen(tmp_g21, pi->r_hat);
	g2_mul(tmp_g22, crs->vk, c_hat);
	ep2_add_basic(tmp_g22, tmp_g22, pi->theta);
	if (g2_cmp(tmp_g21, tmp_g22) != RLC_EQ)
	{
		res = 0;
		goto END;
	}

END:
	bn_free(c_hat);
	bn_free(z_s);
	bn_free(tmp_bn1);
	bn_free(tmp_bn2);
	g1_free(tmp_g11);
	g1_free(tmp_g12);
	g2_free(tmp_g21);
	g2_free(tmp_g22);

	return res;
}