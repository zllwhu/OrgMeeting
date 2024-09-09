#include "../inc/sm2.h"
#include "../inc/common.h"


void init_SM2KeyPair(SM2KeyPair_t *kp)
{
	bn_null(kp->d);
	bn_new(kp->d);
	ep_null(kp->P);
	ep_new(kp->P);
}

void free_SM2KeyPair(SM2KeyPair_t *kp)
{
	bn_free(kp->d);
	ep_free(kp->P);
}

void genSM2KeyPair(SM2KeyPair_t *kp)
{
	init_SM2KeyPair(kp);
	// 随机选取私钥d属于[1, n-1]
	bn_rand_mod(kp->d, N_1);
	bn_add_dig(kp->d, kp->d, 1);
	ep_mul_gen(kp->P, kp->d);
}

void init_SM2Sign_t(SM2Sign_t *sig)
{
	bn_null(sig->r);
	bn_null(sig->s);
	bn_new(sig->r);
	bn_new(sig->s);
}

void free_SM2Sign_t(SM2Sign_t *sig)
{
	bn_free(sig->r);
	bn_free(sig->s);
}

void sm2_sign(SM2Sign_t *sig, SM2KeyPair_t *kp, uint8_t *msg, int mlen)
{
	bn_t e, k, x1, tmp1, tmp2;
	bn_null(e); bn_null(k); bn_null(x1); bn_null(tmp1); bn_null(tmp2);
	bn_new(e); bn_new(k); bn_new(x1); bn_new(tmp1); bn_new(tmp2);
	ep_t kG;
	ep_null(kG);
	ep_new(kG);
	// 计算消息msg的哈希
	hash2bn(e, msg, mlen);
	while (1)
	{
		// 随机选取k in [1, n - 1]
		bn_rand_mod(k, N_1);
		bn_add_dig(k, k, 1);
		// 计算[k]G = (x1, y1)
		ep_mul_gen(kG, k);
		// 计算r = (e + x1) mod n
		fp_prime_back(x1, kG->x);
		bn_add(sig->r, e, x1);
		bn_mod(sig->r, sig->r, N);
		// 若r = 0或r + k = n，进行下一次循环
		bn_add(tmp1, sig->r, k);
		if (bn_is_zero(sig->r) || bn_cmp(tmp1, N) == RLC_EQ)
			continue;
		// s = ((1 + d)^-1 (k - r * d)) mod N
		bn_add_dig(tmp1, kp->d, 1);
		bn_mod_inv(tmp1, tmp1, N);
		bn_mul(tmp2, sig->r, kp->d);
		bn_mod(tmp2, tmp2, N);
		bn_sub(tmp2, k, tmp2);
		bn_mod(tmp2, tmp2, N);
		bn_mul(sig->s, tmp1, tmp2);
		bn_mod(sig->s, sig->s, N);
		if (bn_is_zero(sig->s))
			continue;
		// 若正常执行则跳出循环
		break;
	}
	// 释放变量
	bn_free(e); bn_free(k); bn_free(x1); bn_free(tmp1); bn_free(tmp2);
	ep_free(kG);
}

void sm2_signV2(SM2Sign_t *sig, SM2KeyPair_t *kp, uint8_t *msg, int mlen, ep_t K, int *LSB_y)
{
	bn_t e, k, x1, tmp1, tmp2;
	bn_null(e); bn_null(k); bn_null(x1); bn_null(tmp1); bn_null(tmp2);
	bn_new(e); bn_new(k); bn_new(x1); bn_new(tmp1); bn_new(tmp2);
	ep_t kG;
	ep_null(kG);
	ep_new(kG);
	// 计算消息msg的哈希
	hash2bn(e, msg, mlen);
	while (1)
	{
		// 随机选取k in [1, n - 1]
		bn_rand_mod(k, N_1);
		bn_add_dig(k, k, 1);
		// 计算[k]G = (x1, y1)
		ep_mul_gen(kG, k);
		// 记录[k]G和它的y坐标奇偶位
		ep_copy(K, kG);
		// 这里y坐标使用fp_t形式，在内存中可能会用别的形式存储，需要转换成bn_t形式，再取奇偶位
		bn_t y;
		bn_null(y);
		bn_new(y);
		fp_prime_back(y, kG->y);
		*LSB_y = bn_get_bit(y, 0);
		bn_free(y);
		// 计算r = (e + x1) mod n
		fp_prime_back(x1, kG->x);
		bn_add(sig->r, e, x1);
		bn_mod(sig->r, sig->r, N);
		// 若r = 0或r + k = n，进行下一次循环
		bn_add(tmp1, sig->r, k);
		if (bn_is_zero(sig->r) || bn_cmp(tmp1, N) == RLC_EQ)
			continue;
		// s = ((1 + d)^-1 (k - r * d)) mod N
		bn_add_dig(tmp1, kp->d, 1);
		bn_mod_inv(tmp1, tmp1, N);
		bn_mul(tmp2, sig->r, kp->d);
		bn_mod(tmp2, tmp2, N);
		bn_sub(tmp2, k, tmp2);
		bn_mod(tmp2, tmp2, N);
		bn_mul(sig->s, tmp1, tmp2);
		bn_mod(sig->s, sig->s, N);
		if (bn_is_zero(sig->s))
			continue;
		// 若正常执行则跳出循环
		break;
	}
	// 释放变量
	bn_free(e); bn_free(k); bn_free(x1); bn_free(tmp1); bn_free(tmp2);
	ep_free(kG);
}

int sm2_verify(SM2Sign_t *sig, ep_t P, uint8_t *msg, int mlen)
{
	int flag = 0;
	bn_t e, x1, t, R;
	bn_null(e); bn_null(x1); bn_null(t); bn_null(R);
	bn_new(e); bn_new(x1); bn_new(t); bn_new(R);
	ep_t kG, tmpp;
	ep_null(kG); ep_null(tmpp);
	ep_new(kG); ep_new(tmpp);
	// 计算消息msg的哈希
	hash2bn(e, msg, mlen);
	// t = r + s mod n
	bn_add(t, sig->r, sig->s);
	bn_mod(t, t, N);
	// 计算[k]G = [s]G + [t]P = (x1, y1)
	ep_mul_basic(kG, P, t);
	ep_mul_gen(tmpp, sig->s);
	ep_add_basic(kG, kG, tmpp);
	// 计算R = (e + x1) mod n
	fp_prime_back(x1, kG->x);
	bn_add(R, e, x1);
	bn_mod(R, R, N);
	// 验证R==r,若验证通过返回1否则返回0
	if (bn_cmp(R, sig->r) == 0)
		flag = 1;
	bn_free(e); bn_free(x1); bn_free(t); bn_free(R);
	ep_free(kG); ep_free(tmpp);
	return flag;
}

void upk_point(ep_t p, fp_t x, int LSB_y)
{
	uint8_t temp[33];
	fp_write_bin(&temp[1], 32, x);
	temp[0] = LSB_y == 0 ? 2 : 3;
	ep_read_bin(p, temp, 33);
	bn_t y;
	bn_null(y);
	bn_new(y);
	fp_prime_back(y, p->y);
	// 这里不知道为什么有的时候会转换出错，需要重新检查一次
	if (bn_get_bit(y, 0) != LSB_y)
	{
		fp_neg(p->y, p->y);
	}
	bn_free(y);
}