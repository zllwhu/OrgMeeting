#ifndef SCHEME2_H
#define SCHEME2_H

#include "common.h"
#include "sm2.h"
#include "util.h"
#include "twisted_elgamal.h"
#include "rangeproof.h"

/**
 * 方案二：基于Twisted ElGamal加密的SM2签名判定的可验证加密方案
*/

typedef struct
{
	// 签名过程中[k]G的y坐标奇偶位，以便后续从x坐标恢复[k]G
	int lsb_y;
	bn_t r;
	// C = (Ui, Vi)_{i=0} ^ {l-1}
	ep_t C[8][2];
	// 离散对数零知识证明
	bn_t c;
	bn_t z1;
	bn_t z2;
	// Bulletproof证明存储在bf.bin文件中
	char *bf;
}CipherText_st;

/**
 * @brief 初始化方案2密文
 */
void init_CipherText(CipherText_st *ct);

/**
 * @brief 释放方案2密文
*/
void free_CipherText(CipherText_st *ct);

/**
 * @brief 可验证加密算法（基于Twisted ElGamal加密的SM2签名判定的可验证加密方案）
 * @param[out] ct 生成的密文
 * @param[in] sig_kp SM2签名密钥对
 * @param[in] T Twisted ElGamal公钥
 * @param[in] msg 消息
 * @param[in] mlen 消息字节长度
 */
void veriableEnc(CipherText_st *ct, SM2KeyPair_t *sig_kp, ep_t T, uint8_t *msg, int mlen);

/**
 * @brief 加密验证算法（基于Twisted ElGamal加密的SM2签名判定的可验证加密方案）
 * @param[in] ct 密文
 * @param[in] sig_pk SM2签名公钥
 * @param[in] T Twisted ElGamal公钥
 * @param[in] msg 消息
 * @param[in] mlen 消息字节长度
 * @return 1 验证通过; 0 验证失败
 */
int verify(CipherText_st *ct, ep_t sig_pk, ep_t T, uint8_t *msg, int mlen);

/**
 * @brief 可验证解密算法（基于Twisted ElGamal加密的SM2签名判定的可验证加密方案）
 * @param[in] table 预计算表(使用Shank算法求解ECDLP问题)
 * @param[out] sig 恢复出的SM2签名值
 * @param[in] ct 密文
 * @param[in] t Twisted ElGamal私钥
 */
void veriableDec(const PRE_COMPUTE_TABLE table[1 << 16], SM2Sign_t *sig, CipherText_st *ct, bn_t t);

void testScheme2();

#endif