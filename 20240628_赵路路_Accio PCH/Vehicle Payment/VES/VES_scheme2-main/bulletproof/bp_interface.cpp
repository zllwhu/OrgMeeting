#include "global.h"
#include "print.h"
#include "hash.h"
#include "routines.h"
#include "innerproduct_proof.h"
#include "aggregate_bulletproof.h"
#include "bp_interface.h"

void rangeP(size_t range_len, size_t agg_num, uint8_t *g1x, uint8_t g1y, uint32_t *s_arr, uint8_t *rho_l, char *bf_file)
{
    Bullet_PP pp;
    Bullet_PP_new(pp, range_len, agg_num);
    Bullet_Setup(pp, range_len, agg_num, g1x, g1y);

    Bullet_Witness witness;
    Bullet_Witness_new(pp, witness);
    for (int i = 0; i < pp.AGG_NUM; i++)
    {
        BN_bin2bn(rho_l + i * 32, 32, witness.r[i]);
        BN_set_word(witness.v[i], s_arr[i]);
    }

    Bullet_Instance instance;
    Bullet_Instance_new(pp, instance);
    EC_POINT *tmpp1 = EC_POINT_new(group), *tmpp2 = EC_POINT_new(group);

    for (int i = 0; i < pp.AGG_NUM; i++)
    {
        // EC_POINT_mul(group, tmpp1, NULL, pp.g, witness.r[i], bn_ctx);
        // EC_POINT_mul(group, tmpp2, NULL, pp.h, witness.v[i], bn_ctx);
        // EC_POINT_add(group, instance.C[i], tmpp1, tmpp2, bn_ctx);
        EC_POINT_mul(group, instance.C[i], witness.r[i], pp.h, witness.v[i], bn_ctx);
    }

    Bullet_Proof proof;
    Bullet_Proof_new(proof);
    string str = "";
    Bullet_Prove(pp, instance, witness, str, proof);

    // ofstream fout("bf.bin", ios::binary | ios::trunc);
    ofstream fout(bf_file, ios::binary);
    Bullet_Proof_serialize(proof, fout);
    fout.close();

    Bullet_PP_free(pp);
    Bullet_Witness_free(witness);
    Bullet_Instance_free(instance);
    EC_POINT_free(tmpp1);
    EC_POINT_free(tmpp2);
    Bullet_Proof_free(proof);
}

int rangeV(size_t range_len, size_t agg_num, uint8_t *g1x, uint8_t g1y, uint8_t *u_l, char *bf_file)
{
    Bullet_PP pp;
    Bullet_PP_new(pp, range_len, agg_num);
    Bullet_Setup(pp, range_len, agg_num, g1x, g1y);

    Bullet_Instance instance;
    Bullet_Instance_new(pp, instance);

    BIGNUM *X = BN_new();
    for (int i = 0; i < agg_num; i++)
    {
        BN_bin2bn(u_l + i * 33 + 1, 32, X);
        EC_POINT_set_compressed_coordinates(group, instance.C[i], X, u_l[i * 33], bn_ctx);
    }

    size_t ip_vec_len = log2(range_len) + log2(agg_num);
    Bullet_Proof proof;
    Bullet_Proof_new(proof);
    proof.ip_proof.vec_L.resize(ip_vec_len); ECP_vec_new(proof.ip_proof.vec_L);
    proof.ip_proof.vec_R.resize(ip_vec_len); ECP_vec_new(proof.ip_proof.vec_R);
    ifstream fin(bf_file, ios::binary);
    Bullet_Proof_deserialize(proof, fin);
    fin.close();

    string str = "";
    bool flag = Bullet_Verify(pp, instance, str, proof);

    Bullet_PP_free(pp);
    Bullet_Instance_free(instance);
    Bullet_Proof_free(proof);
    BN_free(X);

    return (flag == true) ? 1 : 0;
}

void call_print(size_t range_len, size_t agg_num, char *bf_file)
{
    size_t ip_vec_len = log2(range_len) + log2(agg_num);
    printf("in %d\n", ip_vec_len);
    Bullet_Proof proof;
    Bullet_Proof_new(proof);
    proof.ip_proof.vec_L.resize(ip_vec_len); ECP_vec_new(proof.ip_proof.vec_L);
    proof.ip_proof.vec_R.resize(ip_vec_len); ECP_vec_new(proof.ip_proof.vec_R);
    ifstream fin(bf_file, ios::binary);
    Bullet_Proof_deserialize(proof, fin);
    fin.close();
    Bullet_Proof_print(proof);
    Bullet_Proof_free(proof);
}

extern "C" {

    void call_rangeprove(size_t range_len, size_t agg_num, uint8_t *g1x, uint8_t g1y, uint32_t *s_arr, uint8_t *rho_l, char *bf_file)
    {
        global_initialize(NID_sm2);
        rangeP(range_len, agg_num, g1x, g1y, s_arr, rho_l, bf_file);
        global_finalize();
    }

    int call_rangeverify(size_t range_len, size_t agg_num, uint8_t *g1x, uint8_t g1y, uint8_t *u_l, char *bf_file)
    {
        global_initialize(NID_sm2);
        int ret = rangeV(range_len, agg_num, g1x, g1y, u_l, bf_file);
        global_finalize();
        return ret;
    }

    void print_rangeproof(size_t range_len, size_t agg_num, char *bf_file)
    {
        global_initialize(NID_sm2);
        call_print(range_len, agg_num, bf_file);
        global_finalize();
    }

}