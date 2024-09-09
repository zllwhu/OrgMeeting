#include "global.h"

using namespace std;

/* global variables of OpenSSL */
EC_GROUP *group = nullptr;
const BIGNUM *order = nullptr;
const EC_POINT *generator = nullptr;
BN_CTX *bn_ctx = nullptr;

BIGNUM *BN_0 = nullptr;
BIGNUM *BN_1 = nullptr;
BIGNUM *BN_2 = nullptr;

/* initialize global variables */
bool global_initialize(int curve_id)
{
#ifdef DEBUG
    cout << "initialize global environment" << endl;
#endif
    group = EC_GROUP_new_by_curve_name(curve_id);
    generator = EC_GROUP_get0_generator(group);
    order = EC_GROUP_get0_order(group);
    bn_ctx = BN_CTX_new();
    if (group == NULL || order == NULL || bn_ctx == NULL) return false;
    // EC_GROUP_precompute_mult((EC_GROUP *)group, bn_ctx); // pre-compute the table of g     

#ifdef DEBUG
    if (EC_GROUP_have_precompute_mult((EC_GROUP *)group))
    {
        cout << "precompute enable" << endl;
    }
    else
    {
        cout << "precompute disable" << endl;
    }
#endif

    BN_0 = BN_new();
    BN_zero(BN_0); // set bn_0 = 0
    BN_1 = BN_new();
    BN_one(BN_1); // set bn_1 = 1
    BN_2 = BN_new();
    BN_set_word(BN_2, 2); // set bn_2 = 2
    if (BN_0 == NULL || BN_1 == NULL || BN_2 == NULL) return false;

    return true;
}

/* finalize global variables */
void global_finalize()
{
#ifdef DEBUG
    cout << "finalize global environment" << endl;
#endif
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);

    BN_free(BN_0);
    BN_free(BN_1);
    BN_free(BN_2);
}



