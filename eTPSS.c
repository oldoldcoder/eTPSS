// Implement eTPSS using C language and OPENSSL library
/*
@author:heqi
@time:2024/01/17
@desc:Definition of constants, operations, and header files
*/

#include <openssl/bn.h>

#include "include/eTPSS.h"

#include <stdlib.h>

/*------------------------*/
// mod值
BIGNUM * MOD = NULL;
// 全局ctx
BN_CTX * CTX;
// 随机数序列
static BIGNUM * rand_array[3];
int initialize_Constant() {
    CTX = BN_CTX_new();
    BN_CTX_start(CTX);
    MOD = BN_CTX_get(CTX);
    if (MOD) {
        BIGNUM * n = BN_new();
        BN_set_word(n , N);
        BN_set_word(MOD, 2);
        BN_exp(MOD, MOD, n, CTX); // 计算 2 的 n 次方，并将结果存储在 result 中
        BN_free(n);
    } else {
       return BN_ERROR;
    }
    return BN_SUCCESS;
}
static void free_array(){
    BN_free(rand_array[0]);
    BN_free(rand_array[1]);
    BN_free(rand_array[2]);
}
static int generate_array(){
    BIGNUM * a = BN_new();
    BIGNUM * b = BN_new();
    BIGNUM * c = BN_new();

    if(!BN_rand_range(a,MOD) ||
    !BN_rand_range(b,MOD) ||
    !BN_rand_range(c,MOD)){
        free_array();
        return BN_ERROR;
    }
    rand_array[0] = a;
    rand_array[1] = b;
    rand_array[2] = c;
    return BN_SUCCESS;
}
static void et_refresh_x(eTPSS * a){

    BN_mod_add(a->CS1.x,a->CS1.x,a->CS1.r1,MOD,CTX);
    BN_mod_sub(a->CS1.x,a->CS1.x,a->CS1.r2,MOD,CTX);

    BN_mod_add(a->CS2.x,a->CS2.x,a->CS2.r1,MOD,CTX);
    BN_mod_sub(a->CS2.x,a->CS2.x,a->CS2.r2,MOD,CTX);

    BN_mod_add(a->CS3.x,a->CS3.x,a->CS3.r1,MOD,CTX);
    BN_mod_sub(a->CS3.x,a->CS3.x,a->CS3.r2,MOD,CTX);
}

int init_eTPSS(eTPSS * var){

    var->ctx = BN_CTX_new();
    if(var->ctx == NULL){
        return BN_ERROR;
    }
    BN_CTX_start(var->ctx);
    // 初始化设定不是通过乘法获得
    var->is_multi_res = 0;
    var->CS1.r1 = BN_CTX_get(var->ctx);
    var->CS1.r2 = BN_CTX_get(var->ctx);
    var->CS1.x = BN_CTX_get(var->ctx);

    var->CS2.r1 = BN_CTX_get(var->ctx);
    var->CS2.r2 = BN_CTX_get(var->ctx);
    var->CS2.x = BN_CTX_get(var->ctx);

    var->CS3.r1 = BN_CTX_get(var->ctx);
    var->CS3.r2 = BN_CTX_get(var->ctx);
    var->CS3.x = BN_CTX_get(var->ctx);
    return BN_SUCCESS;

}
int free_eTPSS(eTPSS * var){
    BN_CTX_end(var->ctx);
    BN_CTX_free(var->ctx);
}

int et_Share(eTPSS * var,BIGNUM * num){
    int ret = 1;
    BIGNUM * tmp = BN_new();
    BN_copy(tmp,num);
    BIGNUM * split1 = var->CS1.x;
    BIGNUM * split2 = var->CS2.x;
    BIGNUM * split3 = var->CS3.x;
    if(!BN_nnmod(num,num,MOD,CTX)){
        goto end;
    }
    // 第一次随机分割
    if(!BN_rand_range(split1,tmp)){
        fprintf(stderr,"process of split have some trouble");
        goto end;
    }

    BN_sub(tmp,tmp,split1);
    // 第二次随机分割
    if(!BN_rand_range(split2,tmp)){
        fprintf(stderr,"process of split have some trouble");
        goto end;
    }

    BN_sub(tmp,tmp,split2);
    BN_copy(split3,tmp);

    // TODO 验证分割的正确性
    BN_add(tmp,split1,split2);
    BN_add(tmp,tmp,split3);
    if(BN_cmp(tmp,num) != 0){
        fprintf(stderr,"result of split is not equal original value");
        goto end;
    }
    ret = 0;
end:
    BN_free(tmp);
    return ret == 1? ETPSS_ERROR:ETPSS_SUCCESS;
}

int et_Recover(BIGNUM *num,eTPSS *var){
    int ret = 1;
    BIGNUM * tmp = BN_new();
    BIGNUM * halfMod = BN_new();
    BN_copy(halfMod,MOD);
    BN_div_word(halfMod,2);
    BN_mod_add(tmp,var->CS1.x,var->CS2.x,MOD,CTX);
    BN_mod_add(tmp,tmp,var->CS3.x,MOD,CTX);
    if(BN_cmp(tmp,halfMod) >= 0){
        if(! BN_sub(num, tmp,halfMod))
            goto end;
    }else{
        BN_copy(num,tmp);
    }
    ret = 0;
end:
    BN_free(tmp);
    BN_free(halfMod);
    return ret == 1? ETPSS_ERROR:ETPSS_SUCCESS;
}

int et_Add(eTPSS *res,eTPSS * a,eTPSS *b){

    if(!BN_mod_add(res->CS1.x,a->CS1.x,b->CS1.x,MOD,CTX) ||
    !BN_mod_add(res->CS2.x,a->CS2.x,b->CS2.x,MOD,CTX) ||
    !BN_mod_add(res->CS3.x,a->CS3.x,b->CS3.x,MOD,CTX)){
        return ETPSS_ERROR;
    }
    return ETPSS_SUCCESS;
}

int et_ScalP(eTPSS *res,eTPSS *var,BIGNUM *num){
    if(!BN_mod_mul(res->CS1.x,var->CS1.x,num,MOD,CTX) ||
    !BN_mod_mul(res->CS2.x,var->CS2.x,num,MOD,CTX) ||
    !BN_mod_mul(res->CS3.x,var->CS3.x,num,MOD,CTX)){
        return ETPSS_ERROR;
    }
    return ETPSS_SUCCESS;
}

int et_Mul(eTPSS *res,eTPSS *a,eTPSS *b){
    if(a->is_multi_res == 1){
        // 生成随机序列
        generate_array();
        a->CS1.r1 = rand_array[0];
        a->CS1.r2 = rand_array[2];

        a->CS2.r1 = rand_array[1];
        a->CS2.r2 = rand_array[0];

        a->CS3.r1 = rand_array[2];
        a->CS3.r2 = rand_array[1];
        // 通过r扰动刷新x的值
        et_refresh_x(a);
        free_array();
    }
    if(b->is_multi_res == 1){
        // 生成随机序列
        generate_array();
        b->CS1.r1 = rand_array[0];
        b->CS1.r2 = rand_array[2];

        b->CS2.r1 = rand_array[1];
        b->CS2.r2 = rand_array[0];

        b->CS3.r1 = rand_array[2];
        b->CS3.r2 = rand_array[1];
        // 通过r扰动刷新x的值
        et_refresh_x(b);
        free_array();
    }
    BIGNUM  * z1 = res->CS1.x;
    BIGNUM  * z2 = res->CS2.x;
    BIGNUM  * z3 = res->CS3.x;
    BIGNUM  * t1 = BN_new();
    BIGNUM  * t2 = BN_new();
    BIGNUM  * t3 = BN_new();
    /*---计算z1---*/
    BN_mod_mul(t1,a->CS1.x,b->CS1.x,MOD,CTX);
    BN_mod_mul(t2,a->CS2.x,b->CS1.x,MOD,CTX);
    BN_mod_mul(t3,a->CS1.x,b->CS2.x,MOD,CTX);
    BN_mod_add(t1,t1,t2,MOD,CTX);
    BN_mod_add(z1,t1,t3,MOD,CTX);
    /*---计算z2---*/
    BN_mod_mul(t1,a->CS2.x,b->CS2.x,MOD,CTX);
    BN_mod_mul(t2,a->CS3.x,b->CS2.x,MOD,CTX);
    BN_mod_mul(t3,a->CS2.x,b->CS3.x,MOD,CTX);
    BN_mod_add(t1,t1,t2,MOD,CTX);
    BN_mod_add(z2,t1,t3,MOD,CTX);
    /*---计算z3---*/
    BN_mod_mul(t1,a->CS3.x,b->CS3.x,MOD,CTX);
    BN_mod_mul(t2,a->CS1.x,b->CS3.x,MOD,CTX);
    BN_mod_mul(t3,a->CS3.x,b->CS1.x,MOD,CTX);
    BN_mod_add(t1,t1,t2,MOD,CTX);
    BN_mod_add(z3,t1,t3,MOD,CTX);

    // 通过相乘得到的值
    res->is_multi_res = 1;

    BN_free(t1);
    BN_free(t2);
    BN_free(t3);
    return ETPSS_SUCCESS;
}

void free_BN_CTX(){
    BN_CTX_end(CTX);
    BN_CTX_free(CTX);
}