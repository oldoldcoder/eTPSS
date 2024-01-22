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
BIGNUM * RANDOM_RANGE = NULL;
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

        BN_set_word(n,random_bits);
        BN_set_word(RANDOM_RANGE, 2);
        BN_exp(RANDOM_RANGE, RANDOM_RANGE, n, CTX); // 计算 2 的 n 次方，并将结果存储在 result 中

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

    // 判断负值然后刷新
    int neg_flag = 0;

    BN_add(a->CS1.x,a->CS1.x,a->CS1.r1);
    if(BN_is_negative(a->CS1.x))
        neg_flag = 1;
    BN_set_negative(a->CS1.x,0);
    BN_nnmod(a->CS1.x,a->CS1.x,MOD,CTX);
    BN_set_negative(a->CS1.x,neg_flag);


    BN_sub(a->CS1.x,a->CS1.x,a->CS1.r2);
    neg_flag = 0;
    if(BN_is_negative(a->CS1.x))
        neg_flag = 1;
    BN_set_negative(a->CS1.x,0);
    BN_nnmod(a->CS1.x,a->CS1.x,MOD,CTX);
    BN_set_negative(a->CS1.x,neg_flag);

    neg_flag = 0;

    BN_add(a->CS2.x,a->CS2.x,a->CS2.r1);
    if(BN_is_negative(a->CS2.x))
        neg_flag = 1;
    BN_set_negative(a->CS2.x,0);
    BN_nnmod(a->CS2.x,a->CS2.x,MOD,CTX);
    BN_set_negative(a->CS2.x,neg_flag);

    BN_sub(a->CS2.x,a->CS2.x,a->CS2.r2);
    neg_flag = 0;
    if(BN_is_negative(a->CS2.x))
        neg_flag = 1;
    BN_set_negative(a->CS2.x,0);
    BN_nnmod(a->CS2.x,a->CS2.x,MOD,CTX);
    BN_set_negative(a->CS2.x,neg_flag);

    neg_flag = 0;

    BN_add(a->CS3.x,a->CS3.x,a->CS3.r1);
    if(BN_is_negative(a->CS3.x))
        neg_flag = 1;
    BN_set_negative(a->CS3.x,0);
    BN_nnmod(a->CS3.x,a->CS3.x,MOD,CTX);
    BN_set_negative(a->CS3.x,neg_flag);

    BN_sub(a->CS3.x,a->CS3.x,a->CS3.r2);
    neg_flag = 0;
    if(BN_is_negative(a->CS3.x))
        neg_flag = 1;
    BN_set_negative(a->CS3.x,0);
    BN_nnmod(a->CS3.x,a->CS3.x,MOD,CTX);
    BN_set_negative(a->CS3.x,neg_flag);
    neg_flag = 0;
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
    // num是否是负数
    int neg_flag = 0;
    BIGNUM * tmp = BN_new();
    if(BN_is_negative(num))
        neg_flag = 1;
    BIGNUM * split1 = var->CS1.x;
    BIGNUM * split2 = var->CS2.x;
    BIGNUM * split3 = var->CS3.x;
    BN_set_negative(num,0);
    if(!BN_nnmod(num,num,MOD,CTX)){
        goto end;
    }
    BN_copy(tmp,num);
    BN_set_negative(num,neg_flag == 1?1:0);

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
    BN_set_negative(split1,neg_flag);
    BN_set_negative(split2,neg_flag);
    BN_set_negative(split3,neg_flag);
    ret = 0;
end:
    BN_free(tmp);
    return ret == 1? ETPSS_ERROR:ETPSS_SUCCESS;
}

int et_Recover(BIGNUM *num,eTPSS *var){
    int ret = 1;
    int neg_flag = 0;

    BIGNUM * tmp = BN_new();
    BIGNUM * halfMod = BN_new();
    BN_copy(halfMod,MOD);
    BN_div_word(halfMod,2);
    // 设置负值

    BN_add(tmp,var->CS1.x,var->CS2.x);
    if(BN_is_negative(tmp))
        neg_flag = 1;
    BN_set_negative(tmp,0);
    BN_nnmod(tmp,tmp,MOD,CTX);
    BN_set_negative(tmp,neg_flag);

    neg_flag = 0;
    BN_add(tmp,tmp,var->CS3.x);
    if(BN_is_negative(tmp))
        neg_flag = 1;
    BN_set_negative(tmp,0);
    BN_nnmod(tmp,tmp,MOD,CTX);
    BN_set_negative(tmp,neg_flag);


    if(neg_flag == 0 && BN_cmp(tmp,halfMod) >= 0){
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

    int neg_flag[3] = {0};
    if(!BN_add(res->CS1.x,a->CS1.x,b->CS1.x) ||
    !BN_add(res->CS2.x,a->CS2.x,b->CS2.x) ||
    !BN_add(res->CS3.x,a->CS3.x,b->CS3.x)){
        return ETPSS_ERROR;
    }
    if(BN_is_negative(res->CS1.x))
        neg_flag[0] = 1;
    if(BN_is_negative(res->CS2.x))
        neg_flag[1] = 1;
    if(BN_is_negative(res->CS3.x))
        neg_flag[2] = 1;
    BN_set_negative(res->CS1.x,0);
    BN_set_negative(res->CS2.x,0);
    BN_set_negative(res->CS3.x,0);
    BN_nnmod(res->CS1.x,res->CS1.x,MOD,CTX);
    BN_nnmod(res->CS2.x,res->CS2.x,MOD,CTX);
    BN_nnmod(res->CS3.x,res->CS3.x,MOD,CTX);

    BN_set_negative(res->CS1.x,neg_flag[0]);
    BN_set_negative(res->CS2.x,neg_flag[1]);
    BN_set_negative(res->CS3.x,neg_flag[2]);
    return ETPSS_SUCCESS;
}

int et_ScalP(eTPSS *res,eTPSS *var,BIGNUM *num){
    int neg_flag[3] = {0};
    if(!BN_mul(res->CS1.x,var->CS1.x,num,CTX) ||
       !BN_mul(res->CS2.x,var->CS2.x,num,CTX) ||
       !BN_mul(res->CS3.x,var->CS3.x,num,CTX)){
        return ETPSS_ERROR;
    }
    if(BN_is_negative(res->CS1.x))
        neg_flag[0] = 1;
    if(BN_is_negative(res->CS2.x))
        neg_flag[1] = 1;
    if(BN_is_negative(res->CS3.x))
        neg_flag[2] = 1;
    BN_set_negative(res->CS1.x,0);
    BN_set_negative(res->CS2.x,0);
    BN_set_negative(res->CS3.x,0);
    BN_nnmod(res->CS1.x,res->CS1.x,MOD,CTX);
    BN_nnmod(res->CS2.x,res->CS2.x,MOD,CTX);
    BN_nnmod(res->CS3.x,res->CS3.x,MOD,CTX);

    BN_set_negative(res->CS1.x,neg_flag[0]);
    BN_set_negative(res->CS2.x,neg_flag[1]);
    BN_set_negative(res->CS3.x,neg_flag[2]);
    return ETPSS_SUCCESS;
}

int et_Mul(eTPSS *res,eTPSS *a,eTPSS *b){
    int neg_flag = 0;
    BIGNUM * tmp = BN_new();
    et_Recover(tmp,a);

    et_Recover(tmp,b);

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
        et_Recover(tmp,a);
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

    BN_mul(t1,a->CS1.x,b->CS1.x,CTX);

    BN_mul(t2,a->CS2.x,b->CS1.x,CTX);

    BN_mul(t3,a->CS1.x,b->CS2.x,CTX);

    BN_add(t1,t1,t2);
    BN_add(z1,t1,t3);

    if(BN_is_negative(z1))
        neg_flag = 1;
    BN_set_negative(z1,0);
    BN_nnmod(z1,z1,MOD,CTX);
    BN_set_negative(z1,neg_flag);
    /*---计算z2---*/
    BN_mul(t1,a->CS2.x,b->CS2.x,CTX);

    BN_mul(t2,a->CS3.x,b->CS2.x,CTX);

    BN_mul(t3,a->CS2.x,b->CS3.x,CTX);

    BN_add(t1,t1,t2);
    BN_add(z2,t1,t3);

    neg_flag = 0;
    if(BN_is_negative(z2))
        neg_flag = 1;
    BN_set_negative(z2,0);
    BN_nnmod(z2,z2,MOD,CTX);
    BN_set_negative(z2,neg_flag);
    /*---计算z3---*/
    BN_mul(t1,a->CS3.x,b->CS3.x,CTX);

    BN_mul(t2,a->CS1.x,b->CS3.x,CTX);

    BN_mul(t3,a->CS3.x,b->CS1.x,CTX);

    BN_add(t1,t1,t2);
    BN_add(z3,t1,t3);

    neg_flag = 0;
    if(BN_is_negative(z3))
        neg_flag = 1;
    BN_set_negative(z3,0);
    BN_nnmod(z3,z3,MOD,CTX);
    BN_set_negative(z3,neg_flag);
    // 通过相乘得到的值
    res->is_multi_res = 1;

    BN_free(t1);
    BN_free(t2);
    BN_free(t3);

    return ETPSS_SUCCESS;
}
// 判断etpss的符号,赋值给res
int et_judge_symbols(int * res,eTPSS *d1){
    int neg_flag = 0;
    // 随机影响因子默认生成的值是2^64次方内的值
    BIGNUM  * u1 = BN_CTX_get(CTX);
    BIGNUM  * u2 = BN_CTX_get(CTX);
    BIGNUM  * u3 = BN_CTX_get(CTX);
    BIGNUM  * w1 = BN_CTX_get(CTX);
    BIGNUM  * w2 = BN_CTX_get(CTX);

    BIGNUM  * tmp = BN_CTX_get(CTX);
    // 随机扰动值
    BIGNUM  * r1 = BN_CTX_get(CTX);
    BIGNUM  * r2 = BN_CTX_get(CTX);
    BIGNUM  * x1 = d1->CS1.x;
    BIGNUM  * x2 = d1->CS3.x;
    BIGNUM  * x3 = d1->CS3.x;
    BIGNUM  * z1 = BN_CTX_get(CTX);
    BIGNUM  * z2 = BN_CTX_get(CTX);
    BIGNUM  * z3 = BN_CTX_get(CTX);


    if (!BN_rand_range(u1, RANDOM_RANGE)){
        // 报错处理
        fprintf(stderr,"Error in obtaining random values.\n");
        return ETPSS_ERROR;
    }
    if (!BN_rand_range(u2, RANDOM_RANGE)){
        // 报错处理
        fprintf(stderr,"Error in obtaining random values.\n");
        return ETPSS_ERROR;
    }
    // 对于负值的处理
    BN_sub(w1,x1,u1);
    if(BN_is_negative(w1))
    {
        neg_flag = 1;
        BN_set_negative(w1,0);
    }
    BN_nnmod(w1,w1,MOD,CTX);
    BN_set_negative(w1,neg_flag);
    neg_flag = 0;

    BN_sub(w2,x2,u2);
    if(BN_is_negative(w2))
    {
        neg_flag = 1;
        BN_set_negative(w2,0);
    }
    BN_nnmod(w2,w2,MOD,CTX);
    BN_set_negative(w2,neg_flag);
    neg_flag = 0;
    /*--------打包w1，w2发送给CS3-------*/
    BN_add(tmp,w1,w2);
    BN_add(u3,x3,tmp);
    if(BN_is_negative(u3))
    {
        neg_flag = 1;
        BN_set_negative(u3,0);
    }
    BN_nnmod(u3,u3,MOD,CTX);
    BN_set_negative(u3,neg_flag);
    neg_flag = 0;
    BN_sub(u3,u3,MOD);
    // CS1和CS2生成一个共同的随机值r1
    if (!BN_rand_range(r1, RANDOM_RANGE)){

    }
    // CS2和CS3生成一个共同的随机值r2
    if (!BN_rand_range(r2, RANDOM_RANGE)){
        // 报错处理
        fprintf(stderr,"Error in obtaining random values.\n");
        return ETPSS_ERROR;
    }
    // CS1计算u1 + r1
    BN_add(z1,u1,r1);
    // CS_3计算z_3=(z_1+u_3 )*α
    BN_add(z1,z1,u3);
    BN_mul(z3,z1,r2,CTX);
    // CS_2计算z_2=(u_2-r)*α
    BN_sub(tmp,u2,r1);
    BN_mul(z2,tmp,r2,CTX);
    /*-----------第四步-----------*/
    int y = -1;
    BN_add(tmp,z2,z3);
    if(BN_is_zero(tmp)){
        // 报告x等于0
        *res = -1;
    }

    if(BN_is_negative(tmp)){
        y = 1;
    }else{
        y = 0;
    }
    if(BN_is_negative(r2)){
        *res = y ^ 1;
    }else{
        *res = y ^ 0;
    }

    return ETPSS_SUCCESS;
}

int et_Sub(int *ret,eTPSS *d1,eTPSS *d2){
    int neg_flag = 0;
    eTPSS t;
    eTPSS res;
    init_eTPSS(&t);
    init_eTPSS(&res);
    // 符号取反
    t.CS1.x = d2->CS1.x;
    BN_set_negative(t.CS1.x,BN_is_negative(t.CS1.x) ^ 1);
    t.CS2.x = d2->CS2.x;
    BN_set_negative(t.CS2.x,BN_is_negative(t.CS2.x) ^ 1);
    t.CS3.x = d2->CS3.x;
    BN_set_negative(t.CS3.x,BN_is_negative(t.CS3.x) ^ 1);
    if(et_Add(&res,d1,&t) != ETPSS_SUCCESS){
        return ETPSS_ERROR;
    }
    if(et_judge_symbols(ret,&res) != ETPSS_SUCCESS){
        return ETPSS_ERROR;
    }
    return ETPSS_SUCCESS;
}

void free_BN_CTX(){
    BN_CTX_end(CTX);
    BN_CTX_free(CTX);
}

