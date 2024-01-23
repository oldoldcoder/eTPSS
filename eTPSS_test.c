#include <openssl/bn.h>

#include "include/eTPSS.h"

#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv){
    // 创建实例
    initialize_Constant();
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *t1,*t2,*t3;

    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    t3 = BN_CTX_get(ctx);

    eTPSS a,b,c;
    init_eTPSS(&a);
    init_eTPSS(&b);
    init_eTPSS(&c);
    /*-------Share---------*/
    BN_set_word(t1,2221);
    //BN_set_negative(t1,1);
    BN_set_word(t2,2222);

    if(et_Share(&a,t1) != ETPSS_SUCCESS){
        fprintf(stderr,"error in Share operation\n");
    }
    char *x1 = BN_bn2dec(a.CS1.x);
    char *x2 = BN_bn2dec(a.CS2.x);
    char *x3 = BN_bn2dec(a.CS3.x);
    char *str1 = BN_bn2dec(t1);
    fprintf(stdout,"[A]-->total:%s, x1:%s, x2:%s, x3:%s\n",str1,x1,x2,x3);
    fflush(stdout);  // 刷新标准输出流
    et_Share(&b,t2);
    x1 = BN_bn2dec(b.CS1.x);
    x2 = BN_bn2dec(b.CS2.x);
    x3 = BN_bn2dec(b.CS3.x);
    str1 = BN_bn2dec(t2);
    fprintf(stdout,"[B]-->total:%s, x1:%s, x2:%s, x3:%s\n",str1,x1,x2,x3);
    fflush(stdout);  // 刷新标准输出流
    /*---------Recover---------*/
    if(et_Recover(t3,&a) == ETPSS_ERROR){
        fprintf(stderr,"error in Recover operation");
    }
    x1 = BN_bn2dec(t3);
    str1 = BN_bn2dec(t1);
    fprintf(stdout,"[A = %s]-->Recover value is %s\n",str1,x1);
    fflush(stdout);  // 刷新标准输出流
    et_Recover(t3,&b);
    x1 = BN_bn2dec(t3);
    str1 = BN_bn2dec(t2);
    fprintf(stdout,"[B = %s]-->Recover value is %s\n",str1,x1);
    fflush(stdout);  // 刷新标准输出流
    /*---------Add---------*/
    if(et_Add(&c,&a,&b) == ETPSS_ERROR){
        fprintf(stderr,"error in ScalP operation");
    }
    et_Recover(t3,&c);
    x1 = BN_bn2dec(t3);
    str1 = BN_bn2dec(t1);
    char * str2 = BN_bn2dec(t2);
    fprintf(stdout,"[A = %s] + [B = %s] = C-->Recover value is %s\n",str1,str2,x1);
    fflush(stdout);  // 刷新标准输出流

    /*---------Sub---------*/
    int ret = -9999;
    if(et_Sub(&ret,&a,&b) != ETPSS_SUCCESS){
        fprintf(stderr,"error in Sub operation");
    }
    if(ret == 0){
        printf("a > b\n");
    }else if(ret == 1){
        printf("a < b\n");
    }else if(ret == -1){
        printf("a = b\n");
    }
    /*---------ScalP---------*/
    int t3n = 3333;
    BN_set_word(t3,t3n);
    // 3333 * 1111 = 3333 * (x1 + x2 + x3)
    if(et_ScalP(&c,&a,t3) == ETPSS_ERROR){
        fprintf(stderr,"error in ScalP operation");
    }
    et_Recover(t3,&c);
    x1 = BN_bn2dec(t3);

    fprintf(stdout,"%d * [A = -1111] = C-->Recover value is %s\n",t3n,x1);
    fflush(stdout);  // 刷新标准输出流
    /*---------et_Mul-----------*/
    if(et_Mul(&c,&a,&b) == ETPSS_ERROR){
        fprintf(stderr,"error in mul operation");
    }
    et_Recover(t3,&c);
    x1 = BN_bn2dec(t3);
    fprintf(stdout,"[A = -1111] * [B = 2222] = C-->Recover value is %s\n",x1);
    fflush(stdout);  // 刷新标准输出流
    if(et_Mul(&a,&c,&b)== ETPSS_ERROR){
        fprintf(stderr,"error in mul operation");
    }
    et_Recover(t3,&a);
    x1 = BN_bn2dec(t3);
    fprintf(stdout,"[C = [A] * [B]] * [B = 2222] = C-->Recover value is %s\n",x1);
    fflush(stdout);  // 刷新标准输出流
    if(et_Mul(&b,&a,&c) == ETPSS_ERROR){
        fprintf(stderr,"error in mul operation");
    }
    et_Recover(t3,&b);
    x1 = BN_bn2dec(t3);
    fprintf(stdout,"[C = [A] * [B]] * [A = [C = [A] * [B]] * [B]] = C-->Recover value is %s\n",x1);
    fflush(stdout);  // 刷新标准输出流
    /*---------------------*/
    free_eTPSS(&a);
    free_eTPSS(&b);
    free_eTPSS(&c);
    // 释放上下文中的CTX
    free_BN_CTX();
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

}