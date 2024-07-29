#include <openssl/bn.h>

#include "../include/eTPSS.h"

#include <cstdlib>
#include <cstdio>

int main(int argc, char **argv){
    // 创建实例
    initialize_Constant();

    int64_t t1,t2,t3;

    eTPSS a,b,c;
    init_eTPSS(&a);
    init_eTPSS(&b);
    init_eTPSS(&c);
    /*-------Share---------*/
    t1 = -1111;
    //BN_set_negative(t1,1);
    t2 = -2222;

    if(et_Share(&a,t1) != ETPSS_SUCCESS){
        fprintf(stderr,"error in Share operation\n");
    }
    fprintf(stdout,"[A]-->total:%ld, x1:%ld, x2:%ld, x3:%ld\n",t1,a.CS1.x,a.CS2.x,a.CS3.x);
    et_Share(&b,t2);
    fprintf(stdout,"[B]-->total:%ld, x1:%ld, x2:%ld, x3:%ld\n",t2,b.CS1.x,b.CS2.x,b.CS3.x);
    fflush(stdout);  // 刷新标准输出流

    /*-----------SUB------------*/
    int  rrrr;
    et_Sub(&rrrr,&a,&b);
    if(rrrr == 0){
        printf("a > b\n");
    }else if(rrrr == 1){
        printf("a < b\n");
    }else if(rrrr == -1){
        printf("a = b\n");
    }
    fflush(stdout);
    /*---------Recover---------*/
    if(et_Recover(&t3,&a) == ETPSS_ERROR){
        fprintf(stderr,"error in Recover operation");
    }

    fprintf(stdout,"[A = %ld]-->Recover value is %ld\n",t1,t3);
    fflush(stdout);  // 刷新标准输出流
    et_Recover(&t3,&b);

    fprintf(stdout,"[B = %ld]-->Recover value is %ld\n",t2,t3);
    fflush(stdout);  // 刷新标准输出流
    /*---------Add---------*/
    if(et_Add(&c,&a,&b) == ETPSS_ERROR){
        fprintf(stderr,"error in ScalP operation");
    }
    et_Recover(&t3,&c);

    fprintf(stdout,"[A = %ld] + [B = %ld] = C-->Recover value is %ld\n",t1 , t2,t3);
    fflush(stdout);  // 刷新标准输出流
    printf("------------打印a，b的值----------------\n");
    et_Recover(&t3,&a);
    printf("A --> %ld\n",t3);
    et_Recover(&t3,&b);
    printf("B --> %ld\n",t3);
    printf("--------------------------------------\n");
    /*---------zt---------*/
    int64_t t3n = 3333;
    // 3333 * 1111 = 3333 * (x1 + x2 + x3)
    if(et_ScalP(&c,&a,t3n) == ETPSS_ERROR){
        fprintf(stderr,"error in ScalP operation");
    }
    et_Recover(&t3,&c);

    fprintf(stdout,"%ld * [A = %ld] = C-->Recover value is %ld\n",t3n,t1,t3);
    fflush(stdout);  // 刷新标准输出流

    /*---------et_Mul-----------*/

    et_Recover(&t3,&a);
    printf("%ld\n",t3);

    et_Recover(&t3,&b);
    printf("%ld\n",t3);
    fflush(stdout);

    if(et_Mul(&c,&a,&b) == ETPSS_ERROR){
        fprintf(stderr,"error in mul operation");
    }
    et_Recover(&t3,&c);
    fprintf(stdout,"[A = 1111] * [B = 2222] = C-->Recover value is %ld\n",t3);
    fflush(stdout);  // 刷新标准输出流
    if(et_Mul(&a,&c,&b)== ETPSS_ERROR){
        fprintf(stderr,"error in mul operation");
    }
    et_Recover(&t3,&a);
    fprintf(stdout,"[C = [A] * [B]] * [B = 2222] = C-->Recover value is %ld\n",t3);
    fflush(stdout);  // 刷新标准输出流*/

    if(et_Mul(&c,&a,&b)== ETPSS_ERROR){
        fprintf(stderr,"error in mul operation");
    }
    et_Recover(&t3,&c);
    fprintf(stdout,"[[C = [A] * [B]] * [B = 2222] * B] = C-->Recover value is %ld\n",t3);
    fflush(stdout);  // 刷新标准输出流*/
    /*---------------------*/
    free_eTPSS(&a);
    free_eTPSS(&b);
    free_eTPSS(&c);
    // 释放上下文中的CTX
    free_BN_CTX();

}