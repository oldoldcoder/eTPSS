// Implement eTPSS using C language and OPENSSL library
/*
@author:heqi
@time:2024/01/17
@desc:Definition of constants, operations, and header files
*/
#ifndef E_TPASS_H
#define E_TPASS_H
#include <openssl/bn.h>

#include <stdint.h>
#include <stdlib.h>
/*---------define constant-----------*/
#define N 64
#define SEED 0xDEADBEEF
#define ETPSS_ERROR -180607
#define ETPSS_SUCCESS -180608
#define BN_ERROR -011013
#define BN_SUCCESS -011012
/*-----------------------------------*/
extern BIGNUM * MOD;
extern BN_CTX * CTX;
// 定义cli的结构
typedef struct {
    BIGNUM *x;
    // 两个扰动
    BIGNUM *r1;
    BIGNUM *r2;
} cli;
// 定义eTPSS的结构
typedef struct {
    cli CS1;
    cli CS2;
    cli CS3;
    BN_CTX * ctx;
    u_char is_multi_res;
} eTPSS;

/*
 * @desc:初始化MOD的值
 * */
int initialize_Constant();
/*
 * @desc:释放全局的CTX值
 * */
void free_BN_CTX();
/*
 * @desc:为eTPSS初始化分配空间
 * @param var:初始化的量
 * */
int init_eTPSS(eTPSS * var);

/*
 * @desc:释放空间
 * @param var:释放的量
 * */
int free_eTPSS(eTPSS * var);

/*
 * @desc:x1 + x2 + x3 = (num mod 2^n),三者在整数域内
 * @param var:得到值被分配的eTPSS
 * num:大数
 * */
int et_Share(eTPSS * var,BIGNUM * num);

/*
 * @desc:恢复x的值
 * @param num:被恢复的大数
 * var:已知的eTPSS值
 * */
int et_Recover(BIGNUM *num,eTPSS *var);

/*
 * @desc:eTPSS加法
 * @param res:加法结果
 * */
int et_Add(eTPSS *res,eTPSS * a,eTPSS *b);

/*
 * @desc:eTPSS标量乘法
 * @param res:标量乘法结果
 * */
int et_ScalP(eTPSS *res,eTPSS *var,BIGNUM * num);

/*
 * @desc:eTPSS乘法
 * @param res:乘法结果
 * */
int et_Mul(eTPSS *res,eTPSS *a,eTPSS *b);

#endif