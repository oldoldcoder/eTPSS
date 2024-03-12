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
#define random_bits 64
#define SEED 0xDEADBEEF
#define ETPSS_ERROR -180607
#define ETPSS_SUCCESS -180608
#define BN_ERROR -011013
#define BN_SUCCESS -011012
/*-----------------------------------*/

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
    // 标记是否是通过乘法获得
    u_char is_multi_res;
} eTPSS;
extern BIGNUM * MOD;
extern BN_CTX * CTX;
extern BIGNUM * RANDOM_RANGE;
extern BIGNUM * ZERO;
extern BIGNUM * ONE;
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
 * @param res:乘法结果,注意这个算法的res目前不能和a或者b为同一个指针，a与b为同一个指针暂时未发现问题
 * */
int et_Mul(eTPSS *res,eTPSS *a,eTPSS *b);
/*
 * @desc:eTPSS在不Recover情况下判断加密数据符号
 * @param res:结果，res = 0 表示 d1是大于0,res = 1表示d1是小于0，res = -1表示d1等于0
 * */
int et_judge_symbols(int * res,eTPSS *d1);
/*
 * @desc:eTPSS的减法操作
 * @param res:结果，res = 0 表示 d1 大于 d2,res = 1表示d1小于d2，res = -1表示d1等于d2
 * */
int et_Sub(int *ret,eTPSS *d1,eTPSS *d2);
/*
 * @desc:eTPSS的复制操作
 * */
void et_Copy(eTPSS *to,eTPSS * from);

// 计算加密数据与普通数据之间的距离
// res是返回的[distance]
int et_Sub_cal_res(eTPSS * res,eTPSS * d1,BIGNUM * d2);

int et_Sub_cal_res_o(eTPSS * res,eTPSS * d1,eTPSS * d2);
#endif