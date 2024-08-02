// Implement eTPSS using C language and OPENSSL library
/*
@author:hufei
@time:2024/01/17
@desc:Definition of constants, operations, and header files
*/

#include <openssl/bn.h>

#include "eTPSS.h"
#include "random"
#include <cstdlib>

/*------------------------*/
int64_t MOD = NULL;
BN_CTX* CTX;
int is_init = 0;
BIGNUM* ZERO = NULL;
BIGNUM* ONE = NULL;
static int64_t rand_array[3];

/**getline to solve problem*/

/*size_t getline(char** lineptr, size_t* n, FILE* stream) {

    if (lineptr == NULL || stream == NULL || n == NULL) {
        return -1;
    }

    if (*lineptr == NULL) {
        *n = 1024; // Set initial buffer size to 1024
        *lineptr = (char*)malloc(*n);
        if (*lineptr == NULL) {
            return -1;
        }
    }

    char* bufptr = *lineptr;
    size_t size = *n;
    size_t len = 0;
    int c;

    while ((c = fgetc(stream)) != EOF) {
        if (len + 1 >= size) {
            size *= 2; // Double the buffer size
            bufptr = (char*)realloc(bufptr, size);
            if (bufptr == NULL) {
                return -1;
            }
            *lineptr = bufptr;
            *n = size;
        }
        bufptr[len++] = c;
        if (c == '\n') {
            break;
        }
    }

    if (len == 0 && c == EOF) {
        return -1; // No data read and EOF reached
    }

    bufptr[len] = '\0';
    return len;
}*/

int64_t mod_add(int64_t a, int64_t b, int64_t mod) {
    __int128_t result = (__int128_t(a) + __int128_t(b)) % mod;
//    if (result < 0) {
//        result += mod;
//    }
    return static_cast<int64_t>(result);
}

int64_t mod_sub(int64_t a, int64_t b, int64_t mod) {
    __int128_t result = (__int128_t(a) - __int128_t(b)) % mod;
//    if (result < 0) {
//        result += mod;
//    }
    return static_cast<int64_t>(result);
}

int64_t mod_mul(int64_t a, int64_t b, int64_t mod) {
    __int128_t result = (__int128_t(a) * __int128_t(b)) % mod;
    return static_cast<int64_t>(result);
//    if (result < 0) {
//        result += mod;
//    }

}

EXPORT_SYMBOL int initialize_Constant() {

    if (is_init)
        return ETPSS_SUCCESS;
    srand(time(0));
    CTX = BN_CTX_new();
    BN_CTX_start(CTX);
    MOD = std::numeric_limits<long long>::max() / 4;

    if (MOD) {
        BIGNUM* n = BN_new();
        BN_set_word(n, N);
        BN_set_word(n, random_bits);

        BN_free(n);
    }
    else {
        return ETPSS_ERROR;
    }
    is_init = 1;

    ONE = BN_CTX_get(CTX);
    BN_set_word(ONE, 1);
    ZERO = BN_CTX_get(CTX);
    BN_set_word(ZERO, 0);
    return ETPSS_SUCCESS;
}
static int generate_array() {

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dis(0, 2000);

    rand_array[0] = dis(gen);
    rand_array[1] = dis(gen);
    rand_array[2] = dis(gen);
    return BN_SUCCESS;
}
static void et_refresh_x(eTPSS* a) {

    int64_t  t3;
    et_Recover(&t3,a);

    printf("refresh_value:%ld\n",t3);
    fflush(stdout);

    a->CS1.x = mod_add(a->CS1.x,a->CS1.r1,MOD);
    a->CS1.x = mod_sub(a->CS1.x,a->CS1.r2,MOD);

    a->CS2.x =  mod_add(a->CS2.x,a->CS2.r1,MOD);
    a->CS2.x = mod_sub(a->CS2.x,a->CS2.r2,MOD);

    a->CS3.x =  mod_add(a->CS3.x,a->CS3.r1,MOD);
    a->CS3.x = mod_sub(a->CS3.x,a->CS3.r2,MOD);
    int64_t t4;
    et_Recover(&t4,a);
    if(t3 != t4){
        printf("refresh_value:%ld\n",t3);
        fflush(stdout);
    }

}



int init_eTPSS(eTPSS* var) {

    // 初始化设定不是通过乘法获得
    var->is_multi_res = 0;
    var->CS1.r1 = 0;
    var->CS1.r2 =0;
    var->CS1.x =0;

    var->CS2.r1 = 0;
    var->CS2.r2 = 0;
    var->CS2.x = 0;

    var->CS3.r1 = 0;
    var->CS3.r2 = 0;
    var->CS3.x = 0;
    return BN_SUCCESS;

}
int free_eTPSS(eTPSS* var) {
    return ETPSS_SUCCESS;
}

int et_Share(eTPSS* var, int64_t num) {
    int ret = 1;
    if(num < 0){
        if(num <= (0 - MOD)){
            fprintf(stderr, "The value of num exceeds -（ 2 ^ 32）\n");
            return ETPSS_ERROR;
        }
    }else{
        if(num >= MOD){
            fprintf(stderr, "The value of num exceeds 2 ^ 32\n");
            return ETPSS_ERROR;
        }
    }

    int64_t tmp = num;
    // 进行直接划分值，在2^64次方内，直接进行划分值
    int64_t split1 = 0;
    int64_t split2 = 0;
    int64_t split3 = 0;
    // 创建随机数生成器
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dis(0, MOD);
    // 生成两个MOD以内的随机值，int64_t类型的
    split1 = dis(gen);
    split2 = dis(gen);
    split3 = tmp - split1 - split2;

    split3 %= MOD;

    var->CS1.x = split1;
    var->CS2.x = split2;
    var->CS3.x = split3;

    var->is_multi_res = 0;
    return ETPSS_SUCCESS;
}
// 返回引用值
int et_Recover(int64_t *num, eTPSS* var) {

    int64_t tmp = 0;
    int64_t halfMod = MOD / 2;

    tmp = var->CS1.x;
    tmp = (tmp + var->CS2.x) % MOD;
    tmp = (tmp + var->CS3.x) % MOD;
    if (tmp >= halfMod) {
        tmp -= MOD;
    }

    *num = tmp;
    return ETPSS_SUCCESS;

}

int et_Add(eTPSS* res, eTPSS* a, eTPSS* b) {
    res->CS1.x = mod_add(a->CS1.x,b->CS1.x , MOD) ;
    res->CS2.x = mod_add(a->CS2.x,b->CS2.x , MOD);
    res->CS3.x = mod_add(a->CS3.x,b->CS3.x , MOD);
    return ETPSS_SUCCESS;
}

int et_ScalP(eTPSS *res,eTPSS *var,int64_t num) {
    res->CS1.x = mod_mul(var->CS1.x,num,MOD);
    res->CS2.x = mod_mul(var->CS2.x,num,MOD);
    res->CS3.x = mod_mul(var->CS3.x,num,MOD);
    return ETPSS_SUCCESS;
}

int et_Mul(eTPSS* res, eTPSS* a, eTPSS* b) {
    // TODO 先摸鱼实现，然后后面测试完之后再修改吧

    int64_t t1,t2,t3;
    et_Recover(&t1,a);
    et_Recover(&t2,b);
    t3 = t1 * t2;
    et_Share(res,t3);

//	if (a->is_multi_res == 1) {
//		// 生成随机序列
//		generate_array();
//		a->CS1.r1 = rand_array[0];
//
//		a->CS1.r2 = rand_array[2];
//
//		a->CS2.r1 = rand_array[1];
//
//		a->CS2.r2 = rand_array[0];
//
//		a->CS3.r1 = rand_array[2];
//
//		a->CS3.r2 = rand_array[1];
//		// 通过r扰动刷新x的值
//		et_refresh_x(a);
//	}
//	if (b->is_multi_res == 1) {
//		// 生成随机序列
//		generate_array();
//		b->CS1.r1 = rand_array[0];
//		b->CS1.r2 = rand_array[2];
//
//		b->CS2.r1 = rand_array[1];
//		b->CS2.r2 = rand_array[0];
//
//		b->CS3.r1 = rand_array[2];
//		b->CS3.r2 = rand_array[1];
//		// 通过r扰动刷新x的值
//		et_refresh_x(b);
//	}
//	int64_t  t1 = 0;
//	int64_t  t2 = 0;
//	int64_t  t3 = 0;
//    /*---计算z1---*/
//
//    t1 = mod_mul(a->CS1.x, b->CS1.x ,MOD);
//    t2 = mod_mul(a->CS2.x , b->CS1.x ,MOD);
//    t3 = mod_mul(a->CS1.x , b->CS2.x , MOD);
//
//	t1 =  t1 + t2;
//	int64_t z1 = t1 + t3;
//
//
//	/*---计算z2---*/
//
//    t1 = mod_mul(a->CS2.x , b->CS2.x , MOD);
//    t2 = mod_mul(a->CS3.x , b->CS2.x , MOD);
//    t3 = mod_mul(a->CS2.x , b->CS3.x , MOD);
//
//    t1 =  t1 + t2;
//    int64_t z2 = t1 + t3;
//
//
//	/*---计算z3---*/
//
//    t1 = mod_mul(a->CS3.x , b->CS3.x ,MOD);
//    t2 = mod_mul(a->CS3.x , b->CS1.x ,MOD);
//    t3 = mod_mul(a->CS1.x , b->CS3.x ,MOD);
//
//    t1 =  t1 + t2;
//    int64_t z3 = t1 + t3;
//	// 通过相乘得到的值
//	res->is_multi_res = 1;
//
//    res->CS1.x = z1;
//    res->CS2.x = z2;
//    res->CS3.x = z3;
//    int64_t ret;
//    et_Recover(&ret,res);
//    if(ret != 2468642L){
//        printf("error\n");
//    }

    /*---这里是debug时候对照的---*/
//
//    t1 = mod_mul(a->CS1.x, b->CS1.x ,MOD);
//    t2 = mod_mul(a->CS2.x , b->CS1.x ,MOD);
//    t3 = mod_mul(a->CS1.x , b->CS2.x , MOD);
//
//    t1 = t1 + t2;
//    z1 = t1 + t3;
//
//
//    /*---计算z2---*/
//
//    t1 = mod_mul(a->CS2.x , b->CS2.x , MOD);
//    t2 = mod_mul(a->CS3.x , b->CS2.x , MOD);
//    t3 = mod_mul(a->CS2.x , b->CS3.x , MOD);
//
//    t1 = t1 + t2;
//    z2 = t1 + t3;
//
//
//    /*---计算z3---*/
//
//    t1 = mod_mul(a->CS3.x , b->CS3.x ,MOD);
//    t2 = mod_mul(a->CS3.x , b->CS1.x ,MOD);
//    t3 = mod_mul(a->CS1.x , b->CS3.x ,MOD);
//
//    t1 = t1 + t2;
//    z3 = t1 + t3;
//
//    res->CS1.x = z1;
//    res->CS2.x = z2;
//    res->CS3.x = z3;
//
//    et_Recover(&ret,res);
//    if(ret != 2468642L){
//        printf("error\n");
//    }

    return ETPSS_SUCCESS;
}


// TODO 这里可以最摸的做法，直接回复之后判断正负算了
int et_judge_symbols(int* res, eTPSS* d1) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dis(0, MOD);
    // 随机影响因子默认生成的值是2^64次方内的值
    int64_t u1 = dis(gen);
    int64_t u2 = dis(gen);
    int64_t u3, w1, w2, tmp, r1, r2, z1, z2, z3;

    int64_t x1 = d1->CS1.x;
    int64_t x2 = d1->CS2.x;
    int64_t x3 = d1->CS3.x;

    // 计算 w1 = x1 - u1, w2 = x2 - u2
    w1 = mod_sub(x1, u1, MOD);
    w2 = mod_sub(x2, u2, MOD);

    // 计算 u3 = x3 + w1 + w2 - MOD
    tmp = mod_add(w1, w2, MOD);
    u3 = mod_add(x3, tmp, MOD);
    u3 = mod_sub(u3, MOD, MOD);

    // CS1和CS2生成一个共同的随机值r1
    r1 = dis(gen);

    // CS2和CS3生成一个共同的随机值r2
    r2 = dis(gen);

    // CS1计算 z1 = u1 + r1
    z1 = mod_add(u1, r1, MOD);

    // CS3计算 z3 = (z1 + u3) * r2
    z1 = mod_add(z1, u3, MOD);
    z3 = mod_mul(z1, r2, MOD);

    // CS2计算 z2 = (u2 - r1) * r2
    tmp = mod_sub(u2, r1, MOD);
    z2 = mod_mul(tmp, r2, MOD);

    // 判断结果
    tmp = mod_add(z2, z3, MOD);

    if (tmp == 0) {
        *res = -1;
        return ETPSS_SUCCESS; // ETPSS_SUCCESS
    }

    int y = (tmp < 0) ? 1 : 0;
    if (r2 < 0) {
        *res = y ^ 1;
    } else {
        *res = y ^ 0;
    }

    return ETPSS_SUCCESS; // ETPSS_SUCCESS
}


int et_Sub(int* ret, eTPSS* d1, eTPSS* d2) {
    /*eTPSS t;
    eTPSS res;
    init_eTPSS(&t);
    init_eTPSS(&res);
    // 符号取反
    t.CS1.x = 0 - d2->CS1.x;
    t.CS2.x = 0 - d2->CS2.x;
    t.CS3.x = 0 - d2->CS3.x;

    et_Add(&res, d1, &t);
    int64_t a;
    et_Recover(&a, &res);
     // 返还符号
    free_eTPSS(&res);
    free_eTPSS(&t);
     */
    int64_t a,b;
    et_Recover(&a,d1);
    et_Recover(&b,d2);



    if ( (a - b) == 0) {
        *ret = -1;
    }
    else if (a < b) {
        *ret = 1;
    }
    else {
        *ret = 0;
    }

    return ETPSS_SUCCESS;
}

// 计算减法的结果
int et_Sub_cal_res(eTPSS* res, eTPSS* d1, int64_t d2) {
    eTPSS t;

    init_eTPSS(&t);
    et_Share(&t, d2);
    // 符号取反，然后进行加法
    t.CS1.x = 0 - t.CS1.x;
    t.CS2.x = 0 - t.CS2.x;
    t.CS3.x = 0 - t.CS3.x;
    if (et_Add(res, d1, &t) != ETPSS_SUCCESS) {
        return ETPSS_ERROR;
    }

    free_eTPSS(&t);
    return ETPSS_SUCCESS;
}

void et_Copy(eTPSS* d1, eTPSS* d2) {
    d1->CS1.x = d2->CS1.x;
    d1->CS2.x = d2->CS2.x;
    d1->CS3.x = d2->CS3.x;
    d1->CS1.r1=d2->CS1.r1;
    d1->CS2.r1= d2->CS2.r1;
    d1->CS3.r1= d2->CS3.r1;
    d1->CS1.r2= d2->CS1.r2;
    d1->CS2.r2= d2->CS2.r2;
    d1->CS3.r2= d2->CS3.r2;
    d1->is_multi_res = d2->is_multi_res;
}

int et_Sub_cal_res_o(eTPSS* res, eTPSS* d1, eTPSS* d2) {

    int64_t n1,n2;
    et_Recover(&n1,d1);
    et_Recover(&n2,d2);

    et_Share(res,n1 - n2);
    return ETPSS_SUCCESS;
}

void free_BN_CTX() {
    BN_CTX_end(CTX);
    BN_CTX_free(CTX);
}

