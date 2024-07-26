// Implement eTPSS using C language and OPENSSL library
/*
@author:hufei
@time:2024/01/17
@desc:Definition of constants, operations, and header files
*/

#include <openssl/bn.h>

#include "eTPSS.h"

#include <stdlib.h>

/*------------------------*/
BIGNUM* MOD = NULL;
BN_CTX* CTX;
BIGNUM* RANDOM_RANGE = NULL;
int is_init = 0;
BIGNUM* ZERO = NULL;
BIGNUM* ONE = NULL;
static BIGNUM* rand_array[3];

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
EXPORT_SYMBOL int initialize_Constant() {

	if (is_init)
		return ETPSS_SUCCESS;
	srand(time(0));
	CTX = BN_CTX_new();
	BN_CTX_start(CTX);
	MOD = BN_CTX_get(CTX);
	RANDOM_RANGE = BN_CTX_get(CTX);

	if (MOD) {
		BIGNUM* n = BN_new();
		BN_set_word(n, N);
		BN_set_word(MOD, 2);
		BN_exp(MOD, MOD, n, CTX); // 计算 2 的 n 次方，并将结果存储在 result 中

		BN_set_word(n, random_bits);
		BN_set_word(RANDOM_RANGE, 2);
		BN_exp(RANDOM_RANGE, RANDOM_RANGE, n, CTX); // 计算 2 的 n 次方，并将结果存储在 result 中

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
static void free_array() {
	BN_free(rand_array[0]);
	BN_free(rand_array[1]);
	BN_free(rand_array[2]);
}
static int generate_array() {
	BIGNUM* a = BN_new();
	BIGNUM* b = BN_new();
	BIGNUM* c = BN_new();

	if (!BN_rand_range(a, MOD) ||
		!BN_rand_range(b, MOD) ||
		!BN_rand_range(c, MOD)) {
		free_array();
		return BN_ERROR;
	}
	rand_array[0] = a;
	rand_array[1] = b;
	rand_array[2] = c;
	return BN_SUCCESS;
}
static void et_refresh_x(eTPSS* a) {

    BN_CTX * ctx = BN_CTX_new();
    BN_CTX_start(ctx);

	BN_mod_add(a->CS1.x, a->CS1.x, a->CS1.r1, MOD, ctx);
	BN_mod_sub(a->CS1.x, a->CS1.x, a->CS1.r2, MOD, ctx);

	BN_mod_add(a->CS2.x, a->CS2.x, a->CS2.r1, MOD, ctx);
	BN_mod_sub(a->CS2.x, a->CS2.x, a->CS2.r2, MOD, ctx);

	BN_mod_add(a->CS3.x, a->CS3.x, a->CS3.r1, MOD, ctx);
	BN_mod_sub(a->CS3.x, a->CS3.x, a->CS3.r2, MOD, ctx);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

}



int init_eTPSS(eTPSS* var) {

	var->ctx = BN_CTX_new();
	if (var->ctx == NULL) {
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
int free_eTPSS(eTPSS* var) {
	BN_CTX_end(var->ctx);
	BN_CTX_free(var->ctx);
	return ETPSS_SUCCESS;
}

int et_Share(eTPSS* var, BIGNUM* num) {
	int ret = 1;
	// 不在范围内的判断
	if (BN_is_negative(num)) {
		// 如果比负的mod还小
		BN_set_negative(MOD, 1);
		if (BN_cmp(num, MOD) <= 0) {
			fprintf(stderr, "The value of num exceeds -（ 2 ^ 64）\n");
			return ETPSS_ERROR;
		}
		BN_set_negative(MOD, 0);
	}
	else {
		if (BN_cmp(num, MOD) >= 0) {
			fprintf(stderr, "The value of num exceeds 2 ^ 64\n");
			return ETPSS_ERROR;
		}
	}
	BIGNUM* tmp = BN_new();
	BN_copy(tmp, num);
	// 进行直接划分值，在2^64次方内，直接进行划分值
	BIGNUM* split1 = var->CS1.x;
	BIGNUM* split2 = var->CS2.x;
	BIGNUM* split3 = var->CS3.x;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

	if (!BN_rand_range(split1, MOD)) {

		fprintf(stderr, "process of split have some trouble\n");
		goto end;
	}
	if (!BN_rand_range(split2, MOD)) {
		fprintf(stderr, "process of split have some trouble\n");
		goto end;
	}
	BN_sub(tmp, tmp, split1);

	BN_sub(tmp, tmp, split2);

	BN_nnmod(split3, tmp, MOD, ctx);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

	var->is_multi_res = 0;
	ret = 0;
end:
	BN_free(tmp);
	return ret == 0 ? ETPSS_SUCCESS : ETPSS_ERROR;
}

int et_Recover(BIGNUM* num, eTPSS* var) {
	BIGNUM* tmp = BN_new();
	BIGNUM* halfMod = BN_new();
	BN_copy(halfMod, MOD);
	BN_div_word(halfMod, 2);
	BN_add(tmp, var->CS1.x, var->CS2.x);
	BN_add(tmp, tmp, var->CS3.x);
    BN_CTX * ctx = BN_CTX_new();
    BN_CTX_start(ctx);
	BN_nnmod(tmp, tmp, MOD, ctx);
	if (BN_cmp(tmp, halfMod) >= 0) {
		BN_sub(tmp, tmp, MOD);
	}
	BN_copy(num, tmp);

	BN_free(tmp);
	BN_free(halfMod);
	return ETPSS_SUCCESS;
}

int et_Add(eTPSS* res, eTPSS* a, eTPSS* b) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
	if (!BN_mod_add(res->CS1.x, a->CS1.x, b->CS1.x, MOD, ctx) ||
		!BN_mod_add(res->CS2.x, a->CS2.x, b->CS2.x, MOD, ctx) ||
		!BN_mod_add(res->CS3.x, a->CS3.x, b->CS3.x, MOD, ctx)) {
		return ETPSS_ERROR;
	}
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
	return ETPSS_SUCCESS;
}

int et_ScalP(eTPSS* res, eTPSS* var, BIGNUM* num) {

	if (!BN_mod_mul(res->CS1.x, var->CS1.x, num, MOD, CTX) ||
		!BN_mod_mul(res->CS2.x, var->CS2.x, num, MOD, CTX) ||
		!BN_mod_mul(res->CS3.x, var->CS3.x, num, MOD, CTX)) {
		return ETPSS_ERROR;
	}
	return ETPSS_SUCCESS;
}

int et_Mul(eTPSS* res, eTPSS* a, eTPSS* b) {

	BIGNUM* tmp = BN_new();
	if (a->is_multi_res == 1) {
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
	if (b->is_multi_res == 1) {
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
	BIGNUM* z1 = res->CS1.x;
	BIGNUM* z2 = res->CS2.x;
	BIGNUM* z3 = res->CS3.x;
	BIGNUM* t1 = BN_new();
	BIGNUM* t2 = BN_new();
	BIGNUM* t3 = BN_new();
	/*---计算z1---*/
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

	BN_mod_mul(t1, a->CS1.x, b->CS1.x, MOD, ctx);

	BN_mod_mul(t2, a->CS2.x, b->CS1.x, MOD, ctx);

	BN_mod_mul(t3, a->CS1.x, b->CS2.x, MOD, ctx);

	BN_add(t1, t1, t2);
	BN_add(z1, t1, t3);


	/*---计算z2---*/
	BN_mod_mul(t1, a->CS2.x, b->CS2.x, MOD, ctx);

	BN_mod_mul(t2, a->CS3.x, b->CS2.x, MOD, ctx);

	BN_mod_mul(t3, a->CS2.x, b->CS3.x, MOD, ctx);

	BN_add(t1, t1, t2);
	BN_add(z2, t1, t3);


	/*---计算z3---*/
	BN_mod_mul(t1, a->CS3.x, b->CS3.x, MOD, ctx);

	BN_mod_mul(t2, a->CS1.x, b->CS3.x, MOD, ctx);

	BN_mod_mul(t3, a->CS3.x, b->CS1.x, MOD, ctx);

	BN_add(t1, t1, t2);
	BN_add(z3, t1, t3);
	// 通过相乘得到的值
	res->is_multi_res = 1;

	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
	return ETPSS_SUCCESS;
}

// 判断etpss的符号,赋值给res
int et_judge_symbols(int* res, eTPSS* d1) {

	// 随机影响因子默认生成的值是2^64次方内的值
	BIGNUM* u1 = BN_CTX_get(CTX);
	BIGNUM* u2 = BN_CTX_get(CTX);
	BIGNUM* u3 = BN_CTX_get(CTX);
	BIGNUM* w1 = BN_CTX_get(CTX);
	BIGNUM* w2 = BN_CTX_get(CTX);

	BIGNUM* tmp = BN_CTX_get(CTX);
	// 随机扰动值
	BIGNUM* r1 = BN_CTX_get(CTX);
	BIGNUM* r2 = BN_CTX_get(CTX);
	BIGNUM* x1 = d1->CS1.x;
	BIGNUM* x2 = d1->CS2.x;
	BIGNUM* x3 = d1->CS3.x;

	BIGNUM* z1 = BN_CTX_get(CTX);
	BIGNUM* z2 = BN_CTX_get(CTX);
	BIGNUM* z3 = BN_CTX_get(CTX);


	if (!BN_rand_range(u1, RANDOM_RANGE)) {
		// 报错处理
		fprintf(stderr, "Error in obtaining random values.\n");
		return ETPSS_ERROR;
	}


	if (!BN_rand_range(u2, RANDOM_RANGE)) {
		// 报错处理
		fprintf(stderr, "Error in obtaining random values.\n");
		return ETPSS_ERROR;
	}


	BN_sub(w1, x1, u1);
	BN_sub(w2, x2, u2);
	/*--------打包w1，w2发送给CS3-------*/
	BN_add(tmp, w1, w2);
	BN_add(u3, x3, tmp);
	BN_nnmod(u3, u3, MOD, CTX);
	BN_sub(u3, u3, MOD);

	// CS1和CS2生成一个共同的随机值r1
	if (!BN_rand_range(r1, RANDOM_RANGE)) {
		// 报错处理
		fprintf(stderr, "Error in obtaining random values.\n");
		return ETPSS_ERROR;
	}
	// CS2和CS3生成一个共同的随机值r2
	if (!BN_rand_range(r2, RANDOM_RANGE)) {
		// 报错处理
		fprintf(stderr, "Error in obtaining random values.\n");
		return ETPSS_ERROR;
	}
	// CS1计算u1 + r1
	BN_add(z1, u1, r1);
	// CS_3计算z_3=(z_1+u_3 )*α
	BN_add(z1, z1, u3);
	BN_mul(z3, z1, r2, CTX);
	// CS_2计算z_2=(u_2-r)*α
	BN_sub(tmp, u2, r1);
	BN_mul(z2, tmp, r2, CTX);
	/*-----------第四步-----------*/
	int y;
	BN_add(tmp, z2, z3);

	fflush(stdout);
	if (BN_is_zero(tmp)) {
		// 报告x等于0
		*res = -1;
		return ETPSS_SUCCESS;
	}

	if (BN_is_negative(tmp)) {
		y = 1;
	}
	else {
		y = 0;
	}
	if (BN_is_negative(r2)) {
		*res = y ^ 1;
	}
	else {
		*res = y ^ 0;
	}

	return ETPSS_SUCCESS;
}

int et_Sub(int* ret, eTPSS* d1, eTPSS* d2) {
	eTPSS t;
	eTPSS res;
	init_eTPSS(&t);
	init_eTPSS(&res);
	// 符号取反
	BN_copy(t.CS1.x, d2->CS1.x);
	BN_set_negative(t.CS1.x, BN_is_negative(t.CS1.x) ^ 1);
	BN_copy(t.CS2.x, d2->CS2.x);
	BN_set_negative(t.CS2.x, BN_is_negative(t.CS2.x) ^ 1);
	BN_copy(t.CS3.x, d2->CS3.x);
	BN_set_negative(t.CS3.x, BN_is_negative(t.CS3.x) ^ 1);
	if (et_Add(&res, d1, &t) != ETPSS_SUCCESS) {
		return ETPSS_ERROR;
	}

	BIGNUM* aaa = BN_new();
	et_Recover(aaa, &res);
	if (BN_is_zero(aaa)) {
		*ret = -1;
	}
	else if (BN_is_negative(aaa)) {
		*ret = 1;
	}
	else {
		*ret = 0;
	}
	/*if(et_judge_symbols(ret,&res) != ETPSS_SUCCESS){
		return ETPSS_ERROR;
	}*/
	// 返还符号
	/*if(et_judge_symbols(ret,&res) != ETPSS_SUCCESS){
		return ETPSS_ERROR;
	}*/
	// 返还符号
	free_eTPSS(&res);
	free_eTPSS(&t);
	return ETPSS_SUCCESS;
}

// 计算减法的结果
int et_Sub_cal_res(eTPSS* res, eTPSS* d1, BIGNUM* d2) {
	eTPSS t;

	init_eTPSS(&t);
	et_Share(&t, d2);
	// 符号取反，然后进行加法
	BN_set_negative(t.CS1.x, BN_is_negative(t.CS1.x) ^ 1);
	BN_set_negative(t.CS2.x, BN_is_negative(t.CS2.x) ^ 1);
	BN_set_negative(t.CS3.x, BN_is_negative(t.CS3.x) ^ 1);
	if (et_Add(res, d1, &t) != ETPSS_SUCCESS) {
		return ETPSS_ERROR;
	}

	free_eTPSS(&t);
	return ETPSS_SUCCESS;
}

void et_Copy(eTPSS* d1, eTPSS* d2) {
	BN_copy(d1->CS1.x, d2->CS1.x);
	BN_copy(d1->CS2.x, d2->CS2.x);
	BN_copy(d1->CS3.x, d2->CS3.x);
	BN_copy(d1->CS1.r1, d2->CS1.r1);
	BN_copy(d1->CS2.r1, d2->CS2.r1);
	BN_copy(d1->CS3.r1, d2->CS3.r1);

	BN_copy(d1->CS1.r2, d2->CS1.r2);
	BN_copy(d1->CS2.r2, d2->CS2.r2);
	BN_copy(d1->CS3.r2, d2->CS3.r2);
	d1->is_multi_res = d2->is_multi_res;
}

int et_Sub_cal_res_o(eTPSS* res, eTPSS* d1, eTPSS* d2) {
	eTPSS t;

	init_eTPSS(&t);
	et_Copy(&t, d2);
	// 符号取反，然后进行加法
	BN_set_negative(t.CS1.x, BN_is_negative(t.CS1.x) ^ 1);
	BN_set_negative(t.CS2.x, BN_is_negative(t.CS2.x) ^ 1);
	BN_set_negative(t.CS3.x, BN_is_negative(t.CS3.x) ^ 1);
	if (et_Add(res, d1, &t) != ETPSS_SUCCESS) {
		return ETPSS_ERROR;
	}

	free_eTPSS(&t);
	return ETPSS_SUCCESS;
}

void free_BN_CTX() {
	BN_CTX_end(CTX);
	BN_CTX_free(CTX);
}

