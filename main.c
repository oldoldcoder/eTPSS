#include <openssl/bn.h>

#include "include/eTPSS.h"
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
int main(){
    initialize_Constant();
    // 从utils中读取我们的数据
    FILE  * file = fopen(DATA_PATH,"r");
    if(file == NULL){
        perror("Error opening file");
        return ERROR;
    }
    char *line = NULL;
    size_t len = 0;
    // 初始化data
    int totalLines;
    fscanf(file, "%d", &totalLines); // 读取第一行中的两个数字
    // 动态的创建一个bignum数组
    BIGNUM ** arr = (BIGNUM **) malloc(sizeof (BIGNUM *) * totalLines);
    int n = 0;
    for(int i = 0 ; i < totalLines ; ++i){
        // 获取一个bignum数组
        arr[i] = BN_CTX_get(CTX);
        if(getline(&line, &len, file) == -1){
            // 没有读到目标数据
            return ERROR;
        }
        if(!BN_dec2bn(&arr[i],line)){
            // 转换错误
            return ERROR;
        }
    }
    fclose(file);

    /**
     * 进行处理，处理相同数量的eTPSS，之后将值写入结果的文件
     * */
    eTPSS ** cryptArr = (eTPSS **) malloc(sizeof (eTPSS *) * totalLines);
    for(int i = 0 ; i < totalLines ; ++i){
        init_eTPSS(cryptArr[i]);
        et_Share(cryptArr[i],arr[i]);
    }
    /**
     * 写入文件，销毁所有数据
     * */
    FILE* resFile = fopen(RES_PATH, "w");
    if (resFile == NULL) {
        printf("Error opening file!\n");
        return ERROR;
    }

    // Write the total number of lines
    fprintf(file, "%d\n", totalLines);

    // Write each line with three big numbers
    for (int i = 0; i < totalLines; ++i) {
        fprintf(file, "%s %s %s\n", BN_bn2dec(cryptArr[i]->CS1.x), BN_bn2dec(cryptArr[i]->CS2.x), BN_bn2dec(cryptArr[i]->CS3.x));
        free_eTPSS(cryptArr[i]);
        BN_clear(arr[i]);
    }
    fclose(file);
    return SUCCESS;
}