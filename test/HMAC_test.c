#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>

int main() {
    char key[] = "my_secret_key";
    char message[] = "Hello, HMAC!";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length;

    // 使用HMAC算法计算消息摘要
    HMAC(EVP_sha256(), key, strlen(key), (unsigned char*) message, strlen(message), digest, &digest_length);

    // 打印消息摘要
    printf("HMAC digest: ");
    for (int i = 0; i < digest_length; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}
