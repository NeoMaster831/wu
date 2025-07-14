#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#define RSA_KEY_BITS 1024
#define RSA_KEY_BYTES (RSA_KEY_BITS / 8)
#define EXPONENT_BITS 256
#define FLAG "codegate2025{fake_flag}"

void print_hex(const char *label, unsigned char *data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}

int pad(unsigned char *msg, size_t msg_len, unsigned char *padded, size_t pad_len) {
    if (msg_len + 3 >= pad_len) return 0;
    size_t padding_len = pad_len - msg_len - 3;
    padded[0] = 0x00;
    padded[1] = 0x02;
    for (size_t i = 0; i < padding_len; i++) {
        unsigned char rb;
        do {
            RAND_bytes(&rb, 1);
        } while (rb == 0x00);
        padded[2 + i] = rb;
    }
    padded[2 + padding_len] = 0x00;
    memcpy(padded + 3 + padding_len, msg, msg_len);
    return 1;
}

int verify(unsigned char *sig, size_t sig_len, unsigned char *msg, size_t *msg_len) {
    if (sig_len < 3 || sig[0] != 0x00 || sig[1] != 0x02) return 0;
    size_t idx = 2;
    while (idx < sig_len && sig[idx] != 0x00) idx++;
    if (idx == sig_len){
        memset(msg, 0, sig_len);
        return 0;
    }
    *msg_len = sig_len - idx - 1;
    memcpy(msg, sig + idx + 1, *msg_len);
    return 1;
}

typedef struct RSAKey{
    BIGNUM *N;
    BIGNUM *e;
    BIGNUM *d;
} RSAKey;

void generate_keys(RSAKey *rsa) {
    BIGNUM *p = BN_new(), *q = BN_new(), *phi = BN_new();
    BIGNUM *e = BN_new(), *d = BN_new();
    BIGNUM *one = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_generate_prime_ex(p, RSA_KEY_BITS / 2, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(q, RSA_KEY_BITS / 2, 1, NULL, NULL, NULL);

    rsa->N = BN_new();
    BN_mul(rsa->N, p, q, ctx);

    BN_sub(one, p, BN_value_one());
    BN_sub(p, q, BN_value_one());
    BN_mul(phi, one, p, ctx);

    do {
        BN_rand(e, EXPONENT_BITS, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    } while (!BN_is_prime_ex(e, BN_prime_checks, ctx, NULL) || BN_gcd(one, e, phi, ctx) > 1);

    BN_mod_inverse(d, e, phi, ctx);

    rsa->e = BN_dup(e);
    rsa->d = BN_dup(d);

    BN_free(p);
    BN_free(q);
    BN_free(phi);
    BN_free(one);
    BN_free(e);
    BN_free(d);
    BN_CTX_free(ctx);
}

void encrypt(RSAKey *rsa, unsigned char *msg, size_t msg_len, unsigned char *enc) {
    BIGNUM *m = BN_new(), *c = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_bin2bn(msg, RSA_KEY_BYTES, m);
    BN_mod_exp(c, m, rsa->e, rsa->N, ctx);
    BN_bn2bin(c, enc);

    BN_free(m);
    BN_free(c);
    BN_CTX_free(ctx);
}

int main() {
    RSAKey rsa;
    generate_keys(&rsa);

    unsigned char flag[RSA_KEY_BYTES + 1] = FLAG;

    unsigned char enc_flag[RSA_KEY_BYTES];
    encrypt(&rsa, flag, strlen((char *)flag), enc_flag);
    print_hex("Signature: ", enc_flag, RSA_KEY_BYTES);
    fflush(stdout);

    char buf[RSA_KEY_BYTES + 1];
    printf("Read Check\n");
    fgets(buf, sizeof(buf), stdin);
    if (memcmp(buf, enc_flag, RSA_KEY_BYTES) == 0) {
        printf("Correct!\nFlag: %s\n", FLAG);
    } else {
        printf("Incorrect!\n");
    }
    
    BN_free(rsa.N);
    BN_free(rsa.e);
    BN_free(rsa.d);
    return 0;
}
