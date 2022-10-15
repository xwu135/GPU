#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/time.h>

#define ROL(a, n) (((a) << (n)) | (((a) & 0xffffffff) >> (32 - (n))))
#define ROR(a, n) ROL((a), 32 - (n))
#define BLOCK_SIZE 16

#define FATAL(msg, ...) \
    do {\
        fprintf(stderr, "[%s:%d] "msg"\n", __FILE__, __LINE__, ##__VA_ARGS__);\
        exit(-1);\
    } while(0)

typedef unsigned char byte;
typedef struct {
    struct timeval startTime;
    struct timeval endTime;
} Timer;

uint32_t tau(uint32_t A);
uint32_t L_ap(uint32_t B);
uint32_t T_ap(uint32_t Z);
uint32_t *expand_key(bool encryption, byte *key);
uint32_t L(uint32_t B);
uint32_t T(uint32_t Z);
uint32_t F0(const uint32_t *X, uint32_t rk);
uint32_t F1(const uint32_t *X, uint32_t rk);
uint32_t F2(const uint32_t *X, uint32_t rk);
uint32_t F3(const uint32_t *X, uint32_t rk);
void init(bool encryption, byte *keys);
uint32_t process_block(byte *in, uint32_t inOff, byte *out, uint32_t outOff);
uint32_t big_endian_to_int(const byte *bs, uint32_t off);
void int_to_big_endian(uint32_t n, byte *bs, uint32_t off);
void encrypt0(byte *plain, byte *encrypted, size_t len, byte *key);
void decrypt0(byte *encrypted, byte *decrypted, size_t len, byte *key);
byte *pkcs7padding(bool mode, byte *data, long data_size, long *buffer_size);
void encrypt(const char *input_path, const char *output_path, byte *key);
void decrypt(const char *input_path, const char *output_path, byte *key);
byte *read_file(const char *path, long *file_size);
void write_file(const char *path, byte *in, size_t inLen);
bool verify(const char *input_path, const char *decrypted_path);
void startTime(Timer* timer);
void stopTime(Timer* timer);
float elapsedTime(Timer timer);
int main(int argc, char *argv[]);

byte Sbox[] = {
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};
uint32_t CK[] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};
uint32_t FK[] = {
        0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};
uint32_t rk[32];

uint32_t tau(uint32_t A) {
    uint32_t b0 = Sbox[(A >> 24) & 0xff] & 0xff;
    uint32_t b1 = Sbox[(A >> 16) & 0xff] & 0xff;
    uint32_t b2 = Sbox[(A >> 8) & 0xff] & 0xff;
    uint32_t b3 = Sbox[A & 0xff] & 0xff;
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

uint32_t L_ap(uint32_t B) {
    return B ^ ROL(B, 13) ^ ROL(B, 23);
}

uint32_t T_ap(uint32_t Z) {
    return L_ap(tau(Z));
}

uint32_t* expand_key(bool encryption, byte *key) {
    uint32_t *RK = (uint32_t*) malloc(sizeof(uint32_t) * 32);
    if (!RK) {
        fprintf(stderr, "cannot allocate more memory\n");
        exit(EXIT_FAILURE);
    }
    uint32_t MK[4];

    MK[0] = big_endian_to_int(key, 0);
    MK[1] = big_endian_to_int(key, 4);
    MK[2] = big_endian_to_int(key, 8);
    MK[3] = big_endian_to_int(key, 12);

    uint32_t K[4];
    K[0] = MK[0] ^ FK[0];
    K[1] = MK[1] ^ FK[1];
    K[2] = MK[2] ^ FK[2];
    K[3] = MK[3] ^ FK[3];

    int i;
    if (encryption)
    {
        RK[0] = K[0] ^ T_ap(K[1] ^ K[2] ^ K[3] ^ CK[0]);
        RK[1] = K[1] ^ T_ap(K[2] ^ K[3] ^ RK[0] ^ CK[1]);
        RK[2] = K[2] ^ T_ap(K[3] ^ RK[0] ^ RK[1] ^ CK[2]);
        RK[3] = K[3] ^ T_ap(RK[0] ^ RK[1] ^ RK[2] ^ CK[3]);
        for (i = 4; i < 32; i++)
        {
            RK[i] = RK[i - 4] ^ T_ap(RK[i - 3] ^ RK[i - 2] ^ RK[i - 1] ^ CK[i]);
        }
    }
    else
    {
        RK[31] = K[0] ^ T_ap(K[1] ^ K[2] ^ K[3] ^ CK[0]);
        RK[30] = K[1] ^ T_ap(K[2] ^ K[3] ^ RK[31] ^ CK[1]);
        RK[29] = K[2] ^ T_ap(K[3] ^ RK[31] ^ RK[30] ^ CK[2]);
        RK[28] = K[3] ^ T_ap(RK[31] ^ RK[30] ^ RK[29] ^ CK[3]);
        for (i = 27; i >= 0; i--)
        {
            RK[i] = RK[i + 4] ^ T_ap(RK[i + 3] ^ RK[i + 2] ^ RK[i + 1] ^ CK[31 - i]);
        }
    }

    return RK;
}

uint32_t L(uint32_t B) {
    return B ^ ROL(B, 2) ^ ROL(B, 10) ^ ROL(B, 18) ^ ROL(B, 24);
}

uint32_t T(uint32_t Z) {
    return L(tau(Z));
}

uint32_t F0(const uint32_t *X, uint32_t RK) {
    return X[0] ^ T(X[1] ^ X[2] ^ X[3] ^ RK);
}

uint32_t F1(const uint32_t *X, uint32_t RK) {
    return X[1] ^ T(X[2] ^ X[3] ^ X[0] ^ RK);
}

uint32_t F2(const uint32_t *X, uint32_t RK) {
    return X[2] ^ T(X[3] ^ X[0] ^ X[1] ^ RK);
}

uint32_t F3(const uint32_t *X, uint32_t RK) {
    return X[3] ^ T(X[0] ^ X[1] ^ X[2] ^ RK);
}

void init(bool encryption, byte *keys) {
    uint32_t *RK = expand_key(encryption, keys);
    memmove(rk, RK, sizeof(uint32_t) * 32);
    free(RK);
}

uint32_t process_block(byte *in, uint32_t inOff, byte *out, uint32_t outOff) {
    uint32_t X[4];
    X[0] = big_endian_to_int(in, inOff);
    X[1] = big_endian_to_int(in, inOff + 4);
    X[2] = big_endian_to_int(in, inOff + 8);
    X[3] = big_endian_to_int(in, inOff + 12);

    int i;

    for (i = 0; i < 32; i += 4)
    {
        X[0] = F0(X, rk[i]);
        X[1] = F1(X, rk[i + 1]);
        X[2] = F2(X, rk[i + 2]);
        X[3] = F3(X, rk[i + 3]);
    }

    int_to_big_endian(X[3], out, outOff);
    int_to_big_endian(X[2], out, outOff + 4);
    int_to_big_endian(X[1], out, outOff + 8);
    int_to_big_endian(X[0], out, outOff + 12);

    return BLOCK_SIZE;
}

uint32_t big_endian_to_int(const byte *bs, uint32_t off) {
    uint32_t n = bs[off] << 24;
    n |= (bs[++off] & 0xff) << 16;
    n |= (bs[++off] & 0xff) << 8;
    n |= (bs[++off] & 0xff);
    return n;
}

void int_to_big_endian(uint32_t n, byte *bs, uint32_t off) {
    bs[off] = ROR(n, 24);
    bs[++off] = ROR(n, 16);
    bs[++off] = ROR(n, 8);
    bs[++off] = n;
}

void encrypt0(byte *plain, byte *encrypted, size_t len, byte *key) {
    size_t times = len / BLOCK_SIZE;
    int i = 0;
    while (i < times) {
        process_block(plain, i * BLOCK_SIZE, encrypted, i * BLOCK_SIZE);
        i++;
    }
}

void decrypt0(byte *encrypted, byte *decrypted, size_t len, byte *key) {
    size_t times = len / BLOCK_SIZE;
    int i = 0;
    while (i < times) {
        process_block(encrypted, i * BLOCK_SIZE, decrypted, i * BLOCK_SIZE);
        i++;
    }
}

byte *pkcs7padding(bool mode, byte *data, long data_size, long *buffer_size) {
    if (mode) {
        *buffer_size = ((data_size >> 4) + 1) << 4;
        data = (byte*) realloc(data, *buffer_size);
        if (!data) {
            FATAL("cannot allocate more memory");
        }
        byte remainder = 16 - data_size % 16;
        for (long i = data_size; i < *buffer_size; i++) {
            data[i] = remainder;
        }
    } else {
        *buffer_size = data_size - data[data_size - 1];
    }
    return data;
}

void encrypt(const char *input_path, const char *output_path, byte *key) {
    Timer timer;
    long file_size, buffer_size;

    startTime(&timer);
    printf("start reading original file {\"%s\"}\n", input_path);
    byte *plain = read_file(input_path, &file_size);
    stopTime(&timer);
    printf("%f s\n", elapsedTime(timer));
    printf("finish reading original file {\"%s\"}\n", input_path);
    printf("file size = %ld B = %f MB = %f GB\n", file_size, (double) file_size / (1 << 20), (double) file_size / (1 << 30));
    printf("\n");

    startTime(&timer);
    printf("start pkcs7padding\n");
    plain = pkcs7padding(true, plain, file_size, &buffer_size);
    stopTime(&timer);
    printf("%f s\n", elapsedTime(timer));
    printf("finish pkcs7padding\n");
    printf("\n");

    byte *encrypted = (byte*) malloc(sizeof(byte) * buffer_size);
    if (!encrypted) {
        FATAL("cannot allocate more memory");
    }
    init(true, key);

    startTime(&timer);
    printf("start encrypting\n");
    encrypt0(plain, encrypted, buffer_size, key);
    stopTime(&timer);
    printf("%f s\n", elapsedTime(timer));
    printf("finish encrypting\n");
    printf("\n");

    startTime(&timer);
    printf("start writing encrypted file {\"%s\"}\n", output_path);
    write_file(output_path, encrypted, buffer_size);
    stopTime(&timer);
    printf("%f s\n", elapsedTime(timer));
    printf("finish writing encrypted file {\"%s\"}\n", output_path);
    printf("file size = %ld B = %f MB = %f GB\n", buffer_size, (double) buffer_size / (1 << 20), (double) buffer_size / (1 << 30));
    printf("\n");

    free(plain);
    free(encrypted);
}

void decrypt(const char *input_path, const char *output_path, byte *key) {
    Timer timer;
    long file_size, buffer_size = 0;

    startTime(&timer);
    printf("start reading encrypted file {\"%s\"}\n", input_path);
    byte *encrypted = read_file(input_path, &file_size);
    stopTime(&timer);
    printf("%f s\n", elapsedTime(timer));
    printf("finish reading encrypted file {\"%s\"}\n", input_path);
    printf("file size = %ld B = %f MB = %f GB\n", file_size, (double) file_size / (1 << 20), (double) file_size / (1 << 30));
    printf("\n");

    byte *decrypted = (byte*) malloc(sizeof(byte) * file_size);
    if (!decrypted) {
        FATAL("cannot allocate more memory");
    }
    init(false, key);

    startTime(&timer);
    printf("start decrypting\n");
    decrypt0(encrypted, decrypted, file_size, key);
    stopTime(&timer);
    printf("%f s\n", elapsedTime(timer));
    printf("finish decrypting\n");
    printf("\n");

    startTime(&timer);
    printf("start pkcs7padding\n");
    decrypted = pkcs7padding(false, decrypted, file_size, &buffer_size);
    stopTime(&timer);
    printf("%f s\n", elapsedTime(timer));
    printf("finish pkcs7padding\n");
    printf("\n");

    startTime(&timer);
    printf("start writing decrypted file {\"%s\"}\n", output_path);
    write_file(output_path, decrypted, buffer_size);
    stopTime(&timer);
    printf("%f s\n", elapsedTime(timer));
    printf("finish writing decrypted file {\"%s\"}\n", output_path);
    printf("file size = %ld B = %f MB = %f GB\n", buffer_size, (double) buffer_size / (1 << 20), (double) buffer_size / (1 << 30));
    printf("\n");

    free(encrypted);
    free(decrypted);
}

byte *read_file(const char *path, long *file_size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        FATAL("read file {%s} error", path);
    }
    fseek(fp, 0, SEEK_END);
    *file_size = ftell(fp);
    byte *data = (byte*) malloc(sizeof(byte) * *file_size);
    if (!data) {
        FATAL("cannot allocate more memory");
    }
    fseek(fp, 0, SEEK_SET);
    fread(data, sizeof(byte), *file_size, fp);
    fclose(fp);
    return data;
}

void write_file(const char *path, byte *in, size_t inLen) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        FATAL("write file {%s} error", path);
    }
    fwrite(in, sizeof(byte), inLen, fp);
    fclose(fp);
}

bool verify(const char *input_path, const char *decrypted_path) {
    long file_size1, file_size2;
    byte *data1 = read_file(input_path, &file_size1);
    byte *data2 = read_file(decrypted_path, &file_size2);

    bool result = file_size1 == file_size2;
    if (result) {
        for (int i = 0; i < file_size1; i++) {
            if (data1[i] != data2[i]) {
                result = false;
                break;
            }
        }
    }
    free(data1);
    free(data2);
    return result;
}

void startTime(Timer* timer) {
    gettimeofday(&(timer->startTime), NULL);
}

void stopTime(Timer* timer) {
    gettimeofday(&(timer->endTime), NULL);
}

float elapsedTime(Timer timer) {
    return ((float) ((timer.endTime.tv_sec - timer.startTime.tv_sec) \
                + (timer.endTime.tv_usec - timer.startTime.tv_usec) / 1.0e6));
}

int main(int argc, char *argv[]) {
    if (1 == argc) {
        FATAL("please input at least on argument");
    }
    byte key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    char *input_path = argv[1];
    char *encrypted_path = NULL;
    char *decrypted_path = NULL;
    if (argc > 2) {
        encrypted_path = argv[2];
    } else {
        encrypted_path = (char*) malloc(sizeof(char) * PATH_MAX);
        snprintf(encrypted_path, PATH_MAX, "%s.en", argv[1]);
    }
    if (argc > 3) {
        decrypted_path = argv[2];
    } else {
        decrypted_path = (char*) malloc(sizeof(char) * PATH_MAX);
        snprintf(decrypted_path, PATH_MAX, "%s.de", argv[1]);
    }

    encrypt(input_path, encrypted_path, key);
    printf("=======================================\n");
    decrypt(encrypted_path, decrypted_path, key);

    Timer timer;
    startTime(&timer);
    printf("start verifying original file {%s} and decrypted file {%s}\n", input_path, decrypted_path);
    bool result = verify(input_path, decrypted_path);
    stopTime(&timer);
    printf("%f s\n", elapsedTime(timer));
    if (result) {
        printf("verify success, two files are identical\n");
    } else {
        printf("verify fail, two files are different\n");
    }
    if (argc <= 2) {
        free(encrypted_path);
    }
    if (argc <= 3) {
        free(decrypted_path);
    }
    return 0;
}
