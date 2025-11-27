#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void xor_encrypt(unsigned char *data, unsigned int data_len, unsigned char key) {
    for (unsigned int i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key;
    }
}

void xor_decrypt(unsigned char *data, unsigned int data_len, unsigned char key) {
    xor_encrypt(data, data_len, key);
}

void generate_encrypted_shellcode() {
    unsigned char key = 0xAA;
    #include "shellcode.h"
    unsigned char *encrypted = malloc(shellcode_len);
    memcpy(encrypted, shellcode, shellcode_len);
    xor_encrypt(encrypted, shellcode_len, key);
    printf("// 加密金鑰: 0x%02X\n", key);
    printf("unsigned char encrypted_shellcode[] = {\n    ");
    for (unsigned int i = 0; i < shellcode_len; i++) {
        printf("0x%02X", encrypted[i]);
        if (i < shellcode_len - 1) { printf(", "); }
        if ((i + 1) % 12 == 0) { printf("\n    "); }
    }
    printf("\n};\n");
    printf("unsigned int shellcode_len = %u;\n", shellcode_len);
    free(encrypted);
}
