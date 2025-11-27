#!/bin/bash
echo "編譯 Linux Shellcode Dropper..."
gcc -o linux_dropper linux_dropper.c -Wall -Wextra -O2 -fno-stack-protector -z execstack
echo "編譯完成！執行檔: linux_dropper"
