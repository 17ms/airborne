#include <windows.h>
#include <iostream>
#include <fstream>

#define VERBOSE 1

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::cout << "[?] Usage: " << argv[0] << " <shellcode-path>" << std::endl;
        return 1;
    }

#ifdef VERBOSE
    std::cout << "[+] Reading shellcode from " << argv[1] << std::endl;
#endif

    std::ifstream shellcode(argv[1]);

    if (!shellcode.is_open())
    {
        std::cout << "[!] Failed to open " << argv[1] << std::endl;
        return 1;
    }

    shellcode.seekg(0, std::ios::end);
    size_t filesize = shellcode.tellg();
    shellcode.seekg(0, std::ios::beg);

    auto buffer = new char[filesize];
    shellcode.read(buffer, filesize);

    auto base = VirtualAlloc(nullptr, filesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!base)
    {
        std::cout << "[!] Failed to allocate memory" << std::endl;
        return 1;
    }

#ifdef VERBOSE
    std::cout << "[+] Allocated " << filesize << " bytes at " << base << std::endl;
#endif

    std::copy(buffer, buffer + filesize, static_cast<char *>(base));

#ifdef VERBOSE
    std::cout << "[+] Copied shellcode to " << base << std::endl;
    std::cout << "[+] Executing 'jmp " << base << "'" << std::endl;
#endif

    __asm__("jmp *%0" ::"r"(base));

    return 0;
}
