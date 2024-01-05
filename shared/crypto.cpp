#include "crypto.hpp"

std::vector<BYTE> GenerateKey(size_t keysize)
{
    std::vector<BYTE> key(keysize, 0);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < key.size(); ++i)
    {
        key[i] = static_cast<BYTE>(dis(gen));
    }

    return key;
}

void XorCipher(std::vector<BYTE> &data, const std::vector<BYTE> &key)
{
    for (size_t i = 0; i < data.size(); i++)
    {
        data[i] = data[i] ^ key[i % key.size()];
    }
}

DWORD CalculateHash(const std::string &source)
{
    auto dwHash = HASH_KEY;

    for (char ch : source)
    {
        if (ch == '\0')
        {
            continue;
        }

        if (ch >= 'a' && ch <= 'z')
        {
            ch -= 0x20;
        }

        // Casting might be unnecessary
        dwHash = ((dwHash << 5) + dwHash) + static_cast<DWORD>(ch);
    }

    return dwHash;
}

DWORD CalculateHash(const UNICODE_STRING &baseDllName)
{
    auto pwszBaseDllName = baseDllName.Buffer;
    auto dwHash = HASH_KEY;

    char ch;

    for (auto i = 0; i < baseDllName.MaximumLength; i++)
    {
        ch = pwszBaseDllName[i];

        if (ch == '\0')
        {
            continue;
        }

        if (ch >= 'a' && ch <= 'z')
        {
            ch -= 0x20;
        }

        // Casting might be unnecessary
        dwHash = ((dwHash << 5) + dwHash) + static_cast<DWORD>(ch);
    }

    return dwHash;
}
