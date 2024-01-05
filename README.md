# Shellcode reflective DLL injection in C++

Reflective DLL injection demo for fun and education. In practical applications, there's significant scope for enhancing build sizes, obfuscation, and delivery logic.

[A blog post describing the technicalities of sRDI.](https://golfed.xyz/blog/understanding-srdi/)

### Project Structure

```shell
.
├── build.sh            # Build script (cmake & make)
├── generator           # Shellcode generator (ties together bootstrap, loader, payload, and user data)
├── injector            # PoC injector
├── payload             # PoC payload (DllMain & PrintMessage(lpUserData))
├── reflective_loader   # sRDI implementation
├── shared              # Common cryptographic & file modules
└── toolchains          # Cross-compilation toolchains (linux & darwin)
```

### Features

- Hashed import names & indirect function calls
- Randomized export iteration & IAT patching
- XOR encryption for shellcode (randomized key generated during shellcode generation)

Check out [Alcatraz](https://github.com/weak1337/Alcatraz/) for additional obfuscation for the shellcode/injector.

### Usage

Compile the libraries and executables with the included `build.sh` shellscript (if cross-compiling).

### Disclaimer

Information and code provided on this repository are for educational purposes only. The creator is in no way responsible for any direct or indirect damage caused due to the misuse of the information.

### Credits

- Stephen Fewer ([@stephenfewer](https://github.com/stephenfewer)) for reflective DLL injection
- Nick Landers ([@monoxgas](https://github.com/monoxgas)) for shellcode generator
- [@memN0ps](https://github.com/memN0ps) for bootstrap shellcode
