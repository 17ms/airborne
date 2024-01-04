# Shellcode reflective DLL injection in C++

```shell
.
├── build.sh            # Build script (cmake & make)
├── generator           # Shellcode generator (ties together bootstrap, loader, payload, and user data)
├── injector            # PoC injector
├── payload             # PoC payload (DllMain & PrintMessage(lpUserData))
├── reflective_loader   # sRDI implementation
└── toolchains          # Cross-compilation toolchains (linux & darwin)
```

### Features

Placeholder.

Check out [Alcatraz](https://github.com/weak1337/Alcatraz/) for additional obfuscation for the shellcode/injector.

### Usage

Compile the libraries and executables with the included `build.sh` shellscript (if cross-compiling).

### Credits

- Stephen Fewer ([@stephenfewer](https://github.com/stephenfewer)) for reflective DLL injection
- Nick Landers ([@monoxgas](https://github.com/monoxgas)) for shellcode generator
- [@memN0ps](https://github.com/memN0ps) for bootstrap shellcode
