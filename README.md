# Shellcode reflective DLL injection in Rust

Reflective DLL injection demo for fun and education. In practical applications, there's significant scope for enhancing build sizes, obfuscation, and delivery logic.

[A blog post describing the technicalities of sRDI.](https://golfed.xyz/blog/understanding-srdi/)

### Project Structure

```shell
.
├── generator           # Shellcode generator (ties together bootstrap, loader, payload, and user data)
├── injector            # PoC injector
├── payload             # PoC payload (DllMain and PrintMessage)
└── reflective_loader   # sRDI implementation
```

### Features

- Compact filesize (~14 kB)
- Hashed import names & indirect function calls
- Randomized payload export iteration & IAT patching
- XOR encryption for shellcode (shellcode generation specific keys)

Check out [Alcatraz](https://github.com/weak1337/Alcatraz/) for additional obfuscation for the shellcode/injector.

### Usage

The following command compiles the DLLs and executables into `target`:

```shell
$ cargo build --release
```

1. Generate shellcode containing the loader and the payload
2. Inject the created shellcode into target

### Disclaimer

Information and code provided on this repository are for educational purposes only. The creator is in no way responsible for any direct or indirect damage caused due to the misuse of the information.

### Credits

- Stephen Fewer ([@stephenfewer](https://github.com/stephenfewer)) for reflective DLL injection
- Nick Landers ([@monoxgas](https://github.com/monoxgas)) for shellcode generator
- [@memN0ps](https://github.com/memN0ps) for bootstrap shellcode
