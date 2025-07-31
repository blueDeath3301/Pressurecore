# Pressurecore

Pressurecore is a position-independent code (PIC) framework for Rust shellcoding, inspired by [Rustic64](https://github.com/safedv/Rustic64) and the original C++ implementation [Stardust](https://github.com/Cracked5pider/Stardust). This project is designed for advanced shellcode development on Windows x64, focusing on stealth and reliability.

## Features

- **no_std**: Minimal runtime, suitable for shellcode and payloads.
- **x64 Only**: Supports only 64-bit Windows targets.
- **SSN Syscalls**: Uses direct syscall numbers for Windows API calls.
- **Vectored Exception Handling (VEH)**: Implements VEH for stealthy syscall invocation.
- **Custom Build Pipeline**: See `Makefile.toml` for the full procedure to compile, strip, and extract raw shellcode binaries.

## Building

The build process is managed via [cargo-make](https://sagiegurari.github.io/cargo-make/). The provided `Makefile.toml` automates:

1. Cleaning previous builds.
2. Compiling with custom Rust flags for PIC and stealth.
3. Stripping unnecessary sections.
4. Extracting raw shellcode using `objcopy`.

**Example:**
```sh
cargo make
```
The final shellcode will be output as `pressurecore.bin`.

## Usage

The output shellcode (`pressurecore.bin`) can be injected into remote processes using various injection techniques.  
**Known Issue:** The shellcode may terminate before the payload executes when injected. Investigation is ongoing — pull requests and suggestions are welcome!

## Credits

- [Rustic64](https://github.com/safedv/Rustic64)
- [Stardust](https://github.com/Cracked5pider/Stardust)
- [RustVEHSyscalls](https://github.com/safedv/RustVEHSyscalls)

## Contributing

Feel free to open issues or submit pull requests, especially regarding shellcode reliability and injection methods.

## License