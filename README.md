# ELF Loader

**Author:** Vlad Parau

A minimal ELF loader in C for Linux x86-64 that loads and runs statically linked 64-bit executables without using the kernel's own loader. Built for the Operating Systems course at the National University of Science and Technology POLITEHNICA Bucharest (2025). The original assignment statement is in [ASSIGNMENT.md](ASSIGNMENT.md).

The loader runs three kinds of binaries:

- minimal static binaries that make Linux syscalls directly (no libc)
- statically linked non-PIE C programs using libc
- statically linked PIE executables

## How it works

The implementation is in [`src/elf-loader.c`](src/elf-loader.c).

1. **Validation** - maps the file into memory and checks the ELF magic bytes and the 64-bit class, exiting with code 3 or 4 if either check fails.
2. **Loading segments** - for every `PT_LOAD` program header, maps an anonymous region at the page-aligned virtual address with `mmap`, copies the segment's bytes from the file and zero-fills the rest of the region (`p_memsz > p_filesz`, i.e. `.bss`).
3. **Memory protection** - each region is mapped read/write first so its contents can be copied, then switched to the permissions from the segment's `p_flags` (`PF_R`, `PF_W`, `PF_X`) with `mprotect`.
4. **PIE support** - position-independent executables (`ET_DYN`) are loaded at a fixed base address (`0x400000`), and every address taken from the ELF file is offset by it.
5. **Process stack** - allocates an 8 MB stack and builds the layout a libc program expects at startup: the argument and environment strings, then the auxiliary vector (`AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ`, `AT_RANDOM`, `AT_NULL`), the `envp` and `argv` pointer arrays and finally `argc`.
6. **Transfer of control** - sets the stack pointer and jumps to the entry point (`e_entry`, offset by the PIE base) with inline assembly.

## Build and run

Requires Linux x86-64 and `gcc`. The tests also need `nasm`.

```sh
cd src
make
./elf-loader <static-elf-binary> [args...]
```

To build the test programs and run the test suite:

```sh
cd tests
make
./run_tests.sh
```

## Limitations

- PIE binaries are always loaded at the same fixed base address instead of a randomized one.
- Whether to build a full process stack is decided from the binary's file name (it must contain `pie`), a shortcut that matches the test suite's naming rather than inspecting the binary itself.
- The 16 bytes pointed to by `AT_RANDOM` are constant instead of random.
- Dynamically linked executables are not supported.

## Acknowledgements

The skeleton code, test suite and checker come from the [Operating Systems course](https://gitlab.upb.ro/operating-systems/assignment-elf-loader) at POLITEHNICA Bucharest.
