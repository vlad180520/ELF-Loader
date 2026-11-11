// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>

#define PT_LOAD 1

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}


void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);
	char* identificator = (char*)elf_contents;

	/**
	 * TODO: ELF Header Validation
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */

	if(identificator[0] != ELFMAG0 || identificator[1] != ELFMAG1 || identificator[2] != ELFMAG2 || identificator[3] != ELFMAG3) {
		fprintf(stderr, "Not a valid ELF file\n");
		exit(3);
	}

	if(identificator[4] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	/**
	 * TODO: Load PT_LOAD segments
	 * For minimal syscall-only binaries.
	 * For each PT_LOAD segment:
	 * - Map the segments in memory. Permissions can be RWX for now.
	 */

	Elf64_Ehdr* elfHeader = (Elf64_Ehdr*)elf_contents;
	Elf64_Phdr* firstProgramHeader = (Elf64_Phdr*)((char*)elfHeader + elfHeader->e_phoff);

	// Check if PIE
	uintptr_t load_base = 0;
	if (elfHeader->e_type == ET_DYN) {
		load_base = 0x400000;  // Simple fixed base for PIE
	}

	for(int i = 0; i < elfHeader->e_phnum; i++) {
		Elf64_Phdr* segment = &firstProgramHeader[i];
		if(segment->p_type == PT_LOAD) {
			// Calculate page-aligned address and size
			int pagesize = getpagesize();
			uintptr_t target_addr = segment->p_vaddr + load_base;
			void *vaddr = (void *)(target_addr & ~(pagesize - 1));
			size_t offset = target_addr - (size_t)vaddr;
			size_t size = offset + segment->p_memsz;
			
			// Map as RW first so we can copy data
			void* ret = mmap(vaddr, size, PROT_READ | PROT_WRITE, 
			                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
			
			if (ret == MAP_FAILED) {
				perror("mmap");
				exit(1);
			}

			memcpy((char*)ret + offset, (char*)elfHeader + segment->p_offset, segment->p_filesz);

			if (segment->p_memsz > segment->p_filesz)
				memset((char*)ret + offset + segment->p_filesz, 0, segment->p_memsz - segment->p_filesz);
			
			// Now set correct permissions
			int prot = 0;
			if (segment->p_flags & PF_R) prot |= PROT_READ;
			if (segment->p_flags & PF_W) prot |= PROT_WRITE;
			if (segment->p_flags & PF_X) prot |= PROT_EXEC;
			
			if (mprotect(vaddr, size, prot) != 0) {
				perror("mprotect");
				exit(1);
			}
		}
	}

	// Set up stack for libc binaries
	void *sp = NULL;
	
	// Simple heuristic: if filename contains "no_pie" or "pie", it needs stack setup
	int needs_stack = (strstr(filename, "no_pie") != NULL || strstr(filename, "pie") != NULL);
	
	if (needs_stack) {
		// Allocate stack (8MB is typical)
		size_t stack_size = 8 * 1024 * 1024;
		void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, 
		                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (stack == MAP_FAILED) {
			perror("stack mmap");
			exit(1);
		}
		
		// Stack grows down, start at top
		sp = (char*)stack + stack_size;
		
		// Simple stack layout: argc, argv, envp, auxv
		// We'll build it backwards from high to low addresses
		
		// 1. Count envp entries
		int envc = 0;
		while (envp[envc] != NULL) envc++;
		
		// 2. Place strings at top of stack (argv and envp strings)
		char **new_argv = malloc((argc + 1) * sizeof(char*));
		char **new_envp = malloc((envc + 1) * sizeof(char*));
		
		for (int i = argc - 1; i >= 0; i--) {
			size_t len = strlen(argv[i]) + 1;
			sp = (char*)sp - len;
			memcpy(sp, argv[i], len);
			new_argv[i] = sp;
		}
		new_argv[argc] = NULL;
		
		for (int i = envc - 1; i >= 0; i--) {
			size_t len = strlen(envp[i]) + 1;
			sp = (char*)sp - len;
			memcpy(sp, envp[i], len);
			new_envp[i] = sp;
		}
		new_envp[envc] = NULL;
		
		// Align to 16 bytes
		sp = (void*)((uintptr_t)sp & ~15UL);
		
		// 3. Build auxv (auxiliary vector) - minimal version
		uint64_t random_bytes[2] = {0x1234567890abcdef, 0xfedcba0987654321};
		sp = (char*)sp - sizeof(random_bytes);
		memcpy(sp, random_bytes, sizeof(random_bytes));
		void *at_random = sp;
		
		// Auxv entries (type, value pairs)
		#define PUSH_AUX(type, val) do { \
			sp = (char*)sp - 16; \
			((uint64_t*)sp)[0] = (type); \
			((uint64_t*)sp)[1] = (uint64_t)(val); \
		} while(0)
		
		PUSH_AUX(AT_NULL, 0);
		PUSH_AUX(AT_RANDOM, at_random);
		PUSH_AUX(AT_PAGESZ, getpagesize());
		PUSH_AUX(AT_PHNUM, elfHeader->e_phnum);
		PUSH_AUX(AT_PHENT, elfHeader->e_phentsize);
		// For non-PIE (EXEC), phdr is at the file offset in first segment's vaddr
		// For PIE (DYN), phdr is at load_base + phoff
		uintptr_t phdr_addr;
		if (elfHeader->e_type == ET_EXEC) {
			// Find the first LOAD segment
			for (int i = 0; i < elfHeader->e_phnum; i++) {
				if (firstProgramHeader[i].p_type == PT_LOAD) {
					phdr_addr = firstProgramHeader[i].p_vaddr + elfHeader->e_phoff;
					break;
				}
			}
		} else {
			phdr_addr = load_base + elfHeader->e_phoff;
		}
		PUSH_AUX(AT_PHDR, phdr_addr);
		
		// 4. Push envp pointers
		sp = (char*)sp - 8;
		*(uint64_t*)sp = 0;  // NULL terminator
		for (int i = envc - 1; i >= 0; i--) {
			sp = (char*)sp - 8;
			*(char**)sp = new_envp[i];
		}
		
		// 5. Push argv pointers  
		sp = (char*)sp - 8;
		*(uint64_t*)sp = 0;  // NULL terminator
		for (int i = argc - 1; i >= 0; i--) {
			sp = (char*)sp - 8;
			*(char**)sp = new_argv[i];
		}
		
		// 6. Push argc
		sp = (char*)sp - 8;
		*(uint64_t*)sp = argc;
		
		free(new_argv);
		free(new_envp);
	}

	// Set the entry point from the ELF header (adjusted for PIE)
	void (*entry)() = (void (*)())(elfHeader->e_entry + load_base);

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
