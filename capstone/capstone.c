/* cstdlib */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

/* autils */
#include "autils/bytes.h"
#include "autils/parsing.h"

/* capstone stuff */
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <capstone/arm.h>
#include <capstone/arm64.h>

/* forward declarations */
int arch_tostr(cs_arch arch, char *buf);
int mode_tostr(cs_arch arch, cs_mode mode, char *buf);
void usage(char **av);

/* main */
int main(int ac, char **av)
{
	int rc = -1;
	int code_size, i, j, len, byte_idx;
	bool inp_bits = false, inp_bytes = true;
	bool verbose = true;
	uint8_t code[1024];

	/* capstone variables */
	csh handle; /* capstone handle is typedef'd size_t */
	cs_arch arch;
	cs_mode mode = (cs_mode)0;
	cs_insn *insn = NULL; /* detailed instruction information
					cs_disasm() will allocate array of cs_insn here */
	size_t instr_count; /* number of instructions disassembled
					(number of cs_insn allocated) */
	int max_instr_size = 0;

	/* parse args */
	if(ac == 1) {
		usage(av);
		goto cleanup;
	}

	/* parse architecture */
	if(!strcmp(av[1], "x86")) {
		arch = CS_ARCH_X86;
	}
	else if(!strcmp(av[1], "x64")) {
		arch = CS_ARCH_X86;
		mode |= CS_MODE_64;
	}
	else if(!strcmp(av[1], "arm")) {
		arch = CS_ARCH_ARM;
	}
	else if(!strcmp(av[1], "arm64")) {
		arch = CS_ARCH_ARM64;
	}
	else if(!strcmp(av[1], "thumb")) {
		arch = CS_ARCH_ARM;
		mode |= CS_MODE_THUMB;
	}
	else {
		printf("ERROR: unrecognized architecture: %s\n\n", av[1]);
		usage(av);
		goto cleanup;
	}

	/* parse options */
	for(byte_idx = 2; byte_idx < ac; byte_idx++) {
		if(!strcmp(av[byte_idx], "lilend")) {
			mode |= CS_MODE_LITTLE_ENDIAN;
			mode &= (~CS_MODE_BIG_ENDIAN);
		}
		else if(!strcmp(av[byte_idx], "bigend")) {
			mode |= CS_MODE_BIG_ENDIAN;
			mode &= (~CS_MODE_LITTLE_ENDIAN);
		}
		else if(!strcmp(av[byte_idx], "bin")) {
			inp_bits = true;
			inp_bytes = false;
		}
		else if(!strcmp(av[byte_idx], "verbose")) {
			verbose = true;
		}
		else {
			if(0 == parse_uint8_hex(av[byte_idx], code))
				break;
			if(0 == parse_bit_list(av + byte_idx, code_size, code))
				break;

			printf("ERROR: unrecognized option: %s\n\n", av[byte_idx]);
			usage(av);
			goto cleanup;
		}
	}

	/* parse bits or bytes */
	if(0 == parse_byte_list(av + byte_idx, ac - byte_idx, code))
		inp_bytes = true;
	if(0 == parse_bit_list(av + byte_idx, ac - byte_idx, code))
		inp_bits = true;
	if(!inp_bytes && !inp_bits) {
		printf("ERROR: could not parse bytes or bits\n");
		usage(av);
		goto cleanup;
	}
	if(inp_bytes && inp_bits) {
		if(ac - byte_idx >= 3)
			inp_bytes = false;
		else
			inp_bits = false;
	}

	if(inp_bytes) {
		code_size = ac - byte_idx;
		if(code_size < 1) {
			printf("ERROR: no bytes provided\n");
			usage(av);
			goto cleanup;
		}
		parse_byte_list(av + byte_idx, code_size, code);
	}

	if(inp_bits) {
		code_size = 0;
		for(i=byte_idx; i<ac; ++i)
			code_size += strlen(av[i]);
		code_size = (code_size + 7)/8;

		parse_bit_list(av + byte_idx, ac - byte_idx, code);

		mode |= CS_MODE_BIG_ENDIAN;
	}

	/* print the setup */
	if(verbose) {
		char str[128];
		arch_tostr(arch, str);
		printf(" arch: %08X (%s)\n", arch, str);
		mode_tostr(arch, mode, str);
		printf(" mode: %08X (%s)\n", mode, str);
		printf("bytes:");
		for(i=0; i<code_size; ++i)
			printf(" %02X", code[i]);

		// print the fetched instruction word for ARM, THUMB
		if(arch == CS_ARCH_ARM) {
			printf(" (instruction word: ");

			if(mode & CS_MODE_THUMB) {
				if(code_size == 2 && (mode & CS_MODE_BIG_ENDIAN))
					printf("%02X%02X", code[0], code[1]);
				else if(code_size == 2 && !(mode & CS_MODE_BIG_ENDIAN))
					printf("%02X%02X", code[1], code[0]);
				else if(code_size == 4 && (mode & CS_MODE_BIG_ENDIAN))
					printf("%02X%02X%02X%02X", code[0], code[1], code[2], code[3]);
				else if(code_size == 4 && !(mode & CS_MODE_BIG_ENDIAN))
					/* (unlike arm) two 2-byte fetches */
					printf("%02X%02X%02X%02X", code[1], code[0], code[3], code[2]);
				else
					printf("error");
			}
			else {
				if(code_size == 4 && (mode & CS_MODE_BIG_ENDIAN))
					printf("%02X%02X%02X%02X", code[0], code[1], code[2], code[3]);
				else if(code_size == 4 && !(mode & CS_MODE_BIG_ENDIAN))
					/* (unlike thumb) one 32-bit fetch */
					printf("%02X%02X%02X%02X", code[3], code[2], code[1], code[0]);
				else
					printf("error");
			}
			
			printf(")");
		}

		printf("\n\n");
	}

	/* disassemble */
	if(cs_open(
	  arch /* cs_arch */,
	  mode /* cs_mode */,
	  &handle /* csh * */) != CS_ERR_OK) {
		printf("ERROR: cs_open()\n");
		goto cleanup;
	}

	instr_count = cs_disasm(handle, code,
		code_size /* code_size */,
		0 /* address */,
		0 /* instr count (0 to consume all) */,
		&insn /* result */
	);

	if(instr_count <= 0) {
		printf("ERROR: cs_disasm() returned %zu\n", instr_count);
		goto cleanup;
	}

	/* print instructions */
	for(i=0; i<instr_count; ++i)
		if(insn[i].size > max_instr_size)
			max_instr_size = insn[i].size;

	for(i=0; i<instr_count; ++i) {
		/* bytes */
		for(j=0; j<max_instr_size; ++j) {
			if(j<insn[i].size)
				printf("%02X", insn[i].bytes[j]);
			else
				printf("  ");

			if(j < max_instr_size - 1)
				printf(" ");
		}

		/* opcode, operands */
		printf("\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
	}

	/* done */
	rc = 0;
	cleanup:
	if(insn)
		cs_free(insn, instr_count);
	return rc;
}

void usage(char **av)
{
	printf("usage: %s <arch> <options> <bytes>\n", av[0]);
	printf("\n");
	printf("{x86, x64, arm, arm64, thumb} are architectures\n");
	printf("{bigend, lilend, bin, verbose} are options\n");
	printf("\n");
	printf("examples:\n");
	printf("%s arm 0c c0 9f e5\n", av[0]);
	printf("%s thumb 01 bc 04 f9 ef 8a\n", av[0]);
	printf("%s x64 ff 35 01 00 00 00\n", av[0]);
	printf("\n");
}

int arch_tostr(cs_arch arch, char *buf)
{
	int rc = 0;

	if(arch == CS_ARCH_ARM) strcpy(buf, "CS_ARCH_ARM");
	else if(arch == CS_ARCH_ARM64) strcpy(buf, "CS_ARCH_ARM64");
	else if(arch == CS_ARCH_MIPS) strcpy(buf, "CS_ARCH_MIPS");
	else if(arch == CS_ARCH_X86) strcpy(buf, "CS_ARCH_X86");
	else if(arch == CS_ARCH_PPC) strcpy(buf, "CS_ARCH_PPC");
	else if(arch == CS_ARCH_SPARC) strcpy(buf, "CS_ARCH_SPARC");
	else if(arch == CS_ARCH_SYSZ) strcpy(buf, "CS_ARCH_SYSZ");
	else if(arch == CS_ARCH_XCORE) strcpy(buf, "CS_ARCH_XCORE");
	else {
		rc = -1;
		strcpy(buf, "error");
	}

	return rc;
}

int mode_tostr(cs_arch arch, cs_mode mode, char *buf_)
{
	char buf[128] = {'\0'};

	/* modes decode based on arch */
	if(arch == CS_ARCH_ARM) {
		if(mode & CS_MODE_BIG_ENDIAN)
			strcat(buf, " BIG_ENDIAN");
		else
			strcat(buf, " LITTLE_ENDIAN");

		if(mode & CS_MODE_ARM) strcat(buf, " ARM");
		if(mode & CS_MODE_THUMB) strcat(buf, " THUMB");
		if(mode & CS_MODE_MCLASS) strcat(buf, " MCLASS");
		if(mode & CS_MODE_V8) strcat(buf, " V8");
	}
	else if(arch == CS_ARCH_ARM64) {
		while(0);
	}
	if(arch == CS_ARCH_MIPS) {
		if(mode & CS_MODE_MICRO) strcat(buf, "MICRO");
		if(mode & CS_MODE_MIPS3) strcat(buf, "MIPS3");
		if(mode & CS_MODE_MIPS32R6) strcat(buf, "MIPS32R6");
		if(mode & CS_MODE_MIPSGP64) strcat(buf, "MIPSGP64");
		if(mode & CS_MODE_MIPS32) strcat(buf, "MIPS32");
		if(mode & CS_MODE_MIPS64) strcat(buf, "MIPS64");
	}
	if(arch == CS_ARCH_X86) {
		if(mode & CS_MODE_16) strcat(buf, " 16");
		if(mode & CS_MODE_16) strcat(buf, " 32");
		if(mode & CS_MODE_16) strcat(buf, " 64");
	}
	if(arch == CS_ARCH_PPC) {
		if(mode & CS_MODE_16) strcat(buf, " 64");
	}
	if(arch == CS_ARCH_SPARC) {
		if(mode & CS_MODE_V9) strcat(buf, " V9");
	}
	if(arch == CS_ARCH_SYSZ) {
		while(0);
	}
	if(arch == CS_ARCH_XCORE) {
		while(0);
	}

	strcpy(buf_, buf+1);
	return 0;
}
