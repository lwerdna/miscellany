/* */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "autils/bytes.h"
#include "autils/parsing.h"

/* capstone stuff */
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <capstone/arm.h>
#include <capstone/arm64.h>

void usage(char **av)
{
	printf("usage: %s <arch> <options> <bytes>\n", av[0]);
	printf("\n");
	printf("{x86, x64, arm, arm64, thumb} are architectures\n");
	printf("{bigend, lilend, verbose} are options\n");
	printf("\n");
	printf("examples:\n");
	printf("%s arm 0c c0 9f e5\n", av[0]);
	printf("%s thumb 01 bc 04 f9 ef 8a\n", av[0]);
	printf("%s x64 ff 35 01 00 00 00\n", av[0]);
	printf("\n");
}

int main(int ac, char **av)
{
	int rc = -1;
	int code_size, i, j, byte_idx;
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
		if(!strcmp(av[1], "lilend")) {
			mode |= CS_MODE_LITTLE_ENDIAN;
			mode &= (~CS_MODE_BIG_ENDIAN);
		}
		else if(!strcmp(av[1], "bigend")) {
			mode |= CS_MODE_BIG_ENDIAN;
			mode &= (~CS_MODE_LITTLE_ENDIAN);
		}
		else if(!strcmp(av[1], "verbose")) {
			verbose = true;
		}
		else {
			if(0 == parse_uint8_hex(av[byte_idx], code))
				break;

			printf("ERROR: unrecognized option: %s\n\n", av[byte_idx]);
			usage(av);
			goto cleanup;
		}
	}

	/* parse bytes */
	code_size = ac - byte_idx;
	if(code_size < 1) {
		printf("ERROR: no bytes provided\n");
		usage(av);
		goto cleanup;
	}
	code_size = ac - byte_idx;
	parse_byte_list(av + byte_idx, code_size, code);

	/* print the setup */
	if(verbose) {
		printf(" arch: %08X\n", arch);
		printf(" mode: %08X\n", mode);
		printf("bytes:");
		for(i=0; i<code_size; ++i)
			printf(" %02X", code[i]);
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

