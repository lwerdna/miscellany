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
#include <capstone/ppc.h>

/* forward declarations */
int arch_tostr(cs_arch arch, char *buf);
int mode_tostr(cs_arch arch, cs_mode mode, char *buf);
char *cs_err_tostr(int err);
/* ppc */
void ppc_print_detail(csh handle, cs_insn *insn);
char *ppc_grp_tostr(int grp);
char *ppc_bc_tostr(int id);
char *ppc_bh_to_str(int id);
char *ppc_ins_tostr(int id);


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
	size_t instr_count; /* number of instructions disassembled
					(number of cs_insn allocated) */
	int max_instr_size = 0;
	/* here is the capstone triple: cs_insn, cs_detail, cs_<arch> */
	cs_insn *insn = NULL; /* detailed instruction information
					cs_disasm() will allocate array of cs_insn here */
	cs_detail *detail;
	cs_ppc *ppc;

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
	else if(!strcmp(av[1], "ppc")) {
		arch = CS_ARCH_PPC;
		mode |= CS_MODE_BIG_ENDIAN; /* default */
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

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

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

	/* print instruction(s) */
	for(i=0; i<instr_count; ++i)
		if(insn[i].size > max_instr_size)
			max_instr_size = insn[i].size;

	for(i=0; i<instr_count; ++i) {
		printf("====instruction %d/%zu====\n", i+1, instr_count);

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

		/* architecture independent details
			all architecures have:
			- regs_read[]
			- regs_write[]
			- groups[] 
		*/
		detail = insn->detail;
		printf("         groups:");
		for(j=0; j<detail->groups_count; ++j) {
			int group = detail->groups[j];
			printf(" %d(%s)", group, cs_group_name(handle, group));
		}
		printf("\n");
		printf("     reads regs:");
		for(j=0; j<detail->regs_read_count; ++j) {
			printf(" %s", cs_reg_name(handle, detail->regs_read[j]));
		}
		printf("\n");
		printf("    writes regs:");
		for(j=0; j<detail->regs_write_count; ++j) {
			printf(" %s", cs_reg_name(handle, detail->regs_write[j]));
		}
		printf("\n");
			
		/* then there is union per-architecture (cs_x86, cs_arm64, cs_ppc, etc.) */
		if(arch == CS_ARCH_PPC) {
			ppc_print_detail(handle, insn);
		}
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

/*****************************************************************************/
/* GENERAL (ARCH UNSPECIFIC) CAPSTONE HELPERS */
/*****************************************************************************/

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

char *cs_err_tostr(int err)
{
	switch(err) {
		case CS_ERR_OK: return "CS_ERR_OK";
		case CS_ERR_MEM: return "CS_ERR_MEM";
		case CS_ERR_ARCH: return "CS_ERR_ARCH";
		case CS_ERR_HANDLE: return "CS_ERR_HANDLE";
		case CS_ERR_CSH: return "CS_ERR_CSH";
		case CS_ERR_MODE: return "CS_ERR_MODE";
		case CS_ERR_OPTION: return "CS_ERR_OPTION";
		case CS_ERR_DETAIL: return "CS_ERR_DETAIL";
		case CS_ERR_MEMSETUP: return "CS_ERR_MEMSETUP";
		case CS_ERR_VERSION: return "CS_ERR_VERSION";
		case CS_ERR_DIET: return "CS_ERR_DIET";
		case CS_ERR_SKIPDATA: return "CS_ERR_SKIPDATA";
		case CS_ERR_X86_ATT: return "CS_ERR_X86_ATT";
		case CS_ERR_X86_INTEL: return "CS_ERR_X86_INTEL";
		default: return "UNKNOWN";
	}
}

/*****************************************************************************/
/* PPC HELPERS */
/*****************************************************************************/
void ppc_print_detail(csh handle, cs_insn *ins)
{
	int j;
	cs_detail *detail = ins->detail;
	cs_ppc *ppc = &(detail->ppc);

	printf("      opcode ID: %d (%s)\n", ins->id, ppc_ins_tostr(ins->id));

	if(1 /* branch instruction */) {
		printf("    branch code: %d (%s)\n", ppc->bc,
		  ppc_bc_tostr(ppc->bc)); // PPC_BC_LT, PPC_BC_LE, etc.

		printf("    branch hint: %d (%s)\n", ppc->bh,
		  ppc_bh_to_str(ppc->bh)); // PPC_BH_PLUS, PPC_BH_MINUS
	}

	printf("     update_cr0: %d\n", ppc->update_cr0);

	for(j=0; j<ppc->op_count; ++j) {
		printf("       operand%d: ", j);

		// .op_count is number of operands
		// .operands[] is array of cs_ppc_op
		cs_ppc_op op = ppc->operands[j];

	 	switch(op.type) {
			case PPC_OP_INVALID:
				printf("invalid\n");
				break;
			case PPC_OP_REG:
				printf("reg: %s\n", cs_reg_name(handle, op.reg));
				break;
			case PPC_OP_IMM:
				printf("imm: 0x%X\n", op.imm);
				break;
			case PPC_OP_MEM:
				printf("mem (%s + 0x%X)\n", cs_reg_name(handle, op.mem.base),
					op.mem.disp);
				break;
			case PPC_OP_CRX:
				printf("crx (scale:%d, reg:%s)\n", op.crx.scale, 
					cs_reg_name(handle, op.crx.reg));
				break;
			default:
				printf("unknown (%d)\n", op.type);
				break;
		}
	}
}

char *ppc_grp_tostr(int grp)
{
	switch(grp) {
		case PPC_GRP_ALTIVEC: return "PPC_GRP_ALTIVEC";
		case PPC_GRP_MODE32: return "PPC_GRP_MODE32";
		case PPC_GRP_MODE64: return "PPC_GRP_MODE64";
		case PPC_GRP_BOOKE: return "PPC_GRP_BOOKE";
		case PPC_GRP_NOTBOOKE: return "PPC_GRP_NOTBOOKE";
		case PPC_GRP_SPE: return "PPC_GRP_SPE";
		case PPC_GRP_VSX: return "PPC_GRP_VSX";
		case PPC_GRP_E500: return "PPC_GRP_E500";
		case PPC_GRP_PPC4XX: return "PPC_GRP_PPC4XX";
		case PPC_GRP_PPC6XX: return "PPC_GRP_PPC6XX";
		default: return "UNKNOWN";
	}
}

char *ppc_bc_tostr(int id)
{
	switch(id) {
		case PPC_BC_INVALID: return "PPC_BC_INVALID";
		case PPC_BC_LT: return "PPC_BC_LT";
		case PPC_BC_LE: return "PPC_BC_LE";
		case PPC_BC_EQ: return "PPC_BC_EQ";
		case PPC_BC_GE: return "PPC_BC_GE";
		case PPC_BC_GT: return "PPC_BC_GT";
		case PPC_BC_NE: return "PPC_BC_NE";
		case PPC_BC_UN: return "PPC_BC_UN";
		case PPC_BC_NU: return "PPC_BC_NU";
		case PPC_BC_SO: return "PPC_BC_SO";
		case PPC_BC_NS: return "PPC_BC_NS";
		default:
			return "DUNNO";
	}
}

char *ppc_bh_to_str(int id)
{
	switch(id) {
		case PPC_BH_INVALID: return "PPC_BH_INVALID";
		case PPC_BH_PLUS: return "PPC_BH_PLUS";
		case PPC_BH_MINUS: return "PPC_BH_MINUS";
		default:
			return "DUNNO";
	}
}

char *ppc_ins_tostr(int id)
{
	switch(id) {
		case PPC_INS_ADD: return "PPC_INS_ADD";
		case PPC_INS_ADDC: return "PPC_INS_ADDC";
		case PPC_INS_ADDE: return "PPC_INS_ADDE";
		case PPC_INS_ADDI: return "PPC_INS_ADDI";
		case PPC_INS_ADDIC: return "PPC_INS_ADDIC";
		case PPC_INS_ADDIS: return "PPC_INS_ADDIS";
		case PPC_INS_ADDME: return "PPC_INS_ADDME";
		case PPC_INS_ADDZE: return "PPC_INS_ADDZE";
		case PPC_INS_AND: return "PPC_INS_AND";
		case PPC_INS_ANDC: return "PPC_INS_ANDC";
		case PPC_INS_ANDIS: return "PPC_INS_ANDIS";
		case PPC_INS_ANDI: return "PPC_INS_ANDI";
		case PPC_INS_B: return "PPC_INS_B";
		case PPC_INS_BA: return "PPC_INS_BA";
		case PPC_INS_BC: return "PPC_INS_BC";
		case PPC_INS_BCCTR: return "PPC_INS_BCCTR";
		case PPC_INS_BCCTRL: return "PPC_INS_BCCTRL";
		case PPC_INS_BCL: return "PPC_INS_BCL";
		case PPC_INS_BCLR: return "PPC_INS_BCLR";
		case PPC_INS_BCLRL: return "PPC_INS_BCLRL";
		case PPC_INS_BCTR: return "PPC_INS_BCTR";
		case PPC_INS_BCTRL: return "PPC_INS_BCTRL";
		case PPC_INS_BDNZ: return "PPC_INS_BDNZ";
		case PPC_INS_BDNZA: return "PPC_INS_BDNZA";
		case PPC_INS_BDNZL: return "PPC_INS_BDNZL";
		case PPC_INS_BDNZLA: return "PPC_INS_BDNZLA";
		case PPC_INS_BDNZLR: return "PPC_INS_BDNZLR";
		case PPC_INS_BDNZLRL: return "PPC_INS_BDNZLRL";
		case PPC_INS_BDZ: return "PPC_INS_BDZ";
		case PPC_INS_BDZA: return "PPC_INS_BDZA";
		case PPC_INS_BDZL: return "PPC_INS_BDZL";
		case PPC_INS_BDZLA: return "PPC_INS_BDZLA";
		case PPC_INS_BDZLR: return "PPC_INS_BDZLR";
		case PPC_INS_BDZLRL: return "PPC_INS_BDZLRL";
		case PPC_INS_BL: return "PPC_INS_BL";
		case PPC_INS_BLA: return "PPC_INS_BLA";
		case PPC_INS_BLR: return "PPC_INS_BLR";
		case PPC_INS_BLRL: return "PPC_INS_BLRL";
		case PPC_INS_BRINC: return "PPC_INS_BRINC";
		case PPC_INS_CMPD: return "PPC_INS_CMPD";
		case PPC_INS_CMPDI: return "PPC_INS_CMPDI";
		case PPC_INS_CMPLD: return "PPC_INS_CMPLD";
		case PPC_INS_CMPLDI: return "PPC_INS_CMPLDI";
		case PPC_INS_CMPLW: return "PPC_INS_CMPLW";
		case PPC_INS_CMPLWI: return "PPC_INS_CMPLWI";
		case PPC_INS_CMPW: return "PPC_INS_CMPW";
		case PPC_INS_CMPWI: return "PPC_INS_CMPWI";
		case PPC_INS_CNTLZD: return "PPC_INS_CNTLZD";
		case PPC_INS_CNTLZW: return "PPC_INS_CNTLZW";
		case PPC_INS_CREQV: return "PPC_INS_CREQV";
		case PPC_INS_CRXOR: return "PPC_INS_CRXOR";
		case PPC_INS_CRAND: return "PPC_INS_CRAND";
		case PPC_INS_CRANDC: return "PPC_INS_CRANDC";
		case PPC_INS_CRNAND: return "PPC_INS_CRNAND";
		case PPC_INS_CRNOR: return "PPC_INS_CRNOR";
		case PPC_INS_CROR: return "PPC_INS_CROR";
		case PPC_INS_CRORC: return "PPC_INS_CRORC";
		case PPC_INS_DCBA: return "PPC_INS_DCBA";
		case PPC_INS_DCBF: return "PPC_INS_DCBF";
		case PPC_INS_DCBI: return "PPC_INS_DCBI";
		case PPC_INS_DCBST: return "PPC_INS_DCBST";
		case PPC_INS_DCBT: return "PPC_INS_DCBT";
		case PPC_INS_DCBTST: return "PPC_INS_DCBTST";
		case PPC_INS_DCBZ: return "PPC_INS_DCBZ";
		case PPC_INS_DCBZL: return "PPC_INS_DCBZL";
		case PPC_INS_DCCCI: return "PPC_INS_DCCCI";
		case PPC_INS_DIVD: return "PPC_INS_DIVD";
		case PPC_INS_DIVDU: return "PPC_INS_DIVDU";
		case PPC_INS_DIVW: return "PPC_INS_DIVW";
		case PPC_INS_DIVWU: return "PPC_INS_DIVWU";
		case PPC_INS_DSS: return "PPC_INS_DSS";
		case PPC_INS_DSSALL: return "PPC_INS_DSSALL";
		case PPC_INS_DST: return "PPC_INS_DST";
		case PPC_INS_DSTST: return "PPC_INS_DSTST";
		case PPC_INS_DSTSTT: return "PPC_INS_DSTSTT";
		case PPC_INS_DSTT: return "PPC_INS_DSTT";
		case PPC_INS_EIEIO: return "PPC_INS_EIEIO";
		case PPC_INS_EQV: return "PPC_INS_EQV";
		case PPC_INS_EVABS: return "PPC_INS_EVABS";
		case PPC_INS_EVADDIW: return "PPC_INS_EVADDIW";
		case PPC_INS_EVADDSMIAAW: return "PPC_INS_EVADDSMIAAW";
		case PPC_INS_EVADDSSIAAW: return "PPC_INS_EVADDSSIAAW";
		case PPC_INS_EVADDUMIAAW: return "PPC_INS_EVADDUMIAAW";
		case PPC_INS_EVADDUSIAAW: return "PPC_INS_EVADDUSIAAW";
		case PPC_INS_EVADDW: return "PPC_INS_EVADDW";
		case PPC_INS_EVAND: return "PPC_INS_EVAND";
		case PPC_INS_EVANDC: return "PPC_INS_EVANDC";
		case PPC_INS_EVCMPEQ: return "PPC_INS_EVCMPEQ";
		case PPC_INS_EVCMPGTS: return "PPC_INS_EVCMPGTS";
		case PPC_INS_EVCMPGTU: return "PPC_INS_EVCMPGTU";
		case PPC_INS_EVCMPLTS: return "PPC_INS_EVCMPLTS";
		case PPC_INS_EVCMPLTU: return "PPC_INS_EVCMPLTU";
		case PPC_INS_EVCNTLSW: return "PPC_INS_EVCNTLSW";
		case PPC_INS_EVCNTLZW: return "PPC_INS_EVCNTLZW";
		case PPC_INS_EVDIVWS: return "PPC_INS_EVDIVWS";
		case PPC_INS_EVDIVWU: return "PPC_INS_EVDIVWU";
		case PPC_INS_EVEQV: return "PPC_INS_EVEQV";
		case PPC_INS_EVEXTSB: return "PPC_INS_EVEXTSB";
		case PPC_INS_EVEXTSH: return "PPC_INS_EVEXTSH";
		case PPC_INS_EVLDD: return "PPC_INS_EVLDD";
		case PPC_INS_EVLDDX: return "PPC_INS_EVLDDX";
		case PPC_INS_EVLDH: return "PPC_INS_EVLDH";
		case PPC_INS_EVLDHX: return "PPC_INS_EVLDHX";
		case PPC_INS_EVLDW: return "PPC_INS_EVLDW";
		case PPC_INS_EVLDWX: return "PPC_INS_EVLDWX";
		case PPC_INS_EVLHHESPLAT: return "PPC_INS_EVLHHESPLAT";
		case PPC_INS_EVLHHESPLATX: return "PPC_INS_EVLHHESPLATX";
		case PPC_INS_EVLHHOSSPLAT: return "PPC_INS_EVLHHOSSPLAT";
		case PPC_INS_EVLHHOSSPLATX: return "PPC_INS_EVLHHOSSPLATX";
		case PPC_INS_EVLHHOUSPLAT: return "PPC_INS_EVLHHOUSPLAT";
		case PPC_INS_EVLHHOUSPLATX: return "PPC_INS_EVLHHOUSPLATX";
		case PPC_INS_EVLWHE: return "PPC_INS_EVLWHE";
		case PPC_INS_EVLWHEX: return "PPC_INS_EVLWHEX";
		case PPC_INS_EVLWHOS: return "PPC_INS_EVLWHOS";
		case PPC_INS_EVLWHOSX: return "PPC_INS_EVLWHOSX";
		case PPC_INS_EVLWHOU: return "PPC_INS_EVLWHOU";
		case PPC_INS_EVLWHOUX: return "PPC_INS_EVLWHOUX";
		case PPC_INS_EVLWHSPLAT: return "PPC_INS_EVLWHSPLAT";
		case PPC_INS_EVLWHSPLATX: return "PPC_INS_EVLWHSPLATX";
		case PPC_INS_EVLWWSPLAT: return "PPC_INS_EVLWWSPLAT";
		case PPC_INS_EVLWWSPLATX: return "PPC_INS_EVLWWSPLATX";
		case PPC_INS_EVMERGEHI: return "PPC_INS_EVMERGEHI";
		case PPC_INS_EVMERGEHILO: return "PPC_INS_EVMERGEHILO";
		case PPC_INS_EVMERGELO: return "PPC_INS_EVMERGELO";
		case PPC_INS_EVMERGELOHI: return "PPC_INS_EVMERGELOHI";
		case PPC_INS_EVMHEGSMFAA: return "PPC_INS_EVMHEGSMFAA";
		case PPC_INS_EVMHEGSMFAN: return "PPC_INS_EVMHEGSMFAN";
		case PPC_INS_EVMHEGSMIAA: return "PPC_INS_EVMHEGSMIAA";
		case PPC_INS_EVMHEGSMIAN: return "PPC_INS_EVMHEGSMIAN";
		case PPC_INS_EVMHEGUMIAA: return "PPC_INS_EVMHEGUMIAA";
		case PPC_INS_EVMHEGUMIAN: return "PPC_INS_EVMHEGUMIAN";
		case PPC_INS_EVMHESMF: return "PPC_INS_EVMHESMF";
		case PPC_INS_EVMHESMFA: return "PPC_INS_EVMHESMFA";
		case PPC_INS_EVMHESMFAAW: return "PPC_INS_EVMHESMFAAW";
		case PPC_INS_EVMHESMFANW: return "PPC_INS_EVMHESMFANW";
		case PPC_INS_EVMHESMI: return "PPC_INS_EVMHESMI";
		case PPC_INS_EVMHESMIA: return "PPC_INS_EVMHESMIA";
		case PPC_INS_EVMHESMIAAW: return "PPC_INS_EVMHESMIAAW";
		case PPC_INS_EVMHESMIANW: return "PPC_INS_EVMHESMIANW";
		case PPC_INS_EVMHESSF: return "PPC_INS_EVMHESSF";
		case PPC_INS_EVMHESSFA: return "PPC_INS_EVMHESSFA";
		case PPC_INS_EVMHESSFAAW: return "PPC_INS_EVMHESSFAAW";
		case PPC_INS_EVMHESSFANW: return "PPC_INS_EVMHESSFANW";
		case PPC_INS_EVMHESSIAAW: return "PPC_INS_EVMHESSIAAW";
		case PPC_INS_EVMHESSIANW: return "PPC_INS_EVMHESSIANW";
		case PPC_INS_EVMHEUMI: return "PPC_INS_EVMHEUMI";
		case PPC_INS_EVMHEUMIA: return "PPC_INS_EVMHEUMIA";
		case PPC_INS_EVMHEUMIAAW: return "PPC_INS_EVMHEUMIAAW";
		case PPC_INS_EVMHEUMIANW: return "PPC_INS_EVMHEUMIANW";
		case PPC_INS_EVMHEUSIAAW: return "PPC_INS_EVMHEUSIAAW";
		case PPC_INS_EVMHEUSIANW: return "PPC_INS_EVMHEUSIANW";
		case PPC_INS_EVMHOGSMFAA: return "PPC_INS_EVMHOGSMFAA";
		case PPC_INS_EVMHOGSMFAN: return "PPC_INS_EVMHOGSMFAN";
		case PPC_INS_EVMHOGSMIAA: return "PPC_INS_EVMHOGSMIAA";
		case PPC_INS_EVMHOGSMIAN: return "PPC_INS_EVMHOGSMIAN";
		case PPC_INS_EVMHOGUMIAA: return "PPC_INS_EVMHOGUMIAA";
		case PPC_INS_EVMHOGUMIAN: return "PPC_INS_EVMHOGUMIAN";
		case PPC_INS_EVMHOSMF: return "PPC_INS_EVMHOSMF";
		case PPC_INS_EVMHOSMFA: return "PPC_INS_EVMHOSMFA";
		case PPC_INS_EVMHOSMFAAW: return "PPC_INS_EVMHOSMFAAW";
		case PPC_INS_EVMHOSMFANW: return "PPC_INS_EVMHOSMFANW";
		case PPC_INS_EVMHOSMI: return "PPC_INS_EVMHOSMI";
		case PPC_INS_EVMHOSMIA: return "PPC_INS_EVMHOSMIA";
		case PPC_INS_EVMHOSMIAAW: return "PPC_INS_EVMHOSMIAAW";
		case PPC_INS_EVMHOSMIANW: return "PPC_INS_EVMHOSMIANW";
		case PPC_INS_EVMHOSSF: return "PPC_INS_EVMHOSSF";
		case PPC_INS_EVMHOSSFA: return "PPC_INS_EVMHOSSFA";
		case PPC_INS_EVMHOSSFAAW: return "PPC_INS_EVMHOSSFAAW";
		case PPC_INS_EVMHOSSFANW: return "PPC_INS_EVMHOSSFANW";
		case PPC_INS_EVMHOSSIAAW: return "PPC_INS_EVMHOSSIAAW";
		case PPC_INS_EVMHOSSIANW: return "PPC_INS_EVMHOSSIANW";
		case PPC_INS_EVMHOUMI: return "PPC_INS_EVMHOUMI";
		case PPC_INS_EVMHOUMIA: return "PPC_INS_EVMHOUMIA";
		case PPC_INS_EVMHOUMIAAW: return "PPC_INS_EVMHOUMIAAW";
		case PPC_INS_EVMHOUMIANW: return "PPC_INS_EVMHOUMIANW";
		case PPC_INS_EVMHOUSIAAW: return "PPC_INS_EVMHOUSIAAW";
		case PPC_INS_EVMHOUSIANW: return "PPC_INS_EVMHOUSIANW";
		case PPC_INS_EVMRA: return "PPC_INS_EVMRA";
		case PPC_INS_EVMWHSMF: return "PPC_INS_EVMWHSMF";
		case PPC_INS_EVMWHSMFA: return "PPC_INS_EVMWHSMFA";
		case PPC_INS_EVMWHSMI: return "PPC_INS_EVMWHSMI";
		case PPC_INS_EVMWHSMIA: return "PPC_INS_EVMWHSMIA";
		case PPC_INS_EVMWHSSF: return "PPC_INS_EVMWHSSF";
		case PPC_INS_EVMWHSSFA: return "PPC_INS_EVMWHSSFA";
		case PPC_INS_EVMWHUMI: return "PPC_INS_EVMWHUMI";
		case PPC_INS_EVMWHUMIA: return "PPC_INS_EVMWHUMIA";
		case PPC_INS_EVMWLSMIAAW: return "PPC_INS_EVMWLSMIAAW";
		case PPC_INS_EVMWLSMIANW: return "PPC_INS_EVMWLSMIANW";
		case PPC_INS_EVMWLSSIAAW: return "PPC_INS_EVMWLSSIAAW";
		case PPC_INS_EVMWLSSIANW: return "PPC_INS_EVMWLSSIANW";
		case PPC_INS_EVMWLUMI: return "PPC_INS_EVMWLUMI";
		case PPC_INS_EVMWLUMIA: return "PPC_INS_EVMWLUMIA";
		case PPC_INS_EVMWLUMIAAW: return "PPC_INS_EVMWLUMIAAW";
		case PPC_INS_EVMWLUMIANW: return "PPC_INS_EVMWLUMIANW";
		case PPC_INS_EVMWLUSIAAW: return "PPC_INS_EVMWLUSIAAW";
		case PPC_INS_EVMWLUSIANW: return "PPC_INS_EVMWLUSIANW";
		case PPC_INS_EVMWSMF: return "PPC_INS_EVMWSMF";
		case PPC_INS_EVMWSMFA: return "PPC_INS_EVMWSMFA";
		case PPC_INS_EVMWSMFAA: return "PPC_INS_EVMWSMFAA";
		case PPC_INS_EVMWSMFAN: return "PPC_INS_EVMWSMFAN";
		case PPC_INS_EVMWSMI: return "PPC_INS_EVMWSMI";
		case PPC_INS_EVMWSMIA: return "PPC_INS_EVMWSMIA";
		case PPC_INS_EVMWSMIAA: return "PPC_INS_EVMWSMIAA";
		case PPC_INS_EVMWSMIAN: return "PPC_INS_EVMWSMIAN";
		case PPC_INS_EVMWSSF: return "PPC_INS_EVMWSSF";
		case PPC_INS_EVMWSSFA: return "PPC_INS_EVMWSSFA";
		case PPC_INS_EVMWSSFAA: return "PPC_INS_EVMWSSFAA";
		case PPC_INS_EVMWSSFAN: return "PPC_INS_EVMWSSFAN";
		case PPC_INS_EVMWUMI: return "PPC_INS_EVMWUMI";
		case PPC_INS_EVMWUMIA: return "PPC_INS_EVMWUMIA";
		case PPC_INS_EVMWUMIAA: return "PPC_INS_EVMWUMIAA";
		case PPC_INS_EVMWUMIAN: return "PPC_INS_EVMWUMIAN";
		case PPC_INS_EVNAND: return "PPC_INS_EVNAND";
		case PPC_INS_EVNEG: return "PPC_INS_EVNEG";
		case PPC_INS_EVNOR: return "PPC_INS_EVNOR";
		case PPC_INS_EVOR: return "PPC_INS_EVOR";
		case PPC_INS_EVORC: return "PPC_INS_EVORC";
		case PPC_INS_EVRLW: return "PPC_INS_EVRLW";
		case PPC_INS_EVRLWI: return "PPC_INS_EVRLWI";
		case PPC_INS_EVRNDW: return "PPC_INS_EVRNDW";
		case PPC_INS_EVSLW: return "PPC_INS_EVSLW";
		case PPC_INS_EVSLWI: return "PPC_INS_EVSLWI";
		case PPC_INS_EVSPLATFI: return "PPC_INS_EVSPLATFI";
		case PPC_INS_EVSPLATI: return "PPC_INS_EVSPLATI";
		case PPC_INS_EVSRWIS: return "PPC_INS_EVSRWIS";
		case PPC_INS_EVSRWIU: return "PPC_INS_EVSRWIU";
		case PPC_INS_EVSRWS: return "PPC_INS_EVSRWS";
		case PPC_INS_EVSRWU: return "PPC_INS_EVSRWU";
		case PPC_INS_EVSTDD: return "PPC_INS_EVSTDD";
		case PPC_INS_EVSTDDX: return "PPC_INS_EVSTDDX";
		case PPC_INS_EVSTDH: return "PPC_INS_EVSTDH";
		case PPC_INS_EVSTDHX: return "PPC_INS_EVSTDHX";
		case PPC_INS_EVSTDW: return "PPC_INS_EVSTDW";
		case PPC_INS_EVSTDWX: return "PPC_INS_EVSTDWX";
		case PPC_INS_EVSTWHE: return "PPC_INS_EVSTWHE";
		case PPC_INS_EVSTWHEX: return "PPC_INS_EVSTWHEX";
		case PPC_INS_EVSTWHO: return "PPC_INS_EVSTWHO";
		case PPC_INS_EVSTWHOX: return "PPC_INS_EVSTWHOX";
		case PPC_INS_EVSTWWE: return "PPC_INS_EVSTWWE";
		case PPC_INS_EVSTWWEX: return "PPC_INS_EVSTWWEX";
		case PPC_INS_EVSTWWO: return "PPC_INS_EVSTWWO";
		case PPC_INS_EVSTWWOX: return "PPC_INS_EVSTWWOX";
		case PPC_INS_EVSUBFSMIAAW: return "PPC_INS_EVSUBFSMIAAW";
		case PPC_INS_EVSUBFSSIAAW: return "PPC_INS_EVSUBFSSIAAW";
		case PPC_INS_EVSUBFUMIAAW: return "PPC_INS_EVSUBFUMIAAW";
		case PPC_INS_EVSUBFUSIAAW: return "PPC_INS_EVSUBFUSIAAW";
		case PPC_INS_EVSUBFW: return "PPC_INS_EVSUBFW";
		case PPC_INS_EVSUBIFW: return "PPC_INS_EVSUBIFW";
		case PPC_INS_EVXOR: return "PPC_INS_EVXOR";
		case PPC_INS_EXTSB: return "PPC_INS_EXTSB";
		case PPC_INS_EXTSH: return "PPC_INS_EXTSH";
		case PPC_INS_EXTSW: return "PPC_INS_EXTSW";
		case PPC_INS_FABS: return "PPC_INS_FABS";
		case PPC_INS_FADD: return "PPC_INS_FADD";
		case PPC_INS_FADDS: return "PPC_INS_FADDS";
		case PPC_INS_FCFID: return "PPC_INS_FCFID";
		case PPC_INS_FCFIDS: return "PPC_INS_FCFIDS";
		case PPC_INS_FCFIDU: return "PPC_INS_FCFIDU";
		case PPC_INS_FCFIDUS: return "PPC_INS_FCFIDUS";
		case PPC_INS_FCMPU: return "PPC_INS_FCMPU";
		case PPC_INS_FCPSGN: return "PPC_INS_FCPSGN";
		case PPC_INS_FCTID: return "PPC_INS_FCTID";
		case PPC_INS_FCTIDUZ: return "PPC_INS_FCTIDUZ";
		case PPC_INS_FCTIDZ: return "PPC_INS_FCTIDZ";
		case PPC_INS_FCTIW: return "PPC_INS_FCTIW";
		case PPC_INS_FCTIWUZ: return "PPC_INS_FCTIWUZ";
		case PPC_INS_FCTIWZ: return "PPC_INS_FCTIWZ";
		case PPC_INS_FDIV: return "PPC_INS_FDIV";
		case PPC_INS_FDIVS: return "PPC_INS_FDIVS";
		case PPC_INS_FMADD: return "PPC_INS_FMADD";
		case PPC_INS_FMADDS: return "PPC_INS_FMADDS";
		case PPC_INS_FMR: return "PPC_INS_FMR";
		case PPC_INS_FMSUB: return "PPC_INS_FMSUB";
		case PPC_INS_FMSUBS: return "PPC_INS_FMSUBS";
		case PPC_INS_FMUL: return "PPC_INS_FMUL";
		case PPC_INS_FMULS: return "PPC_INS_FMULS";
		case PPC_INS_FNABS: return "PPC_INS_FNABS";
		case PPC_INS_FNEG: return "PPC_INS_FNEG";
		case PPC_INS_FNMADD: return "PPC_INS_FNMADD";
		case PPC_INS_FNMADDS: return "PPC_INS_FNMADDS";
		case PPC_INS_FNMSUB: return "PPC_INS_FNMSUB";
		case PPC_INS_FNMSUBS: return "PPC_INS_FNMSUBS";
		case PPC_INS_FRE: return "PPC_INS_FRE";
		case PPC_INS_FRES: return "PPC_INS_FRES";
		case PPC_INS_FRIM: return "PPC_INS_FRIM";
		case PPC_INS_FRIN: return "PPC_INS_FRIN";
		case PPC_INS_FRIP: return "PPC_INS_FRIP";
		case PPC_INS_FRIZ: return "PPC_INS_FRIZ";
		case PPC_INS_FRSP: return "PPC_INS_FRSP";
		case PPC_INS_FRSQRTE: return "PPC_INS_FRSQRTE";
		case PPC_INS_FRSQRTES: return "PPC_INS_FRSQRTES";
		case PPC_INS_FSEL: return "PPC_INS_FSEL";
		case PPC_INS_FSQRT: return "PPC_INS_FSQRT";
		case PPC_INS_FSQRTS: return "PPC_INS_FSQRTS";
		case PPC_INS_FSUB: return "PPC_INS_FSUB";
		case PPC_INS_FSUBS: return "PPC_INS_FSUBS";
		case PPC_INS_ICBI: return "PPC_INS_ICBI";
		case PPC_INS_ICCCI: return "PPC_INS_ICCCI";
		case PPC_INS_ISEL: return "PPC_INS_ISEL";
		case PPC_INS_ISYNC: return "PPC_INS_ISYNC";
		case PPC_INS_LA: return "PPC_INS_LA";
		case PPC_INS_LBZ: return "PPC_INS_LBZ";
		case PPC_INS_LBZU: return "PPC_INS_LBZU";
		case PPC_INS_LBZUX: return "PPC_INS_LBZUX";
		case PPC_INS_LBZX: return "PPC_INS_LBZX";
		case PPC_INS_LD: return "PPC_INS_LD";
		case PPC_INS_LDARX: return "PPC_INS_LDARX";
		case PPC_INS_LDBRX: return "PPC_INS_LDBRX";
		case PPC_INS_LDU: return "PPC_INS_LDU";
		case PPC_INS_LDUX: return "PPC_INS_LDUX";
		case PPC_INS_LDX: return "PPC_INS_LDX";
		case PPC_INS_LFD: return "PPC_INS_LFD";
		case PPC_INS_LFDU: return "PPC_INS_LFDU";
		case PPC_INS_LFDUX: return "PPC_INS_LFDUX";
		case PPC_INS_LFDX: return "PPC_INS_LFDX";
		case PPC_INS_LFIWAX: return "PPC_INS_LFIWAX";
		case PPC_INS_LFIWZX: return "PPC_INS_LFIWZX";
		case PPC_INS_LFS: return "PPC_INS_LFS";
		case PPC_INS_LFSU: return "PPC_INS_LFSU";
		case PPC_INS_LFSUX: return "PPC_INS_LFSUX";
		case PPC_INS_LFSX: return "PPC_INS_LFSX";
		case PPC_INS_LHA: return "PPC_INS_LHA";
		case PPC_INS_LHAU: return "PPC_INS_LHAU";
		case PPC_INS_LHAUX: return "PPC_INS_LHAUX";
		case PPC_INS_LHAX: return "PPC_INS_LHAX";
		case PPC_INS_LHBRX: return "PPC_INS_LHBRX";
		case PPC_INS_LHZ: return "PPC_INS_LHZ";
		case PPC_INS_LHZU: return "PPC_INS_LHZU";
		case PPC_INS_LHZUX: return "PPC_INS_LHZUX";
		case PPC_INS_LHZX: return "PPC_INS_LHZX";
		case PPC_INS_LI: return "PPC_INS_LI";
		case PPC_INS_LIS: return "PPC_INS_LIS";
		case PPC_INS_LMW: return "PPC_INS_LMW";
		case PPC_INS_LSWI: return "PPC_INS_LSWI";
		case PPC_INS_LVEBX: return "PPC_INS_LVEBX";
		case PPC_INS_LVEHX: return "PPC_INS_LVEHX";
		case PPC_INS_LVEWX: return "PPC_INS_LVEWX";
		case PPC_INS_LVSL: return "PPC_INS_LVSL";
		case PPC_INS_LVSR: return "PPC_INS_LVSR";
		case PPC_INS_LVX: return "PPC_INS_LVX";
		case PPC_INS_LVXL: return "PPC_INS_LVXL";
		case PPC_INS_LWA: return "PPC_INS_LWA";
		case PPC_INS_LWARX: return "PPC_INS_LWARX";
		case PPC_INS_LWAUX: return "PPC_INS_LWAUX";
		case PPC_INS_LWAX: return "PPC_INS_LWAX";
		case PPC_INS_LWBRX: return "PPC_INS_LWBRX";
		case PPC_INS_LWZ: return "PPC_INS_LWZ";
		case PPC_INS_LWZU: return "PPC_INS_LWZU";
		case PPC_INS_LWZUX: return "PPC_INS_LWZUX";
		case PPC_INS_LWZX: return "PPC_INS_LWZX";
		case PPC_INS_LXSDX: return "PPC_INS_LXSDX";
		case PPC_INS_LXVD2X: return "PPC_INS_LXVD2X";
		case PPC_INS_LXVDSX: return "PPC_INS_LXVDSX";
		case PPC_INS_LXVW4X: return "PPC_INS_LXVW4X";
		case PPC_INS_MBAR: return "PPC_INS_MBAR";
		case PPC_INS_MCRF: return "PPC_INS_MCRF";
		case PPC_INS_MFCR: return "PPC_INS_MFCR";
		case PPC_INS_MFCTR: return "PPC_INS_MFCTR";
		case PPC_INS_MFDCR: return "PPC_INS_MFDCR";
		case PPC_INS_MFFS: return "PPC_INS_MFFS";
		case PPC_INS_MFLR: return "PPC_INS_MFLR";
		case PPC_INS_MFMSR: return "PPC_INS_MFMSR";
		case PPC_INS_MFOCRF: return "PPC_INS_MFOCRF";
		case PPC_INS_MFSPR: return "PPC_INS_MFSPR";
		case PPC_INS_MFSR: return "PPC_INS_MFSR";
		case PPC_INS_MFSRIN: return "PPC_INS_MFSRIN";
		case PPC_INS_MFTB: return "PPC_INS_MFTB";
		case PPC_INS_MFVSCR: return "PPC_INS_MFVSCR";
		case PPC_INS_MSYNC: return "PPC_INS_MSYNC";
		case PPC_INS_MTCRF: return "PPC_INS_MTCRF";
		case PPC_INS_MTCTR: return "PPC_INS_MTCTR";
		case PPC_INS_MTDCR: return "PPC_INS_MTDCR";
		case PPC_INS_MTFSB0: return "PPC_INS_MTFSB0";
		case PPC_INS_MTFSB1: return "PPC_INS_MTFSB1";
		case PPC_INS_MTFSF: return "PPC_INS_MTFSF";
		case PPC_INS_MTLR: return "PPC_INS_MTLR";
		case PPC_INS_MTMSR: return "PPC_INS_MTMSR";
		case PPC_INS_MTMSRD: return "PPC_INS_MTMSRD";
		case PPC_INS_MTOCRF: return "PPC_INS_MTOCRF";
		case PPC_INS_MTSPR: return "PPC_INS_MTSPR";
		case PPC_INS_MTSR: return "PPC_INS_MTSR";
		case PPC_INS_MTSRIN: return "PPC_INS_MTSRIN";
		case PPC_INS_MTVSCR: return "PPC_INS_MTVSCR";
		case PPC_INS_MULHD: return "PPC_INS_MULHD";
		case PPC_INS_MULHDU: return "PPC_INS_MULHDU";
		case PPC_INS_MULHW: return "PPC_INS_MULHW";
		case PPC_INS_MULHWU: return "PPC_INS_MULHWU";
		case PPC_INS_MULLD: return "PPC_INS_MULLD";
		case PPC_INS_MULLI: return "PPC_INS_MULLI";
		case PPC_INS_MULLW: return "PPC_INS_MULLW";
		case PPC_INS_NAND: return "PPC_INS_NAND";
		case PPC_INS_NEG: return "PPC_INS_NEG";
		case PPC_INS_NOP: return "PPC_INS_NOP";
		case PPC_INS_ORI: return "PPC_INS_ORI";
		case PPC_INS_NOR: return "PPC_INS_NOR";
		case PPC_INS_OR: return "PPC_INS_OR";
		case PPC_INS_ORC: return "PPC_INS_ORC";
		case PPC_INS_ORIS: return "PPC_INS_ORIS";
		case PPC_INS_POPCNTD: return "PPC_INS_POPCNTD";
		case PPC_INS_POPCNTW: return "PPC_INS_POPCNTW";
		case PPC_INS_RFCI: return "PPC_INS_RFCI";
		case PPC_INS_RFDI: return "PPC_INS_RFDI";
		case PPC_INS_RFI: return "PPC_INS_RFI";
		case PPC_INS_RFID: return "PPC_INS_RFID";
		case PPC_INS_RFMCI: return "PPC_INS_RFMCI";
		case PPC_INS_RLDCL: return "PPC_INS_RLDCL";
		case PPC_INS_RLDCR: return "PPC_INS_RLDCR";
		case PPC_INS_RLDIC: return "PPC_INS_RLDIC";
		case PPC_INS_RLDICL: return "PPC_INS_RLDICL";
		case PPC_INS_RLDICR: return "PPC_INS_RLDICR";
		case PPC_INS_RLDIMI: return "PPC_INS_RLDIMI";
		case PPC_INS_RLWIMI: return "PPC_INS_RLWIMI";
		case PPC_INS_RLWINM: return "PPC_INS_RLWINM";
		case PPC_INS_RLWNM: return "PPC_INS_RLWNM";
		case PPC_INS_SC: return "PPC_INS_SC";
		case PPC_INS_SLBIA: return "PPC_INS_SLBIA";
		case PPC_INS_SLBIE: return "PPC_INS_SLBIE";
		case PPC_INS_SLBMFEE: return "PPC_INS_SLBMFEE";
		case PPC_INS_SLBMTE: return "PPC_INS_SLBMTE";
		case PPC_INS_SLD: return "PPC_INS_SLD";
		case PPC_INS_SLW: return "PPC_INS_SLW";
		case PPC_INS_SRAD: return "PPC_INS_SRAD";
		case PPC_INS_SRADI: return "PPC_INS_SRADI";
		case PPC_INS_SRAW: return "PPC_INS_SRAW";
		case PPC_INS_SRAWI: return "PPC_INS_SRAWI";
		case PPC_INS_SRD: return "PPC_INS_SRD";
		case PPC_INS_SRW: return "PPC_INS_SRW";
		case PPC_INS_STB: return "PPC_INS_STB";
		case PPC_INS_STBU: return "PPC_INS_STBU";
		case PPC_INS_STBUX: return "PPC_INS_STBUX";
		case PPC_INS_STBX: return "PPC_INS_STBX";
		case PPC_INS_STD: return "PPC_INS_STD";
		case PPC_INS_STDBRX: return "PPC_INS_STDBRX";
		case PPC_INS_STDCX: return "PPC_INS_STDCX";
		case PPC_INS_STDU: return "PPC_INS_STDU";
		case PPC_INS_STDUX: return "PPC_INS_STDUX";
		case PPC_INS_STDX: return "PPC_INS_STDX";
		case PPC_INS_STFD: return "PPC_INS_STFD";
		case PPC_INS_STFDU: return "PPC_INS_STFDU";
		case PPC_INS_STFDUX: return "PPC_INS_STFDUX";
		case PPC_INS_STFDX: return "PPC_INS_STFDX";
		case PPC_INS_STFIWX: return "PPC_INS_STFIWX";
		case PPC_INS_STFS: return "PPC_INS_STFS";
		case PPC_INS_STFSU: return "PPC_INS_STFSU";
		case PPC_INS_STFSUX: return "PPC_INS_STFSUX";
		case PPC_INS_STFSX: return "PPC_INS_STFSX";
		case PPC_INS_STH: return "PPC_INS_STH";
		case PPC_INS_STHBRX: return "PPC_INS_STHBRX";
		case PPC_INS_STHU: return "PPC_INS_STHU";
		case PPC_INS_STHUX: return "PPC_INS_STHUX";
		case PPC_INS_STHX: return "PPC_INS_STHX";
		case PPC_INS_STMW: return "PPC_INS_STMW";
		case PPC_INS_STSWI: return "PPC_INS_STSWI";
		case PPC_INS_STVEBX: return "PPC_INS_STVEBX";
		case PPC_INS_STVEHX: return "PPC_INS_STVEHX";
		case PPC_INS_STVEWX: return "PPC_INS_STVEWX";
		case PPC_INS_STVX: return "PPC_INS_STVX";
		case PPC_INS_STVXL: return "PPC_INS_STVXL";
		case PPC_INS_STW: return "PPC_INS_STW";
		case PPC_INS_STWBRX: return "PPC_INS_STWBRX";
		case PPC_INS_STWCX: return "PPC_INS_STWCX";
		case PPC_INS_STWU: return "PPC_INS_STWU";
		case PPC_INS_STWUX: return "PPC_INS_STWUX";
		case PPC_INS_STWX: return "PPC_INS_STWX";
		case PPC_INS_STXSDX: return "PPC_INS_STXSDX";
		case PPC_INS_STXVD2X: return "PPC_INS_STXVD2X";
		case PPC_INS_STXVW4X: return "PPC_INS_STXVW4X";
		case PPC_INS_SUBF: return "PPC_INS_SUBF";
		case PPC_INS_SUBFC: return "PPC_INS_SUBFC";
		case PPC_INS_SUBFE: return "PPC_INS_SUBFE";
		case PPC_INS_SUBFIC: return "PPC_INS_SUBFIC";
		case PPC_INS_SUBFME: return "PPC_INS_SUBFME";
		case PPC_INS_SUBFZE: return "PPC_INS_SUBFZE";
		case PPC_INS_SYNC: return "PPC_INS_SYNC";
		case PPC_INS_TD: return "PPC_INS_TD";
		case PPC_INS_TDI: return "PPC_INS_TDI";
		case PPC_INS_TLBIA: return "PPC_INS_TLBIA";
		case PPC_INS_TLBIE: return "PPC_INS_TLBIE";
		case PPC_INS_TLBIEL: return "PPC_INS_TLBIEL";
		case PPC_INS_TLBIVAX: return "PPC_INS_TLBIVAX";
		case PPC_INS_TLBLD: return "PPC_INS_TLBLD";
		case PPC_INS_TLBLI: return "PPC_INS_TLBLI";
		case PPC_INS_TLBRE: return "PPC_INS_TLBRE";
		case PPC_INS_TLBSX: return "PPC_INS_TLBSX";
		case PPC_INS_TLBSYNC: return "PPC_INS_TLBSYNC";
		case PPC_INS_TLBWE: return "PPC_INS_TLBWE";
		case PPC_INS_TRAP: return "PPC_INS_TRAP";
		case PPC_INS_TW: return "PPC_INS_TW";
		case PPC_INS_TWI: return "PPC_INS_TWI";
		case PPC_INS_VADDCUW: return "PPC_INS_VADDCUW";
		case PPC_INS_VADDFP: return "PPC_INS_VADDFP";
		case PPC_INS_VADDSBS: return "PPC_INS_VADDSBS";
		case PPC_INS_VADDSHS: return "PPC_INS_VADDSHS";
		case PPC_INS_VADDSWS: return "PPC_INS_VADDSWS";
		case PPC_INS_VADDUBM: return "PPC_INS_VADDUBM";
		case PPC_INS_VADDUBS: return "PPC_INS_VADDUBS";
		case PPC_INS_VADDUHM: return "PPC_INS_VADDUHM";
		case PPC_INS_VADDUHS: return "PPC_INS_VADDUHS";
		case PPC_INS_VADDUWM: return "PPC_INS_VADDUWM";
		case PPC_INS_VADDUWS: return "PPC_INS_VADDUWS";
		case PPC_INS_VAND: return "PPC_INS_VAND";
		case PPC_INS_VANDC: return "PPC_INS_VANDC";
		case PPC_INS_VAVGSB: return "PPC_INS_VAVGSB";
		case PPC_INS_VAVGSH: return "PPC_INS_VAVGSH";
		case PPC_INS_VAVGSW: return "PPC_INS_VAVGSW";
		case PPC_INS_VAVGUB: return "PPC_INS_VAVGUB";
		case PPC_INS_VAVGUH: return "PPC_INS_VAVGUH";
		case PPC_INS_VAVGUW: return "PPC_INS_VAVGUW";
		case PPC_INS_VCFSX: return "PPC_INS_VCFSX";
		case PPC_INS_VCFUX: return "PPC_INS_VCFUX";
		case PPC_INS_VCMPBFP: return "PPC_INS_VCMPBFP";
		case PPC_INS_VCMPEQFP: return "PPC_INS_VCMPEQFP";
		case PPC_INS_VCMPEQUB: return "PPC_INS_VCMPEQUB";
		case PPC_INS_VCMPEQUH: return "PPC_INS_VCMPEQUH";
		case PPC_INS_VCMPEQUW: return "PPC_INS_VCMPEQUW";
		case PPC_INS_VCMPGEFP: return "PPC_INS_VCMPGEFP";
		case PPC_INS_VCMPGTFP: return "PPC_INS_VCMPGTFP";
		case PPC_INS_VCMPGTSB: return "PPC_INS_VCMPGTSB";
		case PPC_INS_VCMPGTSH: return "PPC_INS_VCMPGTSH";
		case PPC_INS_VCMPGTSW: return "PPC_INS_VCMPGTSW";
		case PPC_INS_VCMPGTUB: return "PPC_INS_VCMPGTUB";
		case PPC_INS_VCMPGTUH: return "PPC_INS_VCMPGTUH";
		case PPC_INS_VCMPGTUW: return "PPC_INS_VCMPGTUW";
		case PPC_INS_VCTSXS: return "PPC_INS_VCTSXS";
		case PPC_INS_VCTUXS: return "PPC_INS_VCTUXS";
		case PPC_INS_VEXPTEFP: return "PPC_INS_VEXPTEFP";
		case PPC_INS_VLOGEFP: return "PPC_INS_VLOGEFP";
		case PPC_INS_VMADDFP: return "PPC_INS_VMADDFP";
		case PPC_INS_VMAXFP: return "PPC_INS_VMAXFP";
		case PPC_INS_VMAXSB: return "PPC_INS_VMAXSB";
		case PPC_INS_VMAXSH: return "PPC_INS_VMAXSH";
		case PPC_INS_VMAXSW: return "PPC_INS_VMAXSW";
		case PPC_INS_VMAXUB: return "PPC_INS_VMAXUB";
		case PPC_INS_VMAXUH: return "PPC_INS_VMAXUH";
		case PPC_INS_VMAXUW: return "PPC_INS_VMAXUW";
		case PPC_INS_VMHADDSHS: return "PPC_INS_VMHADDSHS";
		case PPC_INS_VMHRADDSHS: return "PPC_INS_VMHRADDSHS";
		case PPC_INS_VMINFP: return "PPC_INS_VMINFP";
		case PPC_INS_VMINSB: return "PPC_INS_VMINSB";
		case PPC_INS_VMINSH: return "PPC_INS_VMINSH";
		case PPC_INS_VMINSW: return "PPC_INS_VMINSW";
		case PPC_INS_VMINUB: return "PPC_INS_VMINUB";
		case PPC_INS_VMINUH: return "PPC_INS_VMINUH";
		case PPC_INS_VMINUW: return "PPC_INS_VMINUW";
		case PPC_INS_VMLADDUHM: return "PPC_INS_VMLADDUHM";
		case PPC_INS_VMRGHB: return "PPC_INS_VMRGHB";
		case PPC_INS_VMRGHH: return "PPC_INS_VMRGHH";
		case PPC_INS_VMRGHW: return "PPC_INS_VMRGHW";
		case PPC_INS_VMRGLB: return "PPC_INS_VMRGLB";
		case PPC_INS_VMRGLH: return "PPC_INS_VMRGLH";
		case PPC_INS_VMRGLW: return "PPC_INS_VMRGLW";
		case PPC_INS_VMSUMMBM: return "PPC_INS_VMSUMMBM";
		case PPC_INS_VMSUMSHM: return "PPC_INS_VMSUMSHM";
		case PPC_INS_VMSUMSHS: return "PPC_INS_VMSUMSHS";
		case PPC_INS_VMSUMUBM: return "PPC_INS_VMSUMUBM";
		case PPC_INS_VMSUMUHM: return "PPC_INS_VMSUMUHM";
		case PPC_INS_VMSUMUHS: return "PPC_INS_VMSUMUHS";
		case PPC_INS_VMULESB: return "PPC_INS_VMULESB";
		case PPC_INS_VMULESH: return "PPC_INS_VMULESH";
		case PPC_INS_VMULEUB: return "PPC_INS_VMULEUB";
		case PPC_INS_VMULEUH: return "PPC_INS_VMULEUH";
		case PPC_INS_VMULOSB: return "PPC_INS_VMULOSB";
		case PPC_INS_VMULOSH: return "PPC_INS_VMULOSH";
		case PPC_INS_VMULOUB: return "PPC_INS_VMULOUB";
		case PPC_INS_VMULOUH: return "PPC_INS_VMULOUH";
		case PPC_INS_VNMSUBFP: return "PPC_INS_VNMSUBFP";
		case PPC_INS_VNOR: return "PPC_INS_VNOR";
		case PPC_INS_VOR: return "PPC_INS_VOR";
		case PPC_INS_VPERM: return "PPC_INS_VPERM";
		case PPC_INS_VPKPX: return "PPC_INS_VPKPX";
		case PPC_INS_VPKSHSS: return "PPC_INS_VPKSHSS";
		case PPC_INS_VPKSHUS: return "PPC_INS_VPKSHUS";
		case PPC_INS_VPKSWSS: return "PPC_INS_VPKSWSS";
		case PPC_INS_VPKSWUS: return "PPC_INS_VPKSWUS";
		case PPC_INS_VPKUHUM: return "PPC_INS_VPKUHUM";
		case PPC_INS_VPKUHUS: return "PPC_INS_VPKUHUS";
		case PPC_INS_VPKUWUM: return "PPC_INS_VPKUWUM";
		case PPC_INS_VPKUWUS: return "PPC_INS_VPKUWUS";
		case PPC_INS_VREFP: return "PPC_INS_VREFP";
		case PPC_INS_VRFIM: return "PPC_INS_VRFIM";
		case PPC_INS_VRFIN: return "PPC_INS_VRFIN";
		case PPC_INS_VRFIP: return "PPC_INS_VRFIP";
		case PPC_INS_VRFIZ: return "PPC_INS_VRFIZ";
		case PPC_INS_VRLB: return "PPC_INS_VRLB";
		case PPC_INS_VRLH: return "PPC_INS_VRLH";
		case PPC_INS_VRLW: return "PPC_INS_VRLW";
		case PPC_INS_VRSQRTEFP: return "PPC_INS_VRSQRTEFP";
		case PPC_INS_VSEL: return "PPC_INS_VSEL";
		case PPC_INS_VSL: return "PPC_INS_VSL";
		case PPC_INS_VSLB: return "PPC_INS_VSLB";
		case PPC_INS_VSLDOI: return "PPC_INS_VSLDOI";
		case PPC_INS_VSLH: return "PPC_INS_VSLH";
		case PPC_INS_VSLO: return "PPC_INS_VSLO";
		case PPC_INS_VSLW: return "PPC_INS_VSLW";
		case PPC_INS_VSPLTB: return "PPC_INS_VSPLTB";
		case PPC_INS_VSPLTH: return "PPC_INS_VSPLTH";
		case PPC_INS_VSPLTISB: return "PPC_INS_VSPLTISB";
		case PPC_INS_VSPLTISH: return "PPC_INS_VSPLTISH";
		case PPC_INS_VSPLTISW: return "PPC_INS_VSPLTISW";
		case PPC_INS_VSPLTW: return "PPC_INS_VSPLTW";
		case PPC_INS_VSR: return "PPC_INS_VSR";
		case PPC_INS_VSRAB: return "PPC_INS_VSRAB";
		case PPC_INS_VSRAH: return "PPC_INS_VSRAH";
		case PPC_INS_VSRAW: return "PPC_INS_VSRAW";
		case PPC_INS_VSRB: return "PPC_INS_VSRB";
		case PPC_INS_VSRH: return "PPC_INS_VSRH";
		case PPC_INS_VSRO: return "PPC_INS_VSRO";
		case PPC_INS_VSRW: return "PPC_INS_VSRW";
		case PPC_INS_VSUBCUW: return "PPC_INS_VSUBCUW";
		case PPC_INS_VSUBFP: return "PPC_INS_VSUBFP";
		case PPC_INS_VSUBSBS: return "PPC_INS_VSUBSBS";
		case PPC_INS_VSUBSHS: return "PPC_INS_VSUBSHS";
		case PPC_INS_VSUBSWS: return "PPC_INS_VSUBSWS";
		case PPC_INS_VSUBUBM: return "PPC_INS_VSUBUBM";
		case PPC_INS_VSUBUBS: return "PPC_INS_VSUBUBS";
		case PPC_INS_VSUBUHM: return "PPC_INS_VSUBUHM";
		case PPC_INS_VSUBUHS: return "PPC_INS_VSUBUHS";
		case PPC_INS_VSUBUWM: return "PPC_INS_VSUBUWM";
		case PPC_INS_VSUBUWS: return "PPC_INS_VSUBUWS";
		case PPC_INS_VSUM2SWS: return "PPC_INS_VSUM2SWS";
		case PPC_INS_VSUM4SBS: return "PPC_INS_VSUM4SBS";
		case PPC_INS_VSUM4SHS: return "PPC_INS_VSUM4SHS";
		case PPC_INS_VSUM4UBS: return "PPC_INS_VSUM4UBS";
		case PPC_INS_VSUMSWS: return "PPC_INS_VSUMSWS";
		case PPC_INS_VUPKHPX: return "PPC_INS_VUPKHPX";
		case PPC_INS_VUPKHSB: return "PPC_INS_VUPKHSB";
		case PPC_INS_VUPKHSH: return "PPC_INS_VUPKHSH";
		case PPC_INS_VUPKLPX: return "PPC_INS_VUPKLPX";
		case PPC_INS_VUPKLSB: return "PPC_INS_VUPKLSB";
		case PPC_INS_VUPKLSH: return "PPC_INS_VUPKLSH";
		case PPC_INS_VXOR: return "PPC_INS_VXOR";
		case PPC_INS_WAIT: return "PPC_INS_WAIT";
		case PPC_INS_WRTEE: return "PPC_INS_WRTEE";
		case PPC_INS_WRTEEI: return "PPC_INS_WRTEEI";
		case PPC_INS_XOR: return "PPC_INS_XOR";
		case PPC_INS_XORI: return "PPC_INS_XORI";
		case PPC_INS_XORIS: return "PPC_INS_XORIS";
		case PPC_INS_XSABSDP: return "PPC_INS_XSABSDP";
		case PPC_INS_XSADDDP: return "PPC_INS_XSADDDP";
		case PPC_INS_XSCMPODP: return "PPC_INS_XSCMPODP";
		case PPC_INS_XSCMPUDP: return "PPC_INS_XSCMPUDP";
		case PPC_INS_XSCPSGNDP: return "PPC_INS_XSCPSGNDP";
		case PPC_INS_XSCVDPSP: return "PPC_INS_XSCVDPSP";
		case PPC_INS_XSCVDPSXDS: return "PPC_INS_XSCVDPSXDS";
		case PPC_INS_XSCVDPSXWS: return "PPC_INS_XSCVDPSXWS";
		case PPC_INS_XSCVDPUXDS: return "PPC_INS_XSCVDPUXDS";
		case PPC_INS_XSCVDPUXWS: return "PPC_INS_XSCVDPUXWS";
		case PPC_INS_XSCVSPDP: return "PPC_INS_XSCVSPDP";
		case PPC_INS_XSCVSXDDP: return "PPC_INS_XSCVSXDDP";
		case PPC_INS_XSCVUXDDP: return "PPC_INS_XSCVUXDDP";
		case PPC_INS_XSDIVDP: return "PPC_INS_XSDIVDP";
		case PPC_INS_XSMADDADP: return "PPC_INS_XSMADDADP";
		case PPC_INS_XSMADDMDP: return "PPC_INS_XSMADDMDP";
		case PPC_INS_XSMAXDP: return "PPC_INS_XSMAXDP";
		case PPC_INS_XSMINDP: return "PPC_INS_XSMINDP";
		case PPC_INS_XSMSUBADP: return "PPC_INS_XSMSUBADP";
		case PPC_INS_XSMSUBMDP: return "PPC_INS_XSMSUBMDP";
		case PPC_INS_XSMULDP: return "PPC_INS_XSMULDP";
		case PPC_INS_XSNABSDP: return "PPC_INS_XSNABSDP";
		case PPC_INS_XSNEGDP: return "PPC_INS_XSNEGDP";
		case PPC_INS_XSNMADDADP: return "PPC_INS_XSNMADDADP";
		case PPC_INS_XSNMADDMDP: return "PPC_INS_XSNMADDMDP";
		case PPC_INS_XSNMSUBADP: return "PPC_INS_XSNMSUBADP";
		case PPC_INS_XSNMSUBMDP: return "PPC_INS_XSNMSUBMDP";
		case PPC_INS_XSRDPI: return "PPC_INS_XSRDPI";
		case PPC_INS_XSRDPIC: return "PPC_INS_XSRDPIC";
		case PPC_INS_XSRDPIM: return "PPC_INS_XSRDPIM";
		case PPC_INS_XSRDPIP: return "PPC_INS_XSRDPIP";
		case PPC_INS_XSRDPIZ: return "PPC_INS_XSRDPIZ";
		case PPC_INS_XSREDP: return "PPC_INS_XSREDP";
		case PPC_INS_XSRSQRTEDP: return "PPC_INS_XSRSQRTEDP";
		case PPC_INS_XSSQRTDP: return "PPC_INS_XSSQRTDP";
		case PPC_INS_XSSUBDP: return "PPC_INS_XSSUBDP";
		case PPC_INS_XSTDIVDP: return "PPC_INS_XSTDIVDP";
		case PPC_INS_XSTSQRTDP: return "PPC_INS_XSTSQRTDP";
		case PPC_INS_XVABSDP: return "PPC_INS_XVABSDP";
		case PPC_INS_XVABSSP: return "PPC_INS_XVABSSP";
		case PPC_INS_XVADDDP: return "PPC_INS_XVADDDP";
		case PPC_INS_XVADDSP: return "PPC_INS_XVADDSP";
		case PPC_INS_XVCMPEQDP: return "PPC_INS_XVCMPEQDP";
		case PPC_INS_XVCMPEQSP: return "PPC_INS_XVCMPEQSP";
		case PPC_INS_XVCMPGEDP: return "PPC_INS_XVCMPGEDP";
		case PPC_INS_XVCMPGESP: return "PPC_INS_XVCMPGESP";
		case PPC_INS_XVCMPGTDP: return "PPC_INS_XVCMPGTDP";
		case PPC_INS_XVCMPGTSP: return "PPC_INS_XVCMPGTSP";
		case PPC_INS_XVCPSGNDP: return "PPC_INS_XVCPSGNDP";
		case PPC_INS_XVCPSGNSP: return "PPC_INS_XVCPSGNSP";
		case PPC_INS_XVCVDPSP: return "PPC_INS_XVCVDPSP";
		case PPC_INS_XVCVDPSXDS: return "PPC_INS_XVCVDPSXDS";
		case PPC_INS_XVCVDPSXWS: return "PPC_INS_XVCVDPSXWS";
		case PPC_INS_XVCVDPUXDS: return "PPC_INS_XVCVDPUXDS";
		case PPC_INS_XVCVDPUXWS: return "PPC_INS_XVCVDPUXWS";
		case PPC_INS_XVCVSPDP: return "PPC_INS_XVCVSPDP";
		case PPC_INS_XVCVSPSXDS: return "PPC_INS_XVCVSPSXDS";
		case PPC_INS_XVCVSPSXWS: return "PPC_INS_XVCVSPSXWS";
		case PPC_INS_XVCVSPUXDS: return "PPC_INS_XVCVSPUXDS";
		case PPC_INS_XVCVSPUXWS: return "PPC_INS_XVCVSPUXWS";
		case PPC_INS_XVCVSXDDP: return "PPC_INS_XVCVSXDDP";
		case PPC_INS_XVCVSXDSP: return "PPC_INS_XVCVSXDSP";
		case PPC_INS_XVCVSXWDP: return "PPC_INS_XVCVSXWDP";
		case PPC_INS_XVCVSXWSP: return "PPC_INS_XVCVSXWSP";
		case PPC_INS_XVCVUXDDP: return "PPC_INS_XVCVUXDDP";
		case PPC_INS_XVCVUXDSP: return "PPC_INS_XVCVUXDSP";
		case PPC_INS_XVCVUXWDP: return "PPC_INS_XVCVUXWDP";
		case PPC_INS_XVCVUXWSP: return "PPC_INS_XVCVUXWSP";
		case PPC_INS_XVDIVDP: return "PPC_INS_XVDIVDP";
		case PPC_INS_XVDIVSP: return "PPC_INS_XVDIVSP";
		case PPC_INS_XVMADDADP: return "PPC_INS_XVMADDADP";
		case PPC_INS_XVMADDASP: return "PPC_INS_XVMADDASP";
		case PPC_INS_XVMADDMDP: return "PPC_INS_XVMADDMDP";
		case PPC_INS_XVMADDMSP: return "PPC_INS_XVMADDMSP";
		case PPC_INS_XVMAXDP: return "PPC_INS_XVMAXDP";
		case PPC_INS_XVMAXSP: return "PPC_INS_XVMAXSP";
		case PPC_INS_XVMINDP: return "PPC_INS_XVMINDP";
		case PPC_INS_XVMINSP: return "PPC_INS_XVMINSP";
		case PPC_INS_XVMSUBADP: return "PPC_INS_XVMSUBADP";
		case PPC_INS_XVMSUBASP: return "PPC_INS_XVMSUBASP";
		case PPC_INS_XVMSUBMDP: return "PPC_INS_XVMSUBMDP";
		case PPC_INS_XVMSUBMSP: return "PPC_INS_XVMSUBMSP";
		case PPC_INS_XVMULDP: return "PPC_INS_XVMULDP";
		case PPC_INS_XVMULSP: return "PPC_INS_XVMULSP";
		case PPC_INS_XVNABSDP: return "PPC_INS_XVNABSDP";
		case PPC_INS_XVNABSSP: return "PPC_INS_XVNABSSP";
		case PPC_INS_XVNEGDP: return "PPC_INS_XVNEGDP";
		case PPC_INS_XVNEGSP: return "PPC_INS_XVNEGSP";
		case PPC_INS_XVNMADDADP: return "PPC_INS_XVNMADDADP";
		case PPC_INS_XVNMADDASP: return "PPC_INS_XVNMADDASP";
		case PPC_INS_XVNMADDMDP: return "PPC_INS_XVNMADDMDP";
		case PPC_INS_XVNMADDMSP: return "PPC_INS_XVNMADDMSP";
		case PPC_INS_XVNMSUBADP: return "PPC_INS_XVNMSUBADP";
		case PPC_INS_XVNMSUBASP: return "PPC_INS_XVNMSUBASP";
		case PPC_INS_XVNMSUBMDP: return "PPC_INS_XVNMSUBMDP";
		case PPC_INS_XVNMSUBMSP: return "PPC_INS_XVNMSUBMSP";
		case PPC_INS_XVRDPI: return "PPC_INS_XVRDPI";
		case PPC_INS_XVRDPIC: return "PPC_INS_XVRDPIC";
		case PPC_INS_XVRDPIM: return "PPC_INS_XVRDPIM";
		case PPC_INS_XVRDPIP: return "PPC_INS_XVRDPIP";
		case PPC_INS_XVRDPIZ: return "PPC_INS_XVRDPIZ";
		case PPC_INS_XVREDP: return "PPC_INS_XVREDP";
		case PPC_INS_XVRESP: return "PPC_INS_XVRESP";
		case PPC_INS_XVRSPI: return "PPC_INS_XVRSPI";
		case PPC_INS_XVRSPIC: return "PPC_INS_XVRSPIC";
		case PPC_INS_XVRSPIM: return "PPC_INS_XVRSPIM";
		case PPC_INS_XVRSPIP: return "PPC_INS_XVRSPIP";
		case PPC_INS_XVRSPIZ: return "PPC_INS_XVRSPIZ";
		case PPC_INS_XVRSQRTEDP: return "PPC_INS_XVRSQRTEDP";
		case PPC_INS_XVRSQRTESP: return "PPC_INS_XVRSQRTESP";
		case PPC_INS_XVSQRTDP: return "PPC_INS_XVSQRTDP";
		case PPC_INS_XVSQRTSP: return "PPC_INS_XVSQRTSP";
		case PPC_INS_XVSUBDP: return "PPC_INS_XVSUBDP";
		case PPC_INS_XVSUBSP: return "PPC_INS_XVSUBSP";
		case PPC_INS_XVTDIVDP: return "PPC_INS_XVTDIVDP";
		case PPC_INS_XVTDIVSP: return "PPC_INS_XVTDIVSP";
		case PPC_INS_XVTSQRTDP: return "PPC_INS_XVTSQRTDP";
		case PPC_INS_XVTSQRTSP: return "PPC_INS_XVTSQRTSP";
		case PPC_INS_XXLAND: return "PPC_INS_XXLAND";
		case PPC_INS_XXLANDC: return "PPC_INS_XXLANDC";
		case PPC_INS_XXLNOR: return "PPC_INS_XXLNOR";
		case PPC_INS_XXLOR: return "PPC_INS_XXLOR";
		case PPC_INS_XXLXOR: return "PPC_INS_XXLXOR";
		case PPC_INS_XXMRGHW: return "PPC_INS_XXMRGHW";
		case PPC_INS_XXMRGLW: return "PPC_INS_XXMRGLW";
		case PPC_INS_XXPERMDI: return "PPC_INS_XXPERMDI";
		case PPC_INS_XXSEL: return "PPC_INS_XXSEL";
		case PPC_INS_XXSLDWI: return "PPC_INS_XXSLDWI";
		case PPC_INS_XXSPLTW: return "PPC_INS_XXSPLTW";
		case PPC_INS_BCA: return "PPC_INS_BCA";
		case PPC_INS_BCLA: return "PPC_INS_BCLA";
		case PPC_INS_SLWI: return "PPC_INS_SLWI";
		case PPC_INS_SRWI: return "PPC_INS_SRWI";
		case PPC_INS_SLDI: return "PPC_INS_SLDI";
		case PPC_INS_BTA: return "PPC_INS_BTA";
		case PPC_INS_CRSET: return "PPC_INS_CRSET";
		case PPC_INS_CRNOT: return "PPC_INS_CRNOT";
		case PPC_INS_CRMOVE: return "PPC_INS_CRMOVE";
		case PPC_INS_CRCLR: return "PPC_INS_CRCLR";
		case PPC_INS_MFBR0: return "PPC_INS_MFBR0";
		case PPC_INS_MFBR1: return "PPC_INS_MFBR1";
		case PPC_INS_MFBR2: return "PPC_INS_MFBR2";
		case PPC_INS_MFBR3: return "PPC_INS_MFBR3";
		case PPC_INS_MFBR4: return "PPC_INS_MFBR4";
		case PPC_INS_MFBR5: return "PPC_INS_MFBR5";
		case PPC_INS_MFBR6: return "PPC_INS_MFBR6";
		case PPC_INS_MFBR7: return "PPC_INS_MFBR7";
		case PPC_INS_MFXER: return "PPC_INS_MFXER";
		case PPC_INS_MFRTCU: return "PPC_INS_MFRTCU";
		case PPC_INS_MFRTCL: return "PPC_INS_MFRTCL";
		case PPC_INS_MFDSCR: return "PPC_INS_MFDSCR";
		case PPC_INS_MFDSISR: return "PPC_INS_MFDSISR";
		case PPC_INS_MFDAR: return "PPC_INS_MFDAR";
		case PPC_INS_MFSRR2: return "PPC_INS_MFSRR2";
		case PPC_INS_MFSRR3: return "PPC_INS_MFSRR3";
		case PPC_INS_MFCFAR: return "PPC_INS_MFCFAR";
		case PPC_INS_MFAMR: return "PPC_INS_MFAMR";
		case PPC_INS_MFPID: return "PPC_INS_MFPID";
		case PPC_INS_MFTBLO: return "PPC_INS_MFTBLO";
		case PPC_INS_MFTBHI: return "PPC_INS_MFTBHI";
		case PPC_INS_MFDBATU: return "PPC_INS_MFDBATU";
		case PPC_INS_MFDBATL: return "PPC_INS_MFDBATL";
		case PPC_INS_MFIBATU: return "PPC_INS_MFIBATU";
		case PPC_INS_MFIBATL: return "PPC_INS_MFIBATL";
		case PPC_INS_MFDCCR: return "PPC_INS_MFDCCR";
		case PPC_INS_MFICCR: return "PPC_INS_MFICCR";
		case PPC_INS_MFDEAR: return "PPC_INS_MFDEAR";
		case PPC_INS_MFESR: return "PPC_INS_MFESR";
		case PPC_INS_MFSPEFSCR: return "PPC_INS_MFSPEFSCR";
		case PPC_INS_MFTCR: return "PPC_INS_MFTCR";
		case PPC_INS_MFASR: return "PPC_INS_MFASR";
		case PPC_INS_MFPVR: return "PPC_INS_MFPVR";
		case PPC_INS_MFTBU: return "PPC_INS_MFTBU";
		case PPC_INS_MTCR: return "PPC_INS_MTCR";
		case PPC_INS_MTBR0: return "PPC_INS_MTBR0";
		case PPC_INS_MTBR1: return "PPC_INS_MTBR1";
		case PPC_INS_MTBR2: return "PPC_INS_MTBR2";
		case PPC_INS_MTBR3: return "PPC_INS_MTBR3";
		case PPC_INS_MTBR4: return "PPC_INS_MTBR4";
		case PPC_INS_MTBR5: return "PPC_INS_MTBR5";
		case PPC_INS_MTBR6: return "PPC_INS_MTBR6";
		case PPC_INS_MTBR7: return "PPC_INS_MTBR7";
		case PPC_INS_MTXER: return "PPC_INS_MTXER";
		case PPC_INS_MTDSCR: return "PPC_INS_MTDSCR";
		case PPC_INS_MTDSISR: return "PPC_INS_MTDSISR";
		case PPC_INS_MTDAR: return "PPC_INS_MTDAR";
		case PPC_INS_MTSRR2: return "PPC_INS_MTSRR2";
		case PPC_INS_MTSRR3: return "PPC_INS_MTSRR3";
		case PPC_INS_MTCFAR: return "PPC_INS_MTCFAR";
		case PPC_INS_MTAMR: return "PPC_INS_MTAMR";
		case PPC_INS_MTPID: return "PPC_INS_MTPID";
		case PPC_INS_MTTBL: return "PPC_INS_MTTBL";
		case PPC_INS_MTTBU: return "PPC_INS_MTTBU";
		case PPC_INS_MTTBLO: return "PPC_INS_MTTBLO";
		case PPC_INS_MTTBHI: return "PPC_INS_MTTBHI";
		case PPC_INS_MTDBATU: return "PPC_INS_MTDBATU";
		case PPC_INS_MTDBATL: return "PPC_INS_MTDBATL";
		case PPC_INS_MTIBATU: return "PPC_INS_MTIBATU";
		case PPC_INS_MTIBATL: return "PPC_INS_MTIBATL";
		case PPC_INS_MTDCCR: return "PPC_INS_MTDCCR";
		case PPC_INS_MTICCR: return "PPC_INS_MTICCR";
		case PPC_INS_MTDEAR: return "PPC_INS_MTDEAR";
		case PPC_INS_MTESR: return "PPC_INS_MTESR";
		case PPC_INS_MTSPEFSCR: return "PPC_INS_MTSPEFSCR";
		case PPC_INS_MTTCR: return "PPC_INS_MTTCR";
		case PPC_INS_NOT: return "PPC_INS_NOT";
		case PPC_INS_MR: return "PPC_INS_MR";
		case PPC_INS_ROTLD: return "PPC_INS_ROTLD";
		case PPC_INS_ROTLDI: return "PPC_INS_ROTLDI";
		case PPC_INS_CLRLDI: return "PPC_INS_CLRLDI";
		case PPC_INS_ROTLWI: return "PPC_INS_ROTLWI";
		case PPC_INS_CLRLWI: return "PPC_INS_CLRLWI";
		case PPC_INS_ROTLW: return "PPC_INS_ROTLW";
		case PPC_INS_SUB: return "PPC_INS_SUB";
		case PPC_INS_SUBC: return "PPC_INS_SUBC";
		case PPC_INS_LWSYNC: return "PPC_INS_LWSYNC";
		case PPC_INS_PTESYNC: return "PPC_INS_PTESYNC";
		case PPC_INS_TDLT: return "PPC_INS_TDLT";
		case PPC_INS_TDEQ: return "PPC_INS_TDEQ";
		case PPC_INS_TDGT: return "PPC_INS_TDGT";
		case PPC_INS_TDNE: return "PPC_INS_TDNE";
		case PPC_INS_TDLLT: return "PPC_INS_TDLLT";
		case PPC_INS_TDLGT: return "PPC_INS_TDLGT";
		case PPC_INS_TDU: return "PPC_INS_TDU";
		case PPC_INS_TDLTI: return "PPC_INS_TDLTI";
		case PPC_INS_TDEQI: return "PPC_INS_TDEQI";
		case PPC_INS_TDGTI: return "PPC_INS_TDGTI";
		case PPC_INS_TDNEI: return "PPC_INS_TDNEI";
		case PPC_INS_TDLLTI: return "PPC_INS_TDLLTI";
		case PPC_INS_TDLGTI: return "PPC_INS_TDLGTI";
		case PPC_INS_TDUI: return "PPC_INS_TDUI";
		case PPC_INS_TLBREHI: return "PPC_INS_TLBREHI";
		case PPC_INS_TLBRELO: return "PPC_INS_TLBRELO";
		case PPC_INS_TLBWEHI: return "PPC_INS_TLBWEHI";
		case PPC_INS_TLBWELO: return "PPC_INS_TLBWELO";
		case PPC_INS_TWLT: return "PPC_INS_TWLT";
		case PPC_INS_TWEQ: return "PPC_INS_TWEQ";
		case PPC_INS_TWGT: return "PPC_INS_TWGT";
		case PPC_INS_TWNE: return "PPC_INS_TWNE";
		case PPC_INS_TWLLT: return "PPC_INS_TWLLT";
		case PPC_INS_TWLGT: return "PPC_INS_TWLGT";
		case PPC_INS_TWU: return "PPC_INS_TWU";
		case PPC_INS_TWLTI: return "PPC_INS_TWLTI";
		case PPC_INS_TWEQI: return "PPC_INS_TWEQI";
		case PPC_INS_TWGTI: return "PPC_INS_TWGTI";
		case PPC_INS_TWNEI: return "PPC_INS_TWNEI";
		case PPC_INS_TWLLTI: return "PPC_INS_TWLLTI";
		case PPC_INS_TWLGTI: return "PPC_INS_TWLGTI";
		case PPC_INS_TWUI: return "PPC_INS_TWUI";
		case PPC_INS_WAITRSV: return "PPC_INS_WAITRSV";
		case PPC_INS_WAITIMPL: return "PPC_INS_WAITIMPL";
		case PPC_INS_XNOP: return "PPC_INS_XNOP";
		case PPC_INS_XVMOVDP: return "PPC_INS_XVMOVDP";
		case PPC_INS_XVMOVSP: return "PPC_INS_XVMOVSP";
		case PPC_INS_XXSPLTD: return "PPC_INS_XXSPLTD";
		case PPC_INS_XXMRGHD: return "PPC_INS_XXMRGHD";
		case PPC_INS_XXMRGLD: return "PPC_INS_XXMRGLD";
		case PPC_INS_XXSWAPD: return "PPC_INS_XXSWAPD";
		case PPC_INS_BT: return "PPC_INS_BT";
		case PPC_INS_BF: return "PPC_INS_BF";
		case PPC_INS_BDNZT: return "PPC_INS_BDNZT";
		case PPC_INS_BDNZF: return "PPC_INS_BDNZF";
		case PPC_INS_BDZF: return "PPC_INS_BDZF";
		case PPC_INS_BDZT: return "PPC_INS_BDZT";
		case PPC_INS_BFA: return "PPC_INS_BFA";
		case PPC_INS_BDNZTA: return "PPC_INS_BDNZTA";
		case PPC_INS_BDNZFA: return "PPC_INS_BDNZFA";
		case PPC_INS_BDZTA: return "PPC_INS_BDZTA";
		case PPC_INS_BDZFA: return "PPC_INS_BDZFA";
		case PPC_INS_BTCTR: return "PPC_INS_BTCTR";
		case PPC_INS_BFCTR: return "PPC_INS_BFCTR";
		case PPC_INS_BTCTRL: return "PPC_INS_BTCTRL";
		case PPC_INS_BFCTRL: return "PPC_INS_BFCTRL";
		case PPC_INS_BTL: return "PPC_INS_BTL";
		case PPC_INS_BFL: return "PPC_INS_BFL";
		case PPC_INS_BDNZTL: return "PPC_INS_BDNZTL";
		case PPC_INS_BDNZFL: return "PPC_INS_BDNZFL";
		case PPC_INS_BDZTL: return "PPC_INS_BDZTL";
		case PPC_INS_BDZFL: return "PPC_INS_BDZFL";
		case PPC_INS_BTLA: return "PPC_INS_BTLA";
		case PPC_INS_BFLA: return "PPC_INS_BFLA";
		case PPC_INS_BDNZTLA: return "PPC_INS_BDNZTLA";
		case PPC_INS_BDNZFLA: return "PPC_INS_BDNZFLA";
		case PPC_INS_BDZTLA: return "PPC_INS_BDZTLA";
		case PPC_INS_BDZFLA: return "PPC_INS_BDZFLA";
		case PPC_INS_BTLR: return "PPC_INS_BTLR";
		case PPC_INS_BFLR: return "PPC_INS_BFLR";
		case PPC_INS_BDNZTLR: return "PPC_INS_BDNZTLR";
		case PPC_INS_BDZTLR: return "PPC_INS_BDZTLR";
		case PPC_INS_BDZFLR: return "PPC_INS_BDZFLR";
		case PPC_INS_BTLRL: return "PPC_INS_BTLRL";
		case PPC_INS_BFLRL: return "PPC_INS_BFLRL";
		case PPC_INS_BDNZTLRL: return "PPC_INS_BDNZTLRL";
		case PPC_INS_BDNZFLRL: return "PPC_INS_BDNZFLRL";
		case PPC_INS_BDZTLRL: return "PPC_INS_BDZTLRL";
		case PPC_INS_BDZFLRL: return "PPC_INS_BDZFLRL";
		default:
			return "WTF?";
	}
}

