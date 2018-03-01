# CAPSTONE - command line util for accessing capstone disassembler library

Versus cstool:
- reads bytes OR BITS from command line
- prints instruction identifier (CS_INS_WHATEVER)
- print regs read/written, instruction groups
- architecture specific parts (like branch code, branch hint for ppc)

Example output:
```
$ ./capstone ppc 41 82 00 14
 arch: 00000004 (CS_ARCH_PPC)
 mode: 80000000 ()
bytes: 41 82 00 14

====instruction 1/1====
41 82 00 14	beq	0x14
         groups:
     reads regs: ctr rm
    writes regs: ctr
      opcode ID: 13 (PPC_INS_B)
    branch code: 76 (PPC_BC_EQ)
    branch hint: 0 (PPC_BH_INVALID)
     update_cr0: 0
       operand0: imm: 0x14
```

and

```
$ ./capstone ppc verbose bin 001110 00011 00000 0100000000000000
 arch: 00000004 (CS_ARCH_PPC)
 mode: 80000000 ()
bytes: 38 60 40 00

====instruction 1/1====
li	r3, 0x4000
         groups:
     reads regs:
    writes regs:
      opcode ID: 331 (PPC_INS_LI)
    branch code: 0 (PPC_BC_INVALID)
    branch hint: 0 (PPC_BH_INVALID)
     update_cr0: 0
       operand0: reg: r3
       operand1: imm: 0x4000
```
