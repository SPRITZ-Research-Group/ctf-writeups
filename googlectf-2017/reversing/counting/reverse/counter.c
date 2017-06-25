#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define N_REGS 26

struct instr {
	int opcode;
	int opnd;
	int n1;
	int n2;
};

int g_code_num;
struct instr *g_code;

void read_code()
{
	FILE *fd = fopen("code", "rb");
	if (!fd) {
		puts("Could not find file");
		exit(1);
	}

	if (fread(&g_code_num, sizeof(g_code_num), 1, fd) != 1) {
		puts("Error reading file");
		exit(1);
	}

	if (g_code_num > 1000) {
		puts("Invalid number");
		exit(1);
	}

	g_code = malloc(sizeof(struct instr) * g_code_num);
	if (g_code_num > 0) {
		int i = 0;
		while (fread(&g_code[i], sizeof(g_code[i]), 1, fd) == 1 && i < g_code_num) {
			struct instr *instr = &g_code[i];
			unsigned char opnd = instr->opnd;

			if (instr->opcode < 0 || instr->opcode > 2) {
				puts("Invalid ins");
				exit(1);
			}

			if (instr->opcode != 2 && opnd >= N_REGS) {
				puts("Invalid reg");
				exit(1);
			}

			if (instr->opcode == 2 && instr->opnd > N_REGS) {
				puts("Invalid amo");
				exit(1);
			}

			if (instr->n1 > g_code_num || (instr->opcode != 0 && instr->n2 > g_code_num)) {
				puts("Invalid next");
				exit(1);
			}

			i++;
		}
	}

	fclose(fd);
}

void execute_code(uint64_t *regs, int i)
{
	while (i != g_code_num) {
		struct instr *instr = &g_code[i];
		unsigned char opnd = instr->opnd;

		switch (instr->opcode) {
			case 0:
				regs[opnd]++;
				i = instr->n1;
				break;
			case 1:
				if (regs[opnd]) {
					regs[opnd]--;
					i = instr->n1;
				} else {
					i = instr->n2;
				}
				break;
			case 2: {
				uint64_t *new_regs = malloc(sizeof(uint64_t) * N_REGS);
				for (int j = 0; j < N_REGS; j++)
					new_regs[j] = regs[j];
				execute_code(new_regs, instr->n1);
				for (int j = 0; j < instr->opnd; j++)
					regs[j] = new_regs[j];
				free(new_regs);
				i = instr->n2;
				break;
			}
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		puts("Need one argument");
		return 1;
	}

	long input = strtol(argv[1], NULL, 10); // BUG: 32-bit truncation

	read_code();
	uint64_t *regs = malloc(sizeof(uint64_t) * N_REGS);
	regs[0] = input;
	for (int i = 1; i < N_REGS; i++)
		regs[i] = 0;

	execute_code(regs, 0);
	printf("CTF{%016llx}\n", regs[0]);

	free(regs);
	return 0;
}
