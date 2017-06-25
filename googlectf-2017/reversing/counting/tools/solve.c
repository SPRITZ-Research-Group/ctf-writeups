#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

uint64_t fibonacci_mod(uint64_t n, uint64_t m)
{
	uint64_t a = 0, b = 1;
	for (uint64_t i = 0; i < n; i++) {
		uint64_t t = a;
		a = b;
		b = (t + b) % m;
	}
	return a;
}

uint64_t stopping_time(uint64_t n)
{
	uint64_t st = 0;
	while (n != 1) {
		if (n % 2 == 0) {
			n = n / 2;
			st += 1;
		} else {
			n = (3*n + 1) / 2;
			st += 2;
		}
	}
	return st;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Usage: %s <n>\n", argv[0]);
		return 1;
	}

	uint64_t n = strtoull(argv[1], NULL, 10);
	uint64_t st_sum = 0;
	for (uint64_t i = 1; i <= n; i++)
		st_sum += stopping_time(i);
	printf("Sum: %lld\n", st_sum);
	uint64_t flag = fibonacci_mod(n, st_sum);
	printf("CTF{%016llx}\n", flag);
}
