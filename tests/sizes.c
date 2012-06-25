#include <stdio.h>

void sizes(void)
{
#ifdef __WORDSIZE
	printf("__WORDSIZE\t%d bits\n", __WORDSIZE);
#endif
	printf("pointer\t\t%ld bytes\n", sizeof(void *));
	printf("long double\t%ld bytes\n", sizeof(long double));
	printf("long long\t%ld bytes\n", sizeof(long long));
	printf("double\t\t%ld bytes\n", sizeof(double));
	printf("long\t\t%ld bytes\n", sizeof(long));
	printf("int\t\t%ld bytes\n", sizeof(int));
	printf("float\t\t%ld bytes\n", sizeof(float));
	printf("short\t\t%ld bytes\n", sizeof(short));
	printf("char\t\t%ld byte\n", sizeof(char));
}

int main()
{
	sizes();

	return 0;
}
