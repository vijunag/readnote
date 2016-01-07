
#include <stdio.h>
#include <stdlib.h>

int main()
{
	int *a = NULL;
	fprintf(stderr, "Blow up!!!\n");
	*a = 0;
}

