#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char* reverse(char s[]) {
	int length = strlen(s);
	int c,i,j;

	for(i=0, j=length-1; i < j; i++, j--) {
		c=s[i];
		s[i]=s[j];
		s[j]=c;
	}
return s;
}

int main(int argc, char **argv) {

if (argc < 2) {
	printf("Usage %s <string to revert>",argv[0]);
	exit(1);
} else {
	printf("%s",reverse(argv[1]));
}

return 0;
}

