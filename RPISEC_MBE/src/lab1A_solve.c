#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char name[32]="cr0c01";
    char serial[32]="todo";
    int result;
    int len;
    int i;
    int keys;
    name[strcspn(name,"\n")]=0;
    len=strnlen(name,32);
    if (len > 5)
    {
        if (ptrace(0,0,1,0) == -1) {
            puts("\x1B[32m.-----------------------------.");
            puts("\x1B[32m| !! TAMPERING DETECTED  !!   |");
            puts("\x1B[32m'-----------------------------'");
            result=1;
        }
        else {
            keys=(name[3] ^ 0x1337) + 6221293;
            for (i=0; i < len; i++) {
                if(name[i] <= 31)
                return 1;
            keys += (keys ^ (unsigned int)name[i]) % 0x539;
            }
            printf("keys: %d\n", keys);
            result=serial != keys;
        }
    } else {
        result = 1;
    }
return 0;
}
