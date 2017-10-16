#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct entry {
  int age;
  char *name;
};

#define MAX_ENTRIES 1000
#define NAME_LEN_MAX 64

struct entry *directory[MAX_ENTRIES];
int slots[MAX_ENTRIES];

struct entry *creation() {
    char name[64];
    struct entry *e;

    e = (struct entry *) malloc(sizeof(struct entry));

    printf("Name: ");
    fgets(name, NAME_LEN_MAX, stdin);
    name[strlen(name)-1] = 0;
    e->name = malloc(strlen(name));
    strcpy(e->name, name);

    printf("Age: ");
    fgets(name,6,stdin);
    e->age = atoi(name);

    return e;
}

void change(int e) {
    char name[64];

    printf("New name: ");
    fgets(name, strlen(directory[e]->name)+1, stdin);

    name[strlen(name)] = 0;
    strcpy(directory[e]->name, name);
    printf("New age: ");
    fgets(name, 6, stdin);
    directory[e]->age = atoi(name);
}

void delete(int i) {
    free(directory[i]->name);
    free(directory[i]);
}

int choice(int min, int max, char * chaine) {
    int i;
    char buf[6];
    i = -1;
    while( (i < min) || (i > max)) {
        printf("%s", chaine);
        fgets(buf, 5, stdin);
        i = atoi(buf);
    }
    return i ;
}

int menu() {
    return(choice(1, 5, "Menu\n  1: New entry\n  2: Delete entry\n  3: Change entry\n  4: Show all\n  5: Exit\n---> "));
}

void show(int i) {
    printf("[%d] %s, %d years old\n", i, directory[i]->name, directory[i]->age);
}

int main()
{
    int i,j;
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    printf("* Simple directory - beta version *\n");
    printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
    for(i=0; i < MAX_ENTRIES; slots[i++] = 0);
    for(i=menu();i!=5;i=menu()) switch(i) { 
        case 1 :
            for (j=0;(slots[j]>0 ) && (j<MAX_ENTRIES);j++);
            if (j < MAX_ENTRIES) {
                directory[j] = creation();
                slots[j] = 1;
            }
            break;
        case 2 :
            j = choice(0, MAX_ENTRIES-1, "Entry to delete: ");
            delete(j);
            slots[j] = 0;
            break;
        case 3 : 
            j = choice(0, MAX_ENTRIES-1, "Entry to change: ");
            change(j);
            break;
        case 4 :
            printf("Entries:\n");
            for (j=0;j<MAX_ENTRIES;j++)
                if (slots[j])
                    show(j);
            printf("\n");
            break;
        default : break;
    }
}

