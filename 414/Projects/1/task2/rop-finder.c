#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

int MAX_SIZE;

struct linkedList {
    struct linkedList *nxt;
    struct linkedList *prv;
    int head;
    unsigned char x;
};

typedef struct linkedList *node;

node add(node ptr,unsigned char x) {
    ptr->nxt = (node)malloc(sizeof(struct linkedList));
    ptr->nxt->prv = ptr;
    ptr = ptr->nxt;
    ptr->x = x;
    return ptr;
}

void print(node ptr) {
    if (ptr->x == 0xc3)
    {
        puts("ret\n");
        return;
    }

    if (ptr->x == 0x01 || ptr->x == 0x04 || ptr->x == 0x05) {
        printf("add ");
    }
    else if (ptr->x == 0x31 || ptr->x == 0x34 || ptr->x == 0x35) {
        printf("xor ");
    }
    else if (ptr->x == 0x89 || ptr-> x == 0xb0 || ptr->x == 0xb8) {
        printf("mov ");
    }
    else if (ptr->x == 0x68) {
        printf("push ");
    }
    else if (ptr->x == 0xcd) {
        printf("int ");
    }
    else {
        puts("Error: quitting");
        exit(EXIT_FAILURE);
    }

    if (ptr->x == 0x01 || ptr->x == 0x31 || ptr->x == 0x89) {
        ptr = ptr->nxt;
        if (ptr->x == 0xcd) {
            puts("ebp,ecx");
        }
        else if (ptr->x == 0xd8) {
            puts("eax,ebx");
        }
        else if (ptr->x == 0xf7) {
            puts("edi,esi");
        }
        else {
            puts("Error: quitting");
            exit(EXIT_FAILURE);
        }
    }
    else if (ptr->x == 0x04 || ptr->x == 0x34 || ptr->x == 0xb0) {
        ptr = ptr->nxt;
        printf("al,0x%hhx\n",ptr->x);
    }
    else if (ptr->x == 0x05 || ptr->x == 0x35 || ptr->x == 0xb8) {
        ptr = ptr->nxt;
        int tmp = 0;
        tmp |= ptr->x;
        ptr = ptr->nxt;
        tmp |= ptr->x<<8;
        ptr = ptr->nxt;
        tmp |= ptr->x<<16;
        ptr = ptr->nxt;
        tmp |= ptr->x<<24;
        printf("eax,0x%08x\n",tmp);
    }
    else if (ptr->x == 0x68) {
        ptr = ptr->nxt;
        int tmp = 0;
        tmp |= ptr->x;
        ptr = ptr->nxt;
        tmp |= ptr->x<<8;
        ptr = ptr->nxt;
        tmp |= ptr->x<<16;
        ptr = ptr->nxt;
        tmp |= ptr->x<<24;
        printf("0x%08x\n",tmp);
    } else if (ptr->x == 0xcd) {
        ptr = ptr->nxt;
        printf("0x%hhx\n",ptr->x);
    } else {
        puts("Error: quitting");
        exit(EXIT_FAILURE);
    }
    ptr = ptr->nxt;
    print(ptr);
}

void backtrack(node ptr, int cnt) {
    if (cnt == MAX_SIZE || ptr->head) {
        print(ptr->nxt);
        return;
    }

    node tmp = ptr;
    for(int i = 0 ; i < 4 ; i++)
    {
        tmp = tmp->prv;
        if (tmp->head) break;
    }

    bool ok = 0;

    if (!tmp->head) {
        // printf("%x\n",tmp->x);
        if (tmp->x == 0x05 || tmp->x == 0x35 || tmp->x == 0xb8 || tmp->x == 0x68) {
            backtrack(tmp->prv,cnt+1);
            ok = 1;
        }
    }

    tmp = ptr->prv;
    if (!tmp->head) {
        if (tmp->x == 0x04 || tmp->x == 0x34 || tmp->x == 0xb0 || tmp->x == 0xcd) {
            backtrack(tmp->prv,cnt+1);
            ok = 1;
        }
    }

    if (ptr->x == 0xcd || ptr->x == 0xd8 || ptr->x == 0xf7) {
        if (tmp->x == 0x01 || tmp->x == 0x31 || tmp->x == 0x89) {
            backtrack(tmp->prv,cnt+1);
            ok = 1;
        }
    }
    if (!ok) print(ptr->nxt);
}

int main(int argc,char* argv[]) {
    if (argc != 3) {
        puts("Error: invalid command-line arguments");
        return EXIT_FAILURE;
    }
    MAX_SIZE = atoi(argv[1]);
    FILE *fp = fopen(argv[2],"r");
    if (fp == 0) {
        puts("Error: quitting");
        return EXIT_FAILURE;
    }

    node ptr = (node)malloc(sizeof(struct linkedList));
    ptr->head = 1;

    unsigned char x;

    while(fread(&x, sizeof(unsigned char), 1, fp)) {
        ptr = add(ptr,x);
        if (x == 0xc3) backtrack(ptr->prv,0);
    }

    return EXIT_SUCCESS;
}