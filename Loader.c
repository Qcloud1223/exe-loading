// 'clean' version of a rewriter and loader
// To run:
// LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/ gdb --args  ./Loader /home/hypermoon/Qcloud/change-ELF/test/time
// patched ELF outputs at /usr/local/lib, so it's necessary to include it as a library path

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>

void rewrite(const char *filename)
{
    // ugh! we still have to rewrite the ELF header to HOAX poor little ld.so...
    FILE *f = fopen(filename, "rb+");
    char *tHeader = malloc(sizeof(Elf64_Ehdr));
    if(fread(tHeader, sizeof(Elf64_Ehdr), 1, f) <= 0)
    {
        fprintf(stderr, "reading ELF header from %s failed\n", filename);
        exit(-1);
    }
    Elf64_Ehdr *etmp = (Elf64_Ehdr *)tHeader;
    // this won't work because PIEs are considered as shared objects and has ET_DYN type
    // printf("the type of ELf is %s\n", etmp->e_type == ET_DYN? "ET_DYN": "ET_EXEC");
    // etmp->e_type = ET_DYN;
    Elf64_Addr entry = etmp->e_entry;
    Elf64_Addr phoff = etmp->e_phoff;
    Elf64_Addr phlen = etmp->e_phnum * sizeof(Elf64_Phdr);
    Elf64_Half phnum = etmp->e_phnum;
    Elf64_Phdr *phdr = malloc(phlen);
    fseek(f, phoff, SEEK_SET);
    fread(phdr, phlen, 1, f);
    Elf64_Dyn *ld;
    Elf64_Sxword ldlen;
    Elf64_Off ldoff;
    for(Elf64_Phdr *ph = phdr; ph < &phdr[phnum]; ph++)
    {
        if (ph->p_type == PT_DYNAMIC)
        {
            ld = malloc(ph->p_memsz);
            ldoff = ph->p_offset;
            fseek(f, ldoff, SEEK_SET);
            ldlen = ph->p_memsz;
            fread(ld, ldlen, 1, f);
            break;
        }
    }
    for(Elf64_Dyn *d = ld; ;d++)
    {
        if(d->d_tag == DT_FLAGS_1)
        {
            d->d_un.d_val = 0;
            break;
        }
    }
    fseek(f, ldoff, SEEK_SET);
    if(fwrite(ld, ldlen, 1, f) <= 0)
    {
        fprintf(stderr, "overwrite the content of dynamic section failed\n");
        exit(-1);
    }
    fclose(f);
}

static void debug_stop()
{
    int sleeper;
    scanf("%d", &sleeper);
}

int main(int argc, char *argv[])
{
    if (argc != 2 && argc != 3)
    {
        fprintf(stderr, "usage: ./Loader [exe name] (optional)[address of main]\n");
        exit(-1);
    }
    rewrite(argv[1]);

    // now life is sane, we finally can dlopen the modified version of executable
    void *handle1 = dlopen(argv[1], RTLD_NOW);
    // void *handle1 = dlopen(argv[1], RTLD_NOW | RTLD_DEEPBIND);
    // void *handle1 = dlmopen(LM_ID_NEWLM, argv[1], RTLD_NOW);
    if(!handle1)
    {
        fprintf(stderr, "cannot loader shared object because: %s\n", dlerror());
        exit(-1);
    }
    // void *handle1 = dlmopen(LM_ID_NEWLM, argv[1], RTLD_NOW);
    // note that I don't bother to compile without -rdynamic when testing, it saves useless job
    int (*main1)() = dlsym(handle1, "main");

    // debug_stop();
    if (main1 != NULL)
        main1();
    else
    {
        if(argc == 3)
        {
            printf("using address of main at %s\n", argv[2]);
            unsigned long main_num = strtoul(argv[2], NULL, 0);
            struct link_map *l = (struct link_map *)handle1;
            main_num += l->l_addr;
            main1 = (void *)main_num;
            main1();
        }
        else
        {
            fprintf(stderr, "cannot find main of executable, nor you provide one. Try recompile with rdynamic\n");
            exit(-1);
        }
    }
    return 0;
}