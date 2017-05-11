#include <linux/elf.h>
#include <sys/prctl.h>

#define PAGE_SIZE 4096
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

#define EI_NIDENT       16
#define NT_PRSTATUS     1
#define NT_PRFPREG      2
#define NT_PRPSINFO     3
#define NT_TASKSTRUCT   4
#define NT_AUXV         6
#define NT_PRXFPREG     0x46e62b7f      /* copied from gdb5.1/include/elf/common.h */
#define CORE_STR "CORE"
#define ELF_CORE_EFLAGS 0
#define MAX_THREAD 5


/*#define int int*/

typedef struct i386_regs {    /* Normal (non-FPU) CPU registers            */
#define BP ebp
#define SP esp
#define IP eip
        unsigned int  ebx, ecx, edx, esi, edi, ebp, eax;
        unsigned short  ds, __ds, es, __es;
        unsigned short  fs, __fs, gs, __gs;
        unsigned int  orig_eax, eip;
        unsigned short  cs, __cs;
        unsigned int  eflags, esp;
        unsigned short  ss, __ss;
}REGS;

typedef struct fpregs {     /* FPU registers                             */
        unsigned long  cwd;
        unsigned long  swd;
        unsigned long  twd;
        unsigned long  fip;
        unsigned long  fcs;
        unsigned long  foo;
        unsigned long  fos;
        unsigned long  st_space[20];   /* 8*10 bytes for each FP-reg = 80 bytes     */
} FPREGS;


typedef struct elf_timeval {    /* Time value with microsecond resolution    */
        long tv_sec;                  /* Seconds                                   */
        long tv_usec;                 /* Microseconds                              */
} elf_timeval;


typedef struct elf_siginfo {    /* Information about signal (unused)         */
        int si_signo;             /* Signal number                             */
        int si_code;              /* Extra code                                */
        int si_errno;             /* Errno                                     */
} elf_siginfo;


typedef struct prstatus {       /* Information about thread; includes CPU reg*/
        elf_siginfo    pr_info;       /* Info associated with signal               */
        unsigned short       pr_cursig;     /* Current signal                            */
        unsigned long  pr_sigpend;    /* Set of pending signals                    */
        unsigned long  pr_sighold;    /* Set of held signals                       */
        unsigned int          pr_pid;        /* Process ID                                */
        unsigned int          pr_ppid;       /* Parent's process ID                       */
        unsigned int          pr_pgrp;       /* Group ID                                  */
        unsigned int          pr_sid;        /* Session ID                                */
        elf_timeval    pr_utime;      /* User time                                 */
        elf_timeval    pr_stime;      /* System time                               */
        elf_timeval    pr_cutime;     /* Cumulative user time                      */
        elf_timeval    pr_cstime;     /* Cumulative system time                    */
        REGS           pr_reg;        /* CPU registers                             */
        unsigned int       pr_fpvalid;    /* True if math co-processor being used      */
} PRSTATUS;

typedef struct prpsinfo {       /* Information about process                 */
        unsigned char  pr_state;      /* Numeric process state                     */
        char           pr_sname;      /* Char for pr_state                         */
        unsigned char  pr_zomb;       /* Zombie                                    */
        signed char    pr_nice;       /* Nice val                                  */
        unsigned long  pr_flag;       /* Flags                                     */
        unsigned short       pr_uid;        /* User ID                                   */
        unsigned short       pr_gid;        /* Group ID                                  */
        int          pr_pid;        /* Process ID                                */
        int          pr_ppid;       /* Parent's process ID                       */
        int          pr_pgrp;       /* Group ID                                  */
        int          pr_sid;        /* Session ID                                */
        char           pr_fname[16];  /* Filename of executable                    */
        char           pr_psargs[80]; /* Initial part of arg list                  */
} PRPSINFO;


typedef struct _user {           /* Ptrace returns this data for thread state */
        REGS           regs;          /* CPU registers                             */
        unsigned long  fpvalid;       /* True if math co-processor being used      */
        FPREGS         fpregs;        /* FPU registers                             */
        unsigned long  tsize;         /* Text segment size in pages                */
        unsigned long  dsize;         /* Data segment size in pages                */
        unsigned long  ssize;         /* Stack segment size in pages               */
        unsigned long  start_code;    /* Starting virtual address of text          */
        unsigned long  start_stack;   /* Starting virtual address of stack area    */
        unsigned long  signal;        /* Signal that caused the core dump          */
        unsigned long  reserved;      /* No longer used                            */
        REGS          *regs_ptr;     /* Used by gdb to help find the CPU registers*/
        FPREGS         *fpregs_ptr;   /* Pointer to FPU registers                  */
        unsigned long  magic;         /* Magic for old A.OUT core files            */
        char           comm[32];      /* User command that was responsible         */
        unsigned long  debugreg[8];
        unsigned long  error_code;    /* CPU error code or 0                       */
        unsigned long  fault_address; /* CR3 or 0                                  */
} USER;

typedef int TASKSTRUCT;




#ifdef NO_ELF_HEADER
typedef struct
{
        unsigned char   e_ident[EI_NIDENT];
        unsigned short  e_type;
        unsigned short  e_machine;
        unsigned long   e_version;
        unsigned long   e_entry;
        unsigned long   e_phoff;
        unsigned long   e_shoff;
        unsigned long   e_flags;
        unsigned short  e_ehsize;
        unsigned short  e_phentsize;
        unsigned short  e_phnum;
        unsigned short  e_shentsize;
        unsigned short  e_shnum;
        unsigned short  e_shstrndx;
}
Elf32_Ehdr;

/* Program header */
typedef struct
{
        unsigned long   p_type;
        unsigned long   p_offset;
        unsigned long   p_vaddr;
        unsigned long   p_paddr;
        unsigned long   p_filesz;
        unsigned long   p_memsz;
        unsigned long   p_flags;
        unsigned long   p_align;
        unsigned long   p_compsz;
        unsigned long   p_crc;
}
Elf32_Phdr;

/* Section header */
typedef struct
{
        unsigned long   sh_name;
        unsigned long   sh_type;
        unsigned long   sh_flags;
        unsigned long   sh_addr;
        unsigned long   sh_offset;
        unsigned long   sh_size;
        unsigned long   sh_link;
        unsigned long   sh_info;
        unsigned long   sh_addralign;
        unsigned long   sh_entsize;
        unsigned long   sh_compsz;
        unsigned long   sh_crc;
}
Elf32_Shdr;

/* Symbol table */
typedef struct
{
        unsigned long   st_name;
        unsigned long   st_value;
        unsigned long   st_size;
        unsigned char   st_info;
        unsigned char   st_other;
        unsigned short  st_shndx;
}
Elf32_Sym;

typedef struct
{
  unsigned long n_namesz;                       /* Length of the note's name.  */
  unsigned long n_descsz;                       /* Length of the note's descriptor.  */
  unsigned long n_type;                 /* Type of the note.  */
} Elf32_Nhdr;
#endif

#define ELF_CLASS ELFCLASS32
#define Ehdr      Elf32_Ehdr
#define Phdr      Elf32_Phdr
#define Shdr      Elf32_Shdr
#define Nhdr      Elf32_Nhdr

#define ELF_ARCH  EM_386


typedef enum
{
        REGION_CODE,
        REGION_DATA,
        REGION_BSS,
        REGION_STACK,
        REGION_HEAP,
        REGION_MAX
}REGION_TYPE;

typedef struct mem_region
{
        REGION_TYPE type;
        int valid;
        int start;
        int end;
        int size;
}REGION;




void dump_core(int handle, char *mem, REGS regs, REGION *r)
{



        Ehdr *ehdr = (Ehdr *)mem;
        char *name=NULL;
        Nhdr *nhdr = NULL;
        int nsize = 0;
        PRSTATUS *prstatus = NULL;
        int thread=0;





        int noffset =  sizeof(Ehdr);
        /* Write note section                                                */
        /* scope */


        for(thread=0;thread<MAX_THREAD;thread++)
        {
                //THREAD 1
                nhdr = (Nhdr*)&mem[noffset + nsize];
                memset((void*)nhdr, 0, sizeof(Nhdr));
                nhdr->n_namesz   = 5;
                nhdr->n_descsz   = sizeof(PRSTATUS);
                nhdr->n_type     = NT_PRSTATUS;
                name = (char*)&nhdr[1];
                strncpy(name, "CORE", 4);
                prstatus=(PRSTATUS*)(name + ALIGN(nhdr->n_namesz, 4) );
                prstatus->pr_reg = regs;
                prstatus->pr_cursig = 6;
                prstatus->pr_pid = getpid()+thread;
                nsize += sizeof(Nhdr) + ALIGN(nhdr->n_namesz, 4) + nhdr->n_descsz;


                //PRPSINFO
                nhdr = (Nhdr*)&mem[noffset+nsize];
                memset((void*)nhdr, 0, sizeof(Nhdr));
                nhdr->n_namesz   = 5;
                nhdr->n_descsz   = sizeof(PRPSINFO);
                nhdr->n_type     = NT_PRPSINFO;

                name = (char*)&nhdr[1];
                strncpy(name, CORE_STR, 4);
                PRPSINFO *prpsinfo=(PRPSINFO*)(name + ALIGN(nhdr->n_namesz, 4) );
                memset(prpsinfo, 0, sizeof(PRPSINFO));
                prpsinfo->pr_pid = getpid()+thread;
                prpsinfo->pr_state   = 0;
                prpsinfo->pr_sname   = 'R';
                prpsinfo->pr_zomb    = 0;

                strcpy(prpsinfo->pr_fname, "vmlinux");
                nsize += sizeof(Nhdr) + ALIGN(nhdr->n_namesz, 4) + nhdr->n_descsz;
                prctl(PR_GET_NAME, prpsinfo->pr_psargs, 0L, 0L, 0L);


                //USER INFO
                nhdr = (Nhdr*)&mem[noffset+nsize];
                memset((void*)nhdr, 0, sizeof(Nhdr));
                nhdr->n_namesz   = 5;
                nhdr->n_descsz   = sizeof( USER);
                nhdr->n_type     = NT_PRXFPREG;

                name = (char*)&nhdr[1];
                strncpy(name, CORE_STR, 4);
                USER *user=(USER*)(name + ALIGN(nhdr->n_namesz, 4) );
                memset(user, 0, sizeof(USER));
                //TODO
                nsize += sizeof(Nhdr) + ALIGN(nhdr->n_namesz, 4) + nhdr->n_descsz;


                //TASK STRUCT
                nhdr = (Nhdr*)&mem[noffset+nsize];
                memset((void*)nhdr, 0, sizeof(Nhdr));
                nhdr->n_namesz   = 5;
                nhdr->n_descsz   = sizeof( TASKSTRUCT);
                nhdr->n_type     = NT_TASKSTRUCT;

                name = (char*)&nhdr[1];
                strncpy(name, CORE_STR, 4);
                TASKSTRUCT *ts =(TASKSTRUCT*)(name + ALIGN(nhdr->n_namesz, 4) );
                memset(ts, 0, sizeof(TASKSTRUCT));
                /*memcpy(ts, current, sizeof(TASKSTRUCT));*/
                nsize += sizeof(Nhdr) + ALIGN(nhdr->n_namesz, 4) + nhdr->n_descsz;

        }







        int soffset = noffset + nsize;
        char *stack = (char*)&mem[soffset];
        memcpy(stack, (char*)r[REGION_STACK].start, r[REGION_STACK].size);
        int ssize = r[REGION_STACK].size;

        int hoffset = soffset + ssize;
        char *heap = (char*)&mem[hoffset];
        memcpy(heap, (char*)r[REGION_HEAP].start, r[REGION_HEAP].size);
        int hsize = r[REGION_HEAP].size;


        int doffset = hoffset + hsize;
        char *data = (char*)&mem[doffset];
        memcpy(data, (char*)r[REGION_DATA].start, r[REGION_DATA].size);
        int dsize = r[REGION_DATA].size;


        int boffset = doffset + dsize;
        char *bss = (char*)&mem[boffset];
        memcpy(bss, (char*)r[REGION_BSS].start, r[REGION_BSS].size);
        int bsize = r[REGION_BSS].size;

        int poffset = boffset + bsize;
        int pcount=0;
        Phdr *phdr = (Phdr*)&mem[poffset];

        phdr[pcount].p_type = PT_NOTE;
        phdr[pcount].p_offset = noffset;
        phdr[pcount].p_vaddr =0;
        phdr[pcount].p_paddr =0;
        phdr[pcount].p_filesz = nsize;
        phdr[pcount].p_memsz = phdr->p_filesz;
        phdr[pcount].p_flags = 0;
        phdr[pcount].p_align = 0;
        pcount++;


        phdr[pcount].p_type   = PT_LOAD;
        phdr[pcount].p_offset = soffset;
        phdr[pcount].p_vaddr  = r[REGION_STACK].start;
        phdr[pcount].p_paddr  = 0;
        phdr[pcount].p_filesz = r[REGION_STACK].size;
        phdr[pcount].p_memsz  = phdr[1].p_filesz;
        phdr[pcount].p_flags  = PF_R|PF_W;
        phdr[pcount].p_align  = PAGE_SIZE;
        pcount++;

        phdr[pcount].p_type   = PT_LOAD;
        phdr[pcount].p_offset = hoffset;
        phdr[pcount].p_vaddr  = r[REGION_HEAP].start;
        phdr[pcount].p_paddr  = 0;
        phdr[pcount].p_filesz = r[REGION_HEAP].size;
        phdr[pcount].p_memsz  = phdr[1].p_filesz;
        phdr[pcount].p_flags  = PF_R|PF_W;
        phdr[pcount].p_align  = PAGE_SIZE;
        pcount++;


        phdr[pcount].p_type   = PT_LOAD;
        phdr[pcount].p_offset = doffset;
        phdr[pcount].p_vaddr  = r[REGION_DATA].start;
        phdr[pcount].p_paddr  = 0;
        phdr[pcount].p_filesz = r[REGION_DATA].size;
        phdr[pcount].p_memsz  = phdr[1].p_filesz;
        phdr[pcount].p_flags  = PF_R|PF_W;
        phdr[pcount].p_align  = PAGE_SIZE;
        pcount++;

        phdr[pcount].p_type   = PT_LOAD;
        phdr[pcount].p_offset = boffset;
        phdr[pcount].p_vaddr  = r[REGION_BSS].start;
        phdr[pcount].p_paddr  = 0;
        phdr[pcount].p_filesz = r[REGION_BSS].size;
        phdr[pcount].p_memsz  = phdr[1].p_filesz;
        phdr[pcount].p_flags  = PF_R|PF_W;
        phdr[pcount].p_align  = PAGE_SIZE;
        pcount++;

        ehdr->e_ident[0] = ELFMAG0;
        ehdr->e_ident[1] = ELFMAG1;
        ehdr->e_ident[2] = ELFMAG2;
        ehdr->e_ident[3] = ELFMAG3;
        ehdr->e_ident[4] = ELF_CLASS;
        ehdr->e_ident[5] = ELFDATA2LSB;
        ehdr->e_ident[6] = EV_CURRENT;
        ehdr->e_type     = ET_CORE;
        ehdr->e_machine  = ELF_ARCH;
        ehdr->e_version  = EV_CURRENT;
        ehdr->e_phoff    = poffset;
        ehdr->e_shoff    = 0;
        ehdr->e_ehsize   = sizeof(Ehdr);
        ehdr->e_phnum    = pcount;
        ehdr->e_shnum    = 0;
        ehdr->e_phentsize= sizeof(Phdr);
        ehdr->e_shentsize= sizeof(Shdr);
        ehdr->e_shstrndx = 0;

}

#include <malloc.h>
#include <stdio.h>
#include <assert.h>
/*#include <elf.h>*/
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


  /* On x86 we provide an optimized version of the FRAME() macro, if the
   * compiler supports a GCC-style asm() directive. This results in somewhat
   * more accurate values for CPU registers.
   */
  typedef struct Frame {
    struct i386_regs uregs;
    int              errno_;
    unsigned int     tid;
  } Frame;
  #define FRAME(f) Frame f;                                           \
                   do {                                               \
                     f.errno_ = errno;                                \
                     f.tid    = 0;                                    \
                     __asm__ volatile (                               \
                       "push %%ebp\n"                                 \
                       "push %%ebx\n"                                 \
                       "mov  %%ebx,0(%%eax)\n"                        \
                       "mov  %%ecx,4(%%eax)\n"                        \
                       "mov  %%edx,8(%%eax)\n"                        \
                       "mov  %%esi,12(%%eax)\n"                       \
                       "mov  %%edi,16(%%eax)\n"                       \
                       "mov  %%ebp,20(%%eax)\n"                       \
                       "mov  %%eax,24(%%eax)\n"                       \
                       "mov  %%ds,%%ebx\n"                            \
                       "mov  %%ebx,28(%%eax)\n"                       \
                       "mov  %%es,%%ebx\n"                            \
                       "mov  %%ebx,32(%%eax)\n"                       \
                       "mov  %%fs,%%ebx\n"                            \
                       "mov  %%ebx,36(%%eax)\n"                       \
                       "mov  %%gs,%%ebx\n"                            \
                       "mov  %%ebx, 40(%%eax)\n"                      \
                       "call 0f\n"                                    \
                     "0:pop %%ebx\n"                                  \
                       "add  $1f-0b,%%ebx\n"                          \
                       "mov  %%ebx,48(%%eax)\n"                       \
                       "mov  %%cs,%%ebx\n"                            \
                       "mov  %%ebx,52(%%eax)\n"                       \
                       "pushf\n"                                      \
                       "pop  %%ebx\n"                                 \
                       "mov  %%ebx,56(%%eax)\n"                       \
                       "mov  %%esp,%%ebx\n"                           \
                       "add  $8,%%ebx\n"                              \
                       "mov  %%ebx,60(%%eax)\n"                       \
                       "mov  %%ss,%%ebx\n"                            \
                       "mov  %%ebx,64(%%eax)\n"                       \
                       "pop  %%ebx\n"                                 \
                       "pop  %%ebp\n"                                 \
                     "1:"                                             \
                       : : "a" (&f) : "memory");                      \
                     } while (0)




REGION region[REGION_MAX];
#define CORE_SIZE 512*1024
#if 0
void get_current_stack(int *start, int *end)
{
        char cmd[512]="";

        sprintf(cmd, "cat /proc/%d/maps|grep stack", getpid() );
        FILE *fp = popen(cmd, "r");
        assert(fp);
        fscanf(fp, "%x-%x", start, end);
        fclose(fp);

}
#endif
void get_region(REGION *r, char *type)
{
        char cmd[512]="";

        sprintf(cmd, "cat /proc/%d/maps|grep %s", getpid(), type );
        FILE *fp = popen(cmd, "r");
        assert(fp);
        fscanf(fp, "%x-%x", &r->start, &r->end);
        r->size = r->end - r->start;
        r->valid = 1;
        printf("[ %s ] start:%x, end:%x\n", type, r->start, r->end);
        fclose(fp);

}
extern char __data_start[];
extern char _edata[];
void get_region_data(REGION *r)
{
        printf("[ DATA ] start:%x, end:%x\n", __data_start, _edata);
        r->start = (int)__data_start;
        r->end =  (int)_edata;
        r->size = (int)(_edata-__data_start);
        r->valid = 1;

}
int a[256];
extern char __bss_start[];
extern char _end[];
void get_region_bss(REGION *r)
{
        /*char *__bss_end = region[REGION_HEAP].end;*/
        /*char *__bss_end = (char*)( ( (int)(__bss_start) + 4096)& (~4096) );*/
        char *__bss_end = (char*)_end;
        printf("[ BSS ] start:%x, end:%x\n", __bss_start, __bss_end);
        r->start = (int)__bss_start;
        r->end =  (int)__bss_end;
        r->size = (int)(__bss_end-__bss_start);
        r->valid = 1;
        a[0]=0xAABBCCDD;

}
/*extern char *malloc_begin;*/
/*extern char *malloc_end;*/

int testvar=0xDEADBEAF;
void get_region_all(REGION *r)
{

        get_region ( &region[REGION_HEAP], "heap");
        get_region ( &region[REGION_STACK], "stack");
        get_region_data( &region[REGION_DATA]);
        get_region_bss( &region[REGION_BSS]);
}
void dump_core_self(char *filename)
{
        FRAME (f);

        /*int *p=NULL; *p=NULL;*/

        get_region_all(region);
        /*printf("Start:%x, End:%x, size:%d\n", start, end, end-start);*/

        int handle = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if(handle <0)
        {
                perror("Invalid handle");
                exit(0);
        }
        lseek(handle, CORE_SIZE-1, SEEK_SET);
        write(handle, "", 1);
        lseek(handle, 0, SEEK_SET);

        char *memblock = NULL;
        memblock = mmap(NULL, CORE_SIZE, PROT_WRITE|PROT_READ, MAP_SHARED, handle, 0);

        if (memblock == MAP_FAILED)
        {
                perror("mmap failed");
                exit(0);
        }



        /*printf("MMAP:%x, SIZE:%d\n", memblock, CORE_SIZE);*/
        dump_core(handle, memblock, f.uregs, region);

        // Write it now to disk
        if (msync(memblock, CORE_SIZE, MS_SYNC) == -1)
        {
                perror("Could not sync the file to disk");
        }
        munmap(memblock, CORE_SIZE);
        close(handle);
        printf("Core file %s created successfully!\n", filename);
}

int main(int argc, char *argv[])
{
        /*printf("HEAP: start:%x, end:%x\n", malloc_begin, malloc_end);*/
        dump_core_self("core.file");
        printf("DATA END:%x\n", sbrk(0));
}
