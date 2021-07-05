// previous tests show that localtime called in dlopen-ed executables may get SEGFAULT
// since we now have a self-compiled version of glibc, it benefits to see if the problem persists

/* July. 5 update:
 * I found out where the problem lies using a self-compiled glibc which is not stripped
 *   and it really comes to my rescue.
 * Using a separate copy of renamed glibc may lack some critical initialization happens in rtld.c,
 *   making `malloc' calls internal to glibc fails. The program crashes when dl_addr ask for a lock,
 *   at dl-addr.c:131
 * So it comes to a dilemma again, we have to rethink about the design choice: glibc may have another
 *   100 of subtle bugs even reading the source won't help a lot. Of course we could cherry-pick, but 
 *   the impact remains uncertain. To me, I think making initialized libc and ld.so shared might be a 
 *   better choice. This can be done if we are using PKU, for the consistency of address space is no 
 *   longer an issue.
 * TO achieve this, dlmopen and deepbind are almost absolutely disabled. Also, the symbols inside global
 *   scope also need to be considered wisely.
 * Another issue is that I still can't make audit interface working when dealing with dlopen-ed libararies.
 *   If I can get this working, deepbind or not might not be an issue.
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main()
{
    time_t t = 1555332781;
    struct tm *tm = localtime(&t);
    printf("daylight: %d\n", daylight);
    printf("isdst: %d\n", tm->tm_isdst);

    return 0;
}