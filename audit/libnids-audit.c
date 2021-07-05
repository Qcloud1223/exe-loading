// this audit interface is a test to hopefully fix the copy relocation
#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <nids.h>

// *** do a little tiangou-ing ***
// the reason why I have to do this in a hard way is that
// some functions like nids_ip_filter are static, I just cannot get the address outside the SO
// Plus, AUDIT interface is not powerful enough to refuse a symbol binding:
// once there is a hit, hit it is. Nothing can change this
// So the only thing I can do is to provide a set of definitions here, and interpose using audit

static void nids_syslog(int type, int errnum, struct ip *iph, void *data)
{
    fprintf(stderr, "nids_syslog not implemented\n");
}

void nids_no_mem(char *func)
{
    fprintf(stderr, "Out of memory in %s.\n", func);
    exit(1);
}

static int nids_ip_filter(struct ip *x, int len)
{
    (void)x;
    (void)len;
    return 1;
}

struct nids_prm nids_params = {
    1040,			/* n_tcp_streams */
    256,			/* n_hosts */
    NULL,			/* device */
    NULL,			/* filename */
    168,			/* sk_buff_size */
    -1,				/* dev_addon */
    nids_syslog,		/* syslog() */
    1,			/* syslog_level */
    256,			/* scan_num_hosts */
    3000,			/* scan_delay */
    10,				/* scan_num_ports */
    nids_no_mem,		/* no_mem() */
    nids_ip_filter,		/* ip_filter() */
    NULL,			/* pcap_filter */
    1,				/* promisc */
    0,				/* one_loop_less */
    1024,			/* pcap_timeout */
    0,				/* multiproc */
    20000,			/* queue_limit */
    0,				/* tcp_workarounds */
    NULL,			/* pcap_desc */
    3600			/* tcp_flow_timeout */
};
// *** end of tiangou-ing ***


unsigned int la_version(unsigned int version)
{
    return LAV_CURRENT;
}

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
{
    if(strcmp(map->l_name, "/usr/local/lib/libnids.so.1.25") == 0)
    {
        fprintf(stderr, "libnids reporting\n");
        return LA_FLG_BINDTO | LA_FLG_BINDFROM;
    }
    if(strcmp(map->l_name, "/home/hypermoon/Qcloud/TST-load-exe/src/main-libnids") == 0)
    {
        fprintf(stderr, "PIE executable reporting\n");
        return LA_FLG_BINDTO | LA_FLG_BINDFROM;
    }
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook, uintptr_t *defcook, unsigned int *flags, const char *symname)
{
    printf("binding symbol: %s\n", symname);
    // if (strcmp (symname, "nids_params") == 0)
    // {
    //     fprintf(stderr, "bind for nids_params\n");
    //     return (uintptr_t)&nids_params;
    // }
    return sym->st_value;
}