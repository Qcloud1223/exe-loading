// Libnids used as main, a version where non-ascii chars got rid of

#define _GNU_SOURCE
#include <libnet.h>
#include <malloc.h>
#include <nids.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

char ascii_string[10000];
int state[7] = {0};          // a simple statistics on libnids
char *char_to_ascii(char ch)
{
    memset(ascii_string, 0x00, 10000);
    ascii_string[0] = 0;
    char *string = ascii_string;
    if (isgraph(ch))
    {
        *string++ = ch;
    }
    else if (ch == ' ')
    {
        *string++ = ch;
    }
    else if (ch == '\n' || ch == '\r')
    {
        *string++ = ch;
    }
    else
    {
        *string++ = '.';
    }
    *string = 0;
    return ascii_string;
}

void tcp_protocol_callback(struct tcp_stream *tcp_connection, void **arg)
{
    // printf("tcp_protocol_callback\n");
    int i;
    char address_string[1024];
    static char content[65535];
    // char content_urgent[65535];
    struct tuple4 ip_and_port = tcp_connection->addr;
    strcpy(address_string, inet_ntoa(*((struct in_addr *)&(ip_and_port.saddr))));
    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.source);
    strcat(address_string, " <---> ");
    strcat(address_string, inet_ntoa(*((struct in_addr *)&(ip_and_port.daddr))));
    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.dest);
    strcat(address_string, "\n");
    switch (tcp_connection->nids_state)
    {
    case NIDS_JUST_EST:
        tcp_connection->client.collect++;
        tcp_connection->server.collect++;
        tcp_connection->server.collect_urg++;
        tcp_connection->client.collect_urg++;
        printf("%sTCP connection sets up\n", address_string);
        state[NIDS_JUST_EST]++;
        return;
    case NIDS_CLOSE:
        printf("--------------------------------\n");
        printf("%sTCP connection closes normally\n", address_string);
        state[NIDS_CLOSE]++;
        return;
    case NIDS_RESET:
        printf("--------------------------------\n");
        printf("%sTCP Connection closed by RST\n", address_string);
        state[NIDS_RESET]++;
        return;
    case NIDS_DATA:
        {
            state[NIDS_DATA]++;
            struct half_stream *hlf;
            if (tcp_connection->server.count_new_urg)
            {
                printf("--------------------------------\n");
                strcpy(address_string, inet_ntoa(*((struct in_addr *)&(ip_and_port.saddr))));
                sprintf(address_string + strlen(address_string), " : %i", ip_and_port.source);
                strcat(address_string, " urgent---> ");
                strcat(address_string, inet_ntoa(*((struct in_addr *)&(ip_and_port.daddr))));
                sprintf(address_string + strlen(address_string), " : %i", ip_and_port.dest);
                strcat(address_string, "\n");
                address_string[strlen(address_string) + 1] = 0;
                address_string[strlen(address_string)] = tcp_connection->server.urgdata;
                printf("%s", address_string);
                return;
            }
            if (tcp_connection->client.count_new_urg)
            {
                printf("--------------------------------\n");
                strcpy(address_string, inet_ntoa(*((struct in_addr *)&(ip_and_port.saddr))));
                sprintf(address_string + strlen(address_string), " : %i", ip_and_port.source);
                strcat(address_string, " <--- urgent ");
                strcat(address_string, inet_ntoa(*((struct in_addr *)&(ip_and_port.daddr))));
                sprintf(address_string + strlen(address_string), " : %i", ip_and_port.dest);
                strcat(address_string, "\n");
                address_string[strlen(address_string) + 1] = 0;
                address_string[strlen(address_string)] = tcp_connection->client.urgdata;
                printf("%s", address_string);
                return;
            }
            if (tcp_connection->client.count_new)
            {
                hlf = &tcp_connection->client;
                strcpy(address_string, inet_ntoa(*((struct in_addr *)&(ip_and_port.saddr))));
                sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                strcat(address_string, " <--- ");
                strcat(address_string, inet_ntoa(*((struct in_addr *)&(ip_and_port.daddr))));
                sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
                strcat(address_string, "\n");
                printf("--------------------------------\n");
                printf("%s", address_string);
                memcpy(content, hlf->data, hlf->count_new);
                content[hlf->count_new] = '\0';
                printf("client side receive data\n");
                for (i = 0; i < hlf->count_new; i++) {
                   printf("%s", char_to_ascii(content[i]));
                }
                printf("\n");
                return;
            }
            else
            {
                hlf = &tcp_connection->server;
                strcpy(address_string, inet_ntoa(*((struct in_addr *)&(ip_and_port.saddr))));
                sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                strcat(address_string, " ---> ");
                strcat(address_string, inet_ntoa(*((struct in_addr *)&(ip_and_port.daddr))));
                sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
                strcat(address_string, "\n");
                printf("--------------------------------\n");
                printf("%s", address_string);
                memcpy(content, hlf->data, hlf->count_new);
                content[hlf->count_new] = '\0';
                printf("Server side receive data:\n");
                for (i = 0; i < hlf->count_new; i++) {
                   printf("%s", char_to_ascii(content[i]));
                }
                printf("\n");
                return;
            }
            for (int i = 10; i < 20; i += 1) {
                memcpy(&content[i * 1024], &content[(i - 10) * 1024], 1024);
            }
            return;
        }
    default:
        state[0]++;
        break;
    }
    return;
}

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

static void local_nids_init()
{
    nids_params.n_tcp_streams = 1040;
    nids_params.n_hosts = 256;
    nids_params.device = NULL;
    nids_params.filename = NULL;
    nids_params.sk_buff_size = 168;
    nids_params.dev_addon = -1;
    nids_params.syslog = nids_syslog;
    nids_params.syslog_level = 1;
    nids_params.scan_num_hosts = 256;
    nids_params.scan_delay = 3000;
    nids_params.scan_num_ports = 10;
    nids_params.no_mem = nids_no_mem;
    nids_params.ip_filter = nids_ip_filter;
    nids_params.pcap_filter = NULL;
    nids_params.promisc = 1;
    nids_params.one_loop_less = 0;
    nids_params.pcap_timeout = 1024;
    nids_params.multiproc = 0;
    nids_params.queue_limit = 20000;
    nids_params.tcp_workarounds = 0;
    nids_params.pcap_desc = NULL;
    nids_params.tcp_flow_timeout = 3600;
}

int main(int argc, char *argv[], char **env)
{
    struct nids_chksum_ctl temp;
    temp.netaddr = 0;
    temp.mask = 0;
    temp.action = 1;

    nids_register_chksum_ctl(&temp, 1);
    
    // sign... tiangou inside executable. This is just a quick check to see if there is other problems 
    // beside copy relocation
    // local_nids_init();
    nids_params.filename = "/dev/shm/huawei_tcp.pcap";
    // nids_params.device = "all";
    if (!nids_init())
    {
        printf("Error：%s\n", nids_errbuf);
        exit(1);
    }
    nids_register_tcp((void *)tcp_protocol_callback);

    nids_run();

    return 0;
}
