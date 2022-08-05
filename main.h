#ifndef NETFLOW_ANALYZER_MAIN_H
#define NETFLOW_ANALYZER_MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <mqueue.h>
#include <linux/if_packet.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if.h>
#include <signal.h>
#include <time.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include "uthash.h"

#define PACKET_SIZE 65536 //maximum packet size
#define FLOW_LIST_SIZE 128000 //default amount of possible flow records

#define FLOW_EXPIRY_INTERVAL 120000 //milliseconds
#define FLOW_EXPORT_INTERVAL 240 //seconds

#define FLOWSET_EXPORT 1 //1 - flowset is updated every FLOWSET_EXPORT_INTERVAL seconds
                            //0 - flowset is updated every FLOWSET_PACKET_INTERVAL export packets
#define FLOWSET_EXPORT_INTERVAL 300 //seconds
#define FLOWSET_EXPORT_PACKET 100

#define FLOWSET_ID 256
#define INTERFACE_LENGTH 6 //maximum interface length for sending Data Flow packet

pthread_t sock_read, check;
pthread_mutex_t lock;

_Bool run_switch = 1;

void closing_handler();
int parse_cmdline(int argc, char *argv[]);
void socket_close();
unsigned int c_time();
void *packet_parser();
void flow_identifier();
void *flow_check();

int sock_raw;
int data_size;

struct sockaddr_in fdest;
char interface[16];

struct sockaddr_in source, dest;

typedef struct uniq_flow_data {
    struct sockaddr_in source;
    struct sockaddr_in dest;
    uint16_t source_port;
    uint16_t dest_port;

    uint8_t protocol;
    uint8_t tos;

    uint8_t type;
    uint8_t code;

} uniq_flow_data;

typedef struct flow_data_casing {
    int data_size;

    uniq_flow_data flow_key;
    uint8_t flags;
    uint32_t first_switch;
    uint32_t last_switch;

    unsigned char in_src_mac[6];
    unsigned char in_dst_mac[6];
    uint16_t id;

    uint32_t last_export;

    uint32_t packet_counter;

    UT_hash_handle hh;

} flow_data_casing;
flow_data_casing *r = NULL;

flow_data_casing *casings[FLOW_LIST_SIZE];
int flow_size = FLOW_LIST_SIZE;  //FLOW_LIST_SIZE initialized as variable for further changes

int cur_el;
int flow_count;
unsigned char in_src_mac[6];
unsigned char in_dst_mac[6];
uint16_t id;

_Bool init_0, init_1;

// ============== NETFLOW PACKET =============
int total_exported = 0;

#pragma pack(push, 1)
struct nf_header {
    uint16_t version;
    uint16_t count;
    uint32_t uptime;
    uint32_t epoch_time;
    uint32_t pack_sequence;
    uint32_t source_id;
};

void flow_export(flow_data_casing *flow, struct nf_header header, char *buffer);

struct flowset {
    uint16_t flowset_id;
    uint16_t length;
    uint16_t template_id;
    uint16_t field_count;

    uint16_t fields[40];
};

typedef struct packet_template {
    uint16_t flowset_id;
    uint16_t length;
    uint32_t IN_BYTES;
    uint32_t IN_PKTS;
    uint32_t FLOWS;
    uint8_t PROTOCOL;
    uint8_t SRC_TOS;
    uint8_t TCP_FLAGS;
    uint16_t L4_SRC_PORT;
    uint32_t IPV4_SRC_ADDR;
    uint32_t INPUT_SNMP;
    uint16_t L4_DST_PORT;
    uint32_t IPV4_DST_ADDR;
    uint32_t LAST_SWITCHED;
    uint32_t FIRST_SWITCHED;
    uint16_t ICMP_TYPE;
    uint16_t FLOW_ACTIVE_TIMEOUT;
    uint16_t FLOW_INACTIVE_TIMEOUT;
    uint16_t IPV4_IDENT;
    unsigned char IN_SRC_MAC[6];
    unsigned char IN_DST_MAC[6];
    unsigned char IF_NAME[INTERFACE_LENGTH];

    unsigned char padding[3];
} packet_template;
#pragma pack(pop)

#endif //NETFLOW_ANALYZER_MAIN_H
