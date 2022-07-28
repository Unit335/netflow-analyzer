#include "main.h"

uniq_flow_data uniq_flow;

void closing_handler() 
{
    printf("\nClosing...\n");
    run_switch = 0;
    pthread_cancel(sock_read);
}

int main(int argc, char *argv[]) 
{
    signal(SIGINT, closing_handler);

    if (parse_cmdline(argc, argv) == 1)
        return 1;
    printf("Starting...\n");

    fdest.sin_family = AF_INET;
    int retcode;
    if ((retcode = pthread_create(&sock_read, NULL, packet_parser, NULL)) != 0) {
        fprintf(stderr, "pthread_create (sock_read): (%d)%s\n", retcode, strerror(retcode));
        return 1;
    }
    if ((retcode = pthread_create(&check, NULL, flow_check, NULL)) != 0) {
        fprintf(stderr, "pthread_create (stat): (%d)%s\n", retcode, strerror(retcode));
        return 1;
    }


    int main_retcode = 0;
    void *socket_retcode;
    pthread_join(sock_read, &socket_retcode);
    pthread_join(check, NULL);
    if ((intptr_t) socket_retcode == 1)
        main_retcode = 1;
    return main_retcode;

}

//receives and parses packets
void *packet_parser() 
{
    int saddr_size;
    struct sockaddr saddr;
    unsigned char *buffer = (unsigned char *) malloc(PACKET_SIZE);
    pthread_cleanup_push(free, buffer) ;

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error\n");
        pthread_exit((void *) 1);
    }
    pthread_cleanup_push(socket_close, NULL) ;

    if (interface[0] != '\0') {
        struct ifreq ifr;
        setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, "", 0);
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), interface);
        if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) == -1) {
            perror("Failure to bind socket to interface");
            pthread_exit((void *) 1);
        }
    }

    saddr_size = sizeof saddr;
    cur_el = 0; //points to current element in list of all flows, including deleted
    flow_count = 0;

    for (int i = 0; i < FLOW_LIST_SIZE; i++) {
        casings[i] = (flow_data_casing *) malloc(sizeof(flow_data_casing));
        memset(casings[i], 0, sizeof(flow_data_casing));
    }
    while (!(init_1));

    clock_t start, end;
    double cpu_time_used;


    while (run_switch) {
        data_size = recvfrom(sock_raw, buffer, PACKET_SIZE, 0, &saddr,
                             (socklen_t *) &saddr_size);

        if (data_size < 0) {
            perror("Recvfrom error: ");
            pthread_exit((void *) 1);
        }
        struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
        struct ethhdr *eth = (struct ethhdr *) buffer;
        if (iph->protocol == 17) { //UDP
            unsigned short iphdrlen = iph->ihl * 4;
            struct udphdr *udph = (struct udphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));
            memset(casings[cur_el], 0, sizeof(flow_data_casing));

            casings[cur_el]->flow_key.protocol = iph->protocol;
            casings[cur_el]->flow_key.tos = iph->tos;

            memset(&casings[cur_el]->flow_key.source, 0, sizeof(source));
            casings[cur_el]->flow_key.source.sin_addr.s_addr = iph->saddr;

            memset(&casings[cur_el]->flow_key.dest, 0, sizeof(dest));
            casings[cur_el]->flow_key.dest.sin_addr.s_addr = iph->daddr;
            casings[cur_el]->flow_key.dest_port = udph->dest;
            casings[cur_el]->flow_key.source_port = udph->source;

            memcpy(casings[cur_el]->in_src_mac, eth->h_source, 6);
            memcpy(casings[cur_el]->in_dst_mac, eth->h_source, 6);
            casings[cur_el]->id = iph->id;
        }
        else if (iph->protocol == 6) { //TCP
            unsigned short iphdrlen = iph->ihl * 4;
            struct tcphdr *tcph = (struct tcphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));
            memset(casings[cur_el], 0, sizeof(flow_data_casing));

            casings[cur_el]->flow_key.protocol = iph->protocol;
            casings[cur_el]->flow_key.tos = iph->tos;

            memset(&casings[cur_el]->flow_key.source, 0, sizeof(source));
            casings[cur_el]->flow_key.source.sin_addr.s_addr = iph->saddr;

            memset(&casings[cur_el]->flow_key.dest, 0, sizeof(dest));
            casings[cur_el]->flow_key.dest.sin_addr.s_addr = iph->daddr;
            casings[cur_el]->flow_key.dest_port = tcph->dest;
            casings[cur_el]->flow_key.source_port = tcph->source;

            memcpy(casings[cur_el]->in_src_mac, eth->h_source, 6);
            memcpy(casings[cur_el]->in_dst_mac, eth->h_source, 6);
            casings[cur_el]->id = iph->id;
        }
        else if (iph->protocol == 1) { //ICMP
            unsigned short iphdrlen = iph->ihl * 4;
            struct icmphdr *icmph = (struct icmphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));
            memset(casings[cur_el], 0, sizeof(flow_data_casing));

            casings[cur_el]->flow_key.protocol = iph->protocol;
            casings[cur_el]->flow_key.tos = iph->tos;

            memset(&casings[cur_el]->flow_key.source, 0, sizeof(source));
            casings[cur_el]->flow_key.source.sin_addr.s_addr = iph->saddr;

            memset(&casings[cur_el]->flow_key.dest, 0, sizeof(dest));
            casings[cur_el]->flow_key.dest.sin_addr.s_addr = iph->daddr;
            casings[cur_el]->flow_key.type = icmph->type;
            casings[cur_el]->flow_key.code = icmph->code;

            memcpy(casings[cur_el]->in_src_mac, eth->h_source, 6);
            memcpy(casings[cur_el]->in_dst_mac, eth->h_source, 6);
            casings[cur_el]->id = iph->id;
        }
        flow_identifier();
    }

    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);

    pthread_exit((void *) 0);
}

//creates and updates flows
void flow_identifier() 
{
    flow_data_casing *p;
    HASH_FIND(hh, r, &(casings[cur_el]->flow_key), sizeof(uniq_flow_data), p);
    if (p != NULL) {
        pthread_mutex_lock(&lock);
        p->last_switch = c_time();
        p->data_size += data_size;
        ++p->packet_counter;
        p->flags = casings[cur_el]->flags || p->flags;
        pthread_mutex_unlock(&lock);
    } else {
        casings[cur_el]->first_switch = c_time();
        casings[cur_el]->last_switch = casings[cur_el]->first_switch;
        casings[cur_el]->last_export = time(NULL);
        casings[cur_el]->packet_counter = 1;

        HASH_ADD(hh, r, flow_key, sizeof(uniq_flow_data), casings[cur_el]);
        ++cur_el;
        ++flow_count;

        if (cur_el >= flow_size) {
            flow_size += 2;
            casings[cur_el] = (flow_data_casing *) malloc(sizeof(flow_data_casing));
            casings[cur_el + 1] = (flow_data_casing *) malloc(sizeof(flow_data_casing));
        }

    }
}

//sends data about flow on expiration or in fixed time periods, updates flow set templates
//time variables defined in FLOW_EXPIRY_INTERVAL, FLOW_EXPORT_INTERVAL and FLOWSET_EXPORT_INTERVAL
void *flow_check()
{
    struct nf_header header = {
            .version = htons(9),
            .count = htons(1),
            .uptime = htonl((unsigned int) c_time()),
            .epoch_time = htonl(time(NULL)),
            .source_id = htonl(0x0001)
    };

    struct flowset fl_set = {.flowset_id = htons(0),
            .length = htons(4 * sizeof(uint16_t) +
                            sizeof(uint16_t) * 20 * 2),  //4 default field + id and size for 20 data fields
            .template_id = htons(FLOWSET_ID),
            .field_count = htons(20),
            .fields = {1, 4, //IN_BYTES
                       2, 4, //IN_PKTS
                       3, 4, //FLOWS
                       4, 1, //PROTOCOL
                       5, 1, //SRC_TOS
                       6, 1, //TCP_FLAGS
                       7, 2, //L4_SRC_PORT
                       8, 4, //IPV4_SRC_ADDR
                       10, 4,//INPUT_SNMP
                       11, 2,//L4_DST_PORT
                       12, 4,//IPV4_DST_ADDR
                       21, 4,//LAST_SWITCHED
                       22, 4,//FIRST_SWITCHED
                       32, 2,//ICMP_TYPE
                       36, 2,//FLOW_ACTIVE_TIMEOUT
                       37, 2,//FLOW_INACTIVE_TIMEOUT
                       54, 2,//IPV4_IDENT
                       56, 6,//IN_SRC_MAC
                       80, 6,//IN_DST_MAC
                       82, 6//IF_NAME
            }
    };
    for (int i = 0; i < 40; i++) {
        fl_set.fields[i] = htons(fl_set.fields[i]);
    }
    total_exported = 1;

    header.pack_sequence = htonl(total_exported);
    header.uptime = htonl((unsigned int) c_time());
    header.epoch_time = htonl(time(NULL));

    int export_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (export_socket == -1) {
        perror("export_socket: ");
        pthread_exit((void *) 1);
    }

    int flupdate_sie = sizeof(header) + sizeof(fl_set);
    char tbuffer[flupdate_sie];
    memcpy(tbuffer, &header, sizeof(header));
    memcpy(tbuffer + sizeof(header), &fl_set, sizeof(fl_set));

    if (sendto(export_socket, &tbuffer, sizeof(tbuffer), 0, (struct sockaddr *) &fdest, sizeof(fdest)) < 0) {
        perror("Data Flow Set update error");
    }
    unsigned int flowset_export = time(NULL);

    int buffer_size = sizeof(header) + sizeof(packet_template);
    char buffer[buffer_size];

    unsigned int last_flowset = 1; //for flowset export every N packets;

    sleep(1);
    init_1 = 1;

    while (run_switch) {
        flow_data_casing *p, *tmp;
        HASH_ITER(hh, r, p, tmp) {

            if (c_time() - p->last_switch >= FLOW_EXPIRY_INTERVAL) {
                pthread_mutex_lock(&lock);
                ++total_exported;
                flow_export(p, header, buffer, buffer_size);
                if (sendto(export_socket, &buffer, buffer_size, 0, (struct sockaddr *) &fdest, sizeof(fdest)) < 0) {
                    perror("Export on expiration error: ");
                }
                HASH_DEL(r, p);
                --flow_count;
                pthread_mutex_unlock(&lock);
            } else if (time(NULL) - p->last_export >= FLOW_EXPORT_INTERVAL) {
                pthread_mutex_lock(&lock);
                ++total_exported;
                flow_export(p, header, buffer, buffer_size);
                if (sendto(export_socket, &buffer, buffer_size, 0, (struct sockaddr *) &fdest, sizeof(fdest)) < 0) {
                    perror("Export error: ");
                } else p->last_export = time(NULL);
                pthread_mutex_unlock(&lock);
            }
        }
        if ( ( FLOWSET_EXPORT == 1 && time(NULL) - flowset_export >= FLOWSET_EXPORT_INTERVAL )
            || ( FLOWSET_EXPORT == 0 && total_exported - flowset_export >= FLOWSET_EXPORT_PACKET ) ) {
            header.pack_sequence = htonl(total_exported);
            header.uptime = htonl((unsigned int) c_time());
            header.epoch_time = htonl(time(NULL));
            ++total_exported;
            memcpy(tbuffer, &header, sizeof(header));
            if (sendto(export_socket, &tbuffer, sizeof(tbuffer), 0, (struct sockaddr *) &fdest, sizeof(fdest)) < 0) {
                perror("Data Flow set update error: ");
            } else flowset_export = time(NULL);
            flowset_export = total_exported;
        }

    }

    close(export_socket);
}

void flow_export(flow_data_casing *flow, struct nf_header header, char *buffer, int packet_size)
{
    packet_template *packet_data = (packet_template *) calloc(1, sizeof(packet_template));

    packet_data->flowset_id = htons(FLOWSET_ID);
    packet_data->length = htons(sizeof(packet_template));

    packet_data->IN_BYTES = htonl(flow->data_size);
    packet_data->IN_PKTS = htonl(flow->packet_counter);
    packet_data->FLOWS = htonl(1);
    packet_data->PROTOCOL = flow->flow_key.protocol;

    packet_data->SRC_TOS = flow->flow_key.tos;
    packet_data->TCP_FLAGS = flow->flags;
    packet_data->L4_SRC_PORT = flow->flow_key.source_port;
    packet_data->IPV4_SRC_ADDR = flow->flow_key.source.sin_addr.s_addr;

    packet_data->INPUT_SNMP = htonl(if_nametoindex(interface));
    packet_data->L4_DST_PORT = flow->flow_key.dest_port;
    packet_data->IPV4_DST_ADDR = flow->flow_key.dest.sin_addr.s_addr;
    packet_data->LAST_SWITCHED = htonl((unsigned int) flow->last_switch);

    packet_data->FIRST_SWITCHED = htonl((unsigned int) flow->first_switch);
    packet_data->ICMP_TYPE = htons(flow->flow_key.type);
    packet_data->FLOW_ACTIVE_TIMEOUT = htons((unsigned int) FLOW_EXPORT_INTERVAL);
    packet_data->FLOW_INACTIVE_TIMEOUT = htons((unsigned int) FLOW_EXPIRY_INTERVAL / 1000);

    packet_data->IPV4_IDENT = htons(flow->id);
    memcpy(packet_data->IN_SRC_MAC, flow->in_src_mac, 6);
    memcpy(packet_data->IN_DST_MAC, flow->in_dst_mac, 6);
    memcpy(packet_data->IF_NAME, interface, 6);

    header.count = htons(1);
    header.uptime = htonl(c_time());
    header.epoch_time = htonl(time(NULL));
    header.pack_sequence = htonl(total_exported);
    header.source_id = htonl(0x0001);

    memcpy(buffer, &header, sizeof(header));
    memcpy((buffer + sizeof(header)), packet_data, sizeof(packet_template));

    free(packet_data);
}

//returns time in ms
unsigned int c_time() 
{
    struct timespec res;
    clock_gettime(CLOCK_MONOTONIC, &res);
    unsigned int uptime_ms = res.tv_sec * 1000 + res.tv_nsec / 1000000;
    return uptime_ms;
}


int parse_cmdline(int argc, char *argv[]) 
{
    if (argc < 3) {
        printf("usage: udp-stat [ --interface INTERFACE --dest DESTINATION_IP --dest_port DESTINATION_PORT ] \n"
               "interface: name of network interface \n"
               "dest: collector IP \n"
               "dest_port: collector port\n");
        return 1;
    }
    if (argc != 0) {
        const char *short_options = "i:d:p:";
        const struct option long_options[] = {
                {"interface", required_argument, NULL, 'i'},
                {"dest",      required_argument, NULL, 'd'},
                {"dest_port", required_argument, NULL, 'p'},
                {NULL, 0,                        NULL, 0}
        };
        int rez;
        while ((rez = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
            switch (rez) {
                case 'i':
                    strncpy(interface, optarg, 16);
                    if ((sizeof(interface) - 1) > 15) {
                        perror("Invalid interface name: string too long");
                        return 1;
                    }
                    break;
                case 'd':
                    if (inet_pton(AF_INET, optarg, &(fdest.sin_addr)) <= 0) {
                        perror("Invalid IP in dest argument");
                        return 1;
                    }
                    break;
                case 'p':
                    if ((fdest.sin_port = htons(atoi(optarg))) == 0) {
                        perror("Invalid port number in dest_port argument");
                        return 1;
                    };
                    break;
                default:
                    printf("usage: udp-stat [ --interface INTERFACE --dest DESTINATION_IP --dest_port DESTINATION_PORT ] \n"
                           "interface: name of network interface \n"
                           "dest: collector IP \n"
                           "dest_port: collector port\n");
                    return 1;
            }
        }
    } 

    return 0;
}

void socket_close() 
{ 
	close(sock_raw); 
	for ( int i = 0; i < cur_el; i++ ) {
		free(casings[i]);
	} 
}
