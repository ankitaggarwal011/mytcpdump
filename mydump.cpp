/** 
    
    Author: Ankit Aggarwal
    Description: mydump is a passive network monitoring application.
    Build: sudo make clean && make
    Usage: sudo ./mydump [-i interface] [-r file] [-s string] expression

**/

#include <iostream>
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#define INTERFACE_MODE 1
#define FILE_MODE 2
#define IPV4 0x0800

#define SIZE_ETHERNET 14
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)

using namespace std;

string to_s(const u_char* str) {
    string s((char *)str);
    return s;
}

string to_s(const char* str) {
    string s(str);
    return s;
}

string to_s(int n) {
    return to_string(n);
}

string format_mac(char *str) {
    int a, b, c, d, e, f;
    char mac[20];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) == 6)
        sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X", a, b, c, d, e, f);
    string s(mac);
    return s;
}

char* sanitize_payload(char* str) {
    char sanitizied_payload[strlen(str) - 1];
    char *ch = str, *pl = sanitizied_payload, *s_pl = sanitizied_payload;
    while (*ch) {
        if (isprint(*ch)) {
            *pl = *ch;
            pl++;
        }
        ch++;
    }
    return s_pl;
}

/* Ethernet header */
struct sniff_ethernet {
    const struct ether_addr ether_dhost; /* Destination host address */
    const struct ether_addr ether_shost; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and destination address */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgment number */
    u_char th_offx2;    /* data offset, rsvd */
    u_char th_flags;
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
    u_short sport;  /* source port */
    u_short dport;  /* destination port */
    u_short udp_length;
    u_short udp_sum;    /* checksum */
};

int print_hex_ascii_line(const u_char *payload, int len) {
    const u_char *ch = payload;

    for(int i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
    }   
    if (len < 16) {
        int gap = 16 - len;
        for (int i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("  ");
    ch = payload;
    for(int i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");
    return 0;
}

int print_payload(const u_char *payload, int len) {
    int len_rem = len, line_width = 16, line_len;
    const u_char *ch = payload;

    if (len <= line_width) {
        print_hex_ascii_line(ch, len);
        return 0;
    }
    for (;;) {
        line_len = line_width % len_rem;
        print_hex_ascii_line(ch, line_len);
        len_rem = len_rem - line_len;
        ch = ch + line_len;
        if (len_rem <= line_width) {
            print_hex_ascii_line(ch, len_rem);
            break;
        }
    }
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {    
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const struct sniff_udp *udp;
    const u_char *payload;

    int size_ip, size_tcp, size_payload, size_udp = 8, size_icmp = 8;
    
    string packet_info = "";

    time_t raw_timestamp = (time_t)header->ts.tv_sec;
    struct tm *timestamp = localtime(&raw_timestamp);
    char buffer[100];
    strftime(buffer, 100, "%Y-%d-%m %T", timestamp);
    packet_info += to_s(buffer) + "." + to_s(header->ts.tv_usec) + " "; // Timestamp
    ethernet = (struct sniff_ethernet *)(packet);
    packet_info += format_mac((char *)ether_ntoa(&ethernet->ether_shost)) + " -> " + format_mac((char *)ether_ntoa(&ethernet->ether_dhost));
    stringstream ss;
    ss << hex << ntohs(ethernet->ether_type);
    string packet_type(ss.str());
    packet_info += " type 0x" + packet_type;
    if (ntohs(ethernet->ether_type) == IPV4) {
        ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;
        if (size_ip < 20) {
            cout << "Invalid IP header length." << endl;
            return;
        }
        if (ip->ip_p == IPPROTO_TCP) {
            tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp) * 4;
            if (size_tcp < 20) {
                cout << "Invalid TCP header length." << endl;
                return;
            }
            packet_info += " len " + to_s(header->len) + " "; // confusion, should it print Ethernet packet length or IP packet length to_s(ntohs(ip->ip_len))
            packet_info += to_s(inet_ntoa(ip->ip_src)) + ":" + to_s(ntohs(tcp->th_sport)) + " -> ";
            packet_info += to_s(inet_ntoa(ip->ip_dst)) + ":" + to_s(ntohs(tcp->th_dport));
            packet_info += " TCP ";

            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        }
        else if (ip->ip_p == IPPROTO_UDP) {
            udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
            packet_info += " len " + to_s(header->len) + " ";
            packet_info += to_s(inet_ntoa(ip->ip_src)) + ":" + to_s(ntohs(udp->sport)) + " -> ";
            packet_info += to_s(inet_ntoa(ip->ip_dst)) + ":" + to_s(ntohs(udp->dport));
            packet_info += " UDP ";

            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
        }
        else if (ip->ip_p == IPPROTO_ICMP) {
            packet_info += " len " + to_s(header->len) + " ";
            packet_info += to_s(inet_ntoa(ip->ip_src)) + " -> ";
            packet_info += to_s(inet_ntoa(ip->ip_dst));
            packet_info += " ICMP ";

            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
        }
        else {
            packet_info += " OTHER ";

            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
            size_payload = ntohs(ip->ip_len) - size_ip;
        }
    }
    else {
        packet_info += " len " + to_s(header->len) + " ";
        payload = (u_char *)(packet + SIZE_ETHERNET);
        size_payload = header->len - SIZE_ETHERNET;
    }
    if (*args and strlen((char *)args) > 0) {
        char *sanitizied_payload = sanitize_payload((char *)payload); // such that non-printable characters 
                                                                      // doesn't give incorrect results during string matching
        if (sanitizied_payload == NULL || size_payload == 0 || (!strstr(sanitizied_payload, (char *)args))) return;
    }
    cout << packet_info << endl;
    if (size_payload > 0) {
        print_payload(payload, size_payload);
    }
}

class mydump {
private:
    string interface, file, str, expr;
    char err[PCAP_ERRBUF_SIZE];
    int mode;
public:
    mydump(){
        this->mode = 0;
    }
    ~mydump(){}
private:
    string getInterface() {
        return this->interface;
    }
    string getFile() {
        return this->file;
    }
    string getString() {
        return this->str;
    }
    string getExpression() {
        return this->expr;
    }
public:
    int setInterface(string interface) {
        this->interface = interface;
        if (!this->mode) this->mode = INTERFACE_MODE;
        return 0;
    }
    int setFile(string file) {
        this->file = file;
        if (!this->mode) this->mode = FILE_MODE;
        return 0;
    }
    int setString(string str) {
        this->str = str;
        return 0;
    }
    int setExpression(string expr) {
        this->expr = expr;
        return 0;
    }
    int init() {
        if (!this->interface.empty() && !this->file.empty()) {
            cout << "You can specify either interface or file, not both. Please try again." << endl;
            return 0;
        }
        if (!this->mode) {
            this->mode = INTERFACE_MODE;
            this->interface = to_s(pcap_lookupdev(this->err));
            if (this->interface.empty()) {
                cout << "Couldn't find the default device: " << to_s(this->err) << endl;
                return 0;
            }
        }
        if (this->mode == INTERFACE_MODE) cout << "Listening on interface " << this->interface << endl;
        else if (this->mode == FILE_MODE) cout << "Reading file " << this->file << endl;
        return 1;
    }
    int monitorTraffic() {
        pcap_t *pcap;
        bpf_u_int32 network, mask;
        struct bpf_program filter;
        int status;
        if (this->mode == INTERFACE_MODE) {
            status = pcap_lookupnet(this->interface.c_str(), &network, &mask, err);
            if (status == -1) {
                cout << "Couldn't get IP address and mask: " << to_s(err) << endl;
            }
            pcap = pcap_open_live(this->interface.c_str(), BUFSIZ, 1, 1000, err);
            if (!pcap) {
                cout << "Couldn't open the live traffic: " << to_s(err) << endl;
                return 0;
            }
        }
        else if (this->mode == FILE_MODE) {
            pcap = pcap_open_offline(this->file.c_str(), err);
            if (!pcap) {
                cout << "Couldn't open the file: " << to_s(err) << endl;
                return 0;
            }
        }

        if (pcap_datalink(pcap) != DLT_EN10MB) {
            cout << "Couldn't find Ethernet frames on " << this->interface << endl;
            return 0;
        }

        if (!this->expr.empty()) {
            status = pcap_compile(pcap, &filter, this->expr.c_str(), 0, network);
            if (status == -1) {
                cout << "Couldn't compile expression: " << to_s(pcap_geterr(pcap)) << endl;
                return 0;
            }
            status = pcap_setfilter(pcap, &filter);
            if (status == -1) {
                cout << "Couldn't set filter expression: " << to_s(pcap_geterr(pcap)) << endl;
                return 0;
            }
        }

        pcap_loop(pcap, -1, got_packet, (u_char *)this->str.c_str()); // setting cnt = -1 for capturing packets until an error occurs
        pcap_close(pcap);
        return 0;
    }
};

int main(int argc, char *argv[]) {
    int opt;
    mydump *tcpdump = new mydump();
    while ((opt = getopt(argc, argv, "i:r:s:")) != -1) {
        switch(opt) {
            case 'i':
                tcpdump->setInterface(to_s(optarg));
                break;
            case 'r':
                tcpdump->setFile(to_s(optarg));
                break;
            case 's':
                if (optarg) tcpdump->setString(to_s(optarg));
                break;
            case '?':
                if (optopt == 'i' || optopt == 'r' || optopt == 's') return 0;
                else break;
            default:
                break;
        }
    }
    if (optind < argc - 1) {
        cout << "Please enter the correct number of arguments." << endl;
        cout << "Usage: mydump [-i interface] [-r file] [-s string] expression" << endl;
        return 0;
    }
    else if (optind == argc - 1) {
        tcpdump->setExpression(to_s(argv[optind]));
    }

    if (!tcpdump->init()) return 0;
    tcpdump->monitorTraffic();
    return 0;
}