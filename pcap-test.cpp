#include <iostream>
#include <libnet.h>
#include <pcap.h>

void print_mac(uint8_t *mac, char *src){
    printf("ethernet %s mac : %02x:%02x:%02x:%02x:%02x:%02x\n",src,mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void popopo(const u_char *pkt){
    libnet_ethernet_hdr *eth = (libnet_ethernet_hdr *)pkt;
    uint16_t eth_type = ((eth->ether_type & 0xff) << 8) + ((eth->ether_type & 0xff00) >> 8);

    libnet_ipv4_hdr *ip = (libnet_ipv4_hdr *)(pkt + sizeof(libnet_ethernet_hdr));
    libnet_tcp_hdr *tcp = (libnet_tcp_hdr *)((u_char *)ip + sizeof(libnet_ipv4_hdr));
    u_char *data;

    // if not TCP
    if(eth_type != ETHERTYPE_IP){
        return;
    }

    // line
    printf("=========================================\n\n");

    // ethernet
    printf("ethernet\n");
    print_mac(eth->ether_shost, "src");
    print_mac(eth->ether_dhost, "dest");
    printf("ethernet type : 0x%04x\n\n", eth_type);

    // ip
    printf("ip\n");
    printf("ip src : %s\n", inet_ntoa(ip->ip_src));
    printf("ip dest : %s\n\n", inet_ntoa(ip->ip_dst));

    // tcp
    printf("tcp\n");
    printf("port src : %5d\n", tcp->th_sport);
    printf("port dest : %5d\n\n", tcp->th_dport);

    // data
    uint32_t len = ip->ip_len - sizeof(libnet_ipv4_hdr) - sizeof(libnet_tcp_hdr);
    printf("data length : %d\n", len);

    len = len > 16 ? 16 : len;
    data = (u_char *)tcp + tcp->th_off * 4;

    printf("data : ");
    for(int i=0; i<len; i++){
        printf("%02x", data[i]);
    }
    
    printf("\n\n");
}

void usage(){
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char *argv[]){
    if(argc != 2){
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *popo = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    
    if(!popo){
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -2;
    }

    while(1){
        struct pcap_pkthdr *hdr;
        const u_char* pkt;
        int r = pcap_next_ex(popo, &hdr, &pkt);
        if( !r ){
            continue;
        }
        if (r == -1 || r == -2){
            break;
        }
        popopo(pkt);
    }

    pcap_close(popo);
}
