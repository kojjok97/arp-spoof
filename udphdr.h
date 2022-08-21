#include <cstdint>
#include <netinet/in.h>

struct UdpHdr{

    uint16_t sport_;
    uint16_t dport_;
    uint16_t length_;
    uint16_t checksum_;

    uint16_t sport() {return htons(sport_);}
    uint16_t dport() {return htons(dport_);}
    uint16_t length() {return htons(length_);}
};


