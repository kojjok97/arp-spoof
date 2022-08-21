#include <cstdint>
#include <netinet/in.h>

struct TcpHdr{

    uint16_t sport_;
    uint16_t dport_;
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    uint8_t offset_reserved;
    uint8_t tcp_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;

    uint16_t sport() {return htons(sport_);}
    uint16_t dport() {return htons(dport_);}
    uint16_t offset() {return ((offset_reserved & 0xf0) >> 4)*4;}

};

