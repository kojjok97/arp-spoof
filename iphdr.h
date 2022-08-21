#pragma once

#include <cstdint>
#include <netinet/in.h>
#include "ip.h"

struct IpHdr final{
    uint8_t version_header_length_;
    uint8_t TOS_;
    uint16_t total_length_;
    uint16_t identification_;
    uint16_t fragment_offset_;
    uint8_t ttl_;
    uint8_t protocol_;
    uint16_t header_checksum_;
    Ip sip_;
    Ip dip_;

    Ip sip() {return std::string(sip_);}
    Ip dip() {return std::string(dip_);}
    uint8_t protocol() {return protocol_;}
    uint8_t header_length() {return (version_header_length_& 0x0f)*4;}
    uint8_t version() {return (version_header_length_ & 0xf0) >> 4;}
    uint8_t TOS() {return TOS_;}
    uint16_t total_length() {return htons(total_length_);}
    uint16_t identification() {return htons(identification_);}
    uint16_t fragment_offset() {return htons(fragment_offset_);}
    uint8_t ttl() {return ttl_;}
    uint16_t header_checksum() {return htons(header_checksum_);}

    enum: uint8_t{
        ICMP = 1,
        IGMP = 2,
        TCP = 6,
        UDP = 17

    };
};
