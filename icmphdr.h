#include <cstdint>


struct IcmpHdr{
    uint8_t type_;
    uint8_t code_;
    uint16_t checksum_;
    uint32_t message_;
};
