#include <stdint.h>
#include "mac.h"

#pragma pack(push, 1)
struct radiotap {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct association {
    uint16_t fc;
    uint16_t dur;
    Mac dest;
    Mac source;
    Mac bssid;
    uint16_t seq;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct wireless {
    uint16_t cap;
};
#pragma(pop)

#pragma pack(push, 1)
struct assocpacket {
    struct radiotap radio;
    struct association assoc;
    struct wireless wireles;
};
#pragma pack(pop)
