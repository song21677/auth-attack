#include <stdint.h>
#include "mac.h"

#pragma pack(push, 1)
struct radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct authentication {
    uint16_t fc;
    uint16_t dur;
    Mac dest;
    Mac source;
    Mac bssid;
    uint16_t seq;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct wireless_lan {
    uint16_t auth_algorithm;
    uint16_t auth_seq;
    uint16_t status;
    uint8_t tag_num;
    uint8_t tag_len;
    uint8_t oui[3];
    uint8_t vendor[6];
};
#pragma(pop)

#pragma pack(push, 1)
struct authpacket {
    struct radiotap_header radio;
    struct authentication auth;
    struct wireless_lan wireless;
};
#pragma pack(pop)
