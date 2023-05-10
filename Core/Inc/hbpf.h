#ifndef _HBPF_H_
#define _HBPF_H_
#include "main.h"

#define ETH_ALEN        6               /* Octets in one ethernet addr   */
#define ETH_TLEN        2               /* Octets in ethernet type field */
#define ETH_HLEN        14              /* Total octets in header.       */
#define ETH_ZLEN        60              /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN    1500            /* Max. octets in payload        */
#define ETH_FRAME_LEN   1514            /* Max. octets in frame sans FCS */
#define ETH_FCS_LEN     4               /* Octets in the FCS             */

#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#define ETH_P_ARP       0x0806          /* Address Resolution packet    */
#define ETH_P_IPV6      0x86DD          /* IPv6 over bluebook           */

#define IP_TCP_PROTOCOL 0x6

#define BPF_JMP         0x00
#define BPF_JEQ         0x10
#define BPF_JSET        0x40
#define BPF_LDXB        0x50
#define BPF_RET         0x80

extern uint16_t okCounter;
extern uint8_t *mypData;
extern char myStr[];
extern uint8_t _index;


struct sock_filter {
   uint16_t code;
   void (*functionTrue)(struct sock_filter *filter);
   void (*functionFalse)(struct sock_filter *filter);
   uint32_t k;
};

extern struct sock_filter INSTRUCTION_IP[];
extern struct sock_filter INSTRUCTION_IP_UDP[];

struct sock_fprog {
        unsigned short len;
        struct sock_filter *filter;
};
#endif
