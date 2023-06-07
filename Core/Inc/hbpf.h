#ifndef _HBPF_H_
#define _HBPF_H_
#include "main.h"

#define ETH_P_IP        0x0800
#define ETH_P_ARP       0x0806

#define IP_TCP_PROTOCOL 0x6
#define IP_UDP_PROTOCOL 0x11

#define BPF_JMP         0x00
#define BPF_JEQ         0x10
#define BPF_JSET        0x40
#define BPF_LDXB        0x50
#define BPF_RET         0x80

extern uint32_t filteredCounter;

struct sock_filter {
   uint16_t code;
   uint8_t jt;
   uint8_t jf;
   uint32_t k;
};

extern struct sock_filter INSTRUCTION_IP[];
extern struct sock_filter INSTRUCTION_IP_UDP[];
extern struct sock_filter INSTRUCTION_DEST_PORT[];

#endif
