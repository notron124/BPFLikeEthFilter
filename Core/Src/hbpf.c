#include "hbpf.h"

uint8_t *mypData = NULL;
uint32_t filteredCounter = 0;
uint8_t _index = 0;
uint8_t X = 0;

struct sock_filter INSTRUCTION_ARP[] = {
         { BPF_JMP, 0, 0, 0x0C },
         { BPF_JEQ, 2, 3, ETH_P_ARP },
         { BPF_RET, 0, 0, 1 },
         { BPF_RET, 0, 0, 0 }
};

struct sock_filter INSTRUCTION_IP[] = {
         { BPF_JMP, 0, 0, 0x0C },
         { BPF_JEQ, 2, 3, ETH_P_IP },
         { BPF_RET, 0, 0, 1 },
         { BPF_RET, 0, 0, 0 }
};

struct sock_filter INSTRUCTION_IP_TCP[] = {
         { BPF_JMP, 0, 0, 0x0C },
         { BPF_JEQ, 2, 5, ETH_P_IP },
         { BPF_JMP, 0, 0, 0x17 },
         { BPF_JEQ, 4, 5, IP_TCP_PROTOCOL },
         { BPF_RET, 0, 0, 1 },
         { BPF_RET, 0, 0, 0 }
};

struct sock_filter INSTRUCTION_DEST_PORT[] = {
         { BPF_JMP,  0,  0,  0xC },
         { BPF_JEQ,  2,  10, ETH_P_IP },
         { BPF_JMP,  0,  0,  0x17 },
         { BPF_JEQ,  4,  10, IP_TCP_PROTOCOL },
         { BPF_JMP,  0,  0,  0x14},
         { BPF_JSET, 10, 6,  0x1FFF },
         { BPF_LDXB, 0,  0,  0xE },
         { BPF_JMP,  0,  0,  0x10 },
         { BPF_JEQ,  9,  10, 0x1BB },
         { BPF_RET,  0,  0,  1 },
         { BPF_RET,  0,  0,  0 }
};

struct sock_filter INSTRUCTION_IP_UDP[] = {
         { BPF_JMP, 0, 0, 0x0C },
         { BPF_JEQ, 2, 5, ETH_P_IP },
         { BPF_JMP, 0, 0, 0x17 },
         { BPF_JEQ, 4, 5, IP_UDP_PROTOCOL },
         { BPF_RET, 0, 0, 1 },
         { BPF_RET, 0, 0, 0 }
};

void jt(uint8_t destination)
{
   _index = destination;
}

void jf(uint8_t destination)
{
   _index = destination;
}

void jmp(uint8_t *pdata, uint32_t k)
{
   mypData = pdata;
   mypData += X + k;
   X = 0;
   _index++;
}


void ldxb(uint32_t k, uint8_t *pdata)
{
   mypData = pdata;
   mypData += k;
   X = 4*(*mypData & 0x0F);
}

uint8_t getKSize(uint32_t k)
{
   uint8_t size = 0;

   while (k != 0)
   {
      size++;
      k = k >> 8;
   }

   return size;
}

void jset(uint32_t k, struct sock_filter *filter)
{
   uint8_t kSize = getKSize(k);
   uint32_t actualData = 0;

   for (uint8_t i = 0; i < kSize; i++)
   {
      actualData = actualData << 8;
      actualData += *mypData;
      mypData++;
   }

   if ((actualData & 0x1FFF) == 0)
      jt(filter[_index].jt);
   else
      jf(filter[_index].jf);
}

void jeq(uint32_t k, struct sock_filter *filter)
{
   uint8_t kSize = getKSize(k);
   uint32_t actualData = 0;

   for (uint8_t i = 0; i < kSize; i++)
   {
      actualData = actualData << 8;
      actualData += *mypData;
      mypData++;
   }

   if (actualData == k)
      jt(filter[_index].jt);
   else
      jf(filter[_index].jf);
}

uint8_t Filter(uint8_t *pdata, struct sock_filter *filter)
{
   uint8_t output = 0;
   uint16_t size = 10;
   while (_index < size)
   {
      switch(filter[_index].code)
      {
      case BPF_JMP:
         jmp(pdata, filter[_index].k);
         break;

      case BPF_JEQ:
         jeq(filter[_index].k, filter);
         break;

      case BPF_JSET:
         jset(filter[_index].k, filter);
         break;

      case BPF_LDXB:
         ldxb(filter[_index].k, pdata);
         break;

      case BPF_RET:
         output = filter[_index].k;
         _index = 10;
         break;

      default:
         output = 0;
         _index = 10;
         break;
      }
   }
   return output;
   _index = 0;
}
