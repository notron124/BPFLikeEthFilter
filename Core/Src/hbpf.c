#include "hbpf.h"
#include "pbuf.h"

struct pbuf mypbuf;
uint16_t okCounter = 0;
uint8_t *mypData = NULL;
uint32_t filteredCounter = 0;
uint8_t _index = 0;
uint8_t X = 0;
char myStr[7];


void FunctionTrue(struct sock_filter *filter)
{
   okCounter++;
   _index++;
}

void FunctionFalse(struct sock_filter *filter)
{
   filteredCounter++;
   _index++;
}

void SetRet(struct sock_filter *filter);

void Continue(struct sock_filter *filter)
{
   _index++;
}

struct sock_filter INSTRUCTION_IP[] = {
        { BPF_JMP, NULL, NULL, 0x0000000c },
        { BPF_JEQ, FunctionTrue, FunctionFalse, ETH_P_ARP },
        { 0x06, NULL, NULL, 0x00040000 },
        { 0x06, NULL, NULL, 0x00000000 }
};

struct sock_filter INSTRUCTION_IP_UDP[] = {
         { BPF_JMP, NULL, NULL, 0xC},
         { BPF_JEQ, Continue, SetRet, ETH_P_IP },
         { BPF_JMP, NULL, NULL, 0x17 },
         { BPF_JEQ, Continue, SetRet, 0x11 },
         //{ BPF_JMP, NULL, NULL, 0x14},
         //{ BPF_JSET, SetRet, Continue, 0x1FFF },
         //{ BPF_LDXB, NULL, NULL, 0xE },
         //{ BPF_JMP, NULL, NULL, 0x10 },
         //{ BPF_JEQ, Continue, SetRet, 0x1BB},
         { BPF_RET, NULL, NULL, 0x00040000 }
};

void SetRet(struct sock_filter *filter)
{
   _index = 10;
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
      filter[_index].functionTrue(filter);
   else
      filter[_index].functionFalse(filter);
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
      filter[_index].functionTrue(filter);
   else
      filter[_index].functionFalse(filter);
}

void Filter(uint8_t *pdata, struct sock_filter *filter)
{
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
         okCounter++;
         _index = 10;
         break;

      default:
         _index = 10;
         break;
      }
   }
   _index = 0;
}
