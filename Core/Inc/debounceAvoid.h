#ifndef _DEBOUNCE_AVOID_H_
#define _DEBOUNCE_AVOID_H_

/*Your main header file*/
#include "main.h"

struct Key_TypeDef
{
   GPIO_TypeDef *GPIOx;
   uint16_t pin;
   uint16_t counter;
   uint8_t shortPressID;
   uint8_t longPressID;
   struct {
      uint8_t autorepeat : 1;
      uint8_t isPressed : 1;
   } flags;
};

struct Keys_Properties
{
   uint8_t shortPressDelay;
   uint16_t longPressDelay;
   uint8_t autorepeatSpeed;
};

extern uint8_t keyCode;

extern uint8_t commonKeyFlags;

#define F_KEY_READY     0x01

#define SET_KEY_READY   commonKeyFlags |= F_KEY_READY
#define RESET_KEY_READY commonKeyFlags &= ~F_KEY_READY
#define KEY_READY       (commonKeyFlags & F_KEY_READY)



void DebounceAvoid(struct Key_TypeDef *keyx, struct Keys_Properties *keysProperties);

#endif
