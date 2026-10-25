#ifndef TUNNIXKEY_USB_TRANSPORT_H
#define TUNNIXKEY_USB_TRANSPORT_H
#include "application.h"
/* One owner on core 0. USB callbacks copy input only; application calls happen
 * outside tud_task, so callbacks cannot reenter the CTAP coordinator. */
bool rp2350_usb_init(void);
void rp2350_usb_close(void);
bool rp2350_usb_submit(void *, const uint8_t report[64], uint64_t transfer);
CtaphidDeviceResult rp2350_usb_poll(Rp2350Application *);
#endif
