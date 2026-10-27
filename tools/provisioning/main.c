#include "board_layout.h"
#include "provisioning.h"
#include "board_flash.h"
#include "board_entropy.h"
#include "presence.h"
#include "pico/stdlib.h"
#include "pico/bootrom.h"
#include "hardware/watchdog.h"

/* Explicit RAM-only factory tool, never linked into the product. The host
 * loads it intentionally; NEW physical touch is still required before erase.
 * Success returns to ROM so the host can verify/load the normal application. */
static struct {
    Rp2350Provisioning provisioning;
    Rp2350Crypto crypto;
    Rp2350BoardFlash board;
    Rp2350Entropy entropy;
    Rp2350Presence presence;
    bool permission;
} app;
static void progress(void *ctx) { (void)ctx; watchdog_update(); }
static AuthStatus authorize(void *ctx) {
    (void)ctx;
    if(!app.permission) return AUTH_BUSY;
    app.permission=false; return AUTH_OK;
}
static AuthStatus open_flash(bool writes) {
    AuthStatus status=rp2350_board_flash_open(&app.board,0,writes ? RP2350_STORE_FLASH_BYTES : 0);
    app.board.progress=progress; return status;
}
int main(void) {
    gpio_init(PICO_DEFAULT_LED_PIN); gpio_set_dir(PICO_DEFAULT_LED_PIN,GPIO_OUT);
    gpio_init(RP2350_BUTTON_GPIO); gpio_set_dir(RP2350_BUTTON_GPIO,GPIO_IN); gpio_pull_up(RP2350_BUTTON_GPIO);
    watchdog_enable(6000,true);
    AuthStatus status=open_flash(false);
    if(status==AUTH_OK && !rp2350_board_entropy_init(&app.entropy)) status=AUTH_CRYPTO_ERROR;
    if(status==AUTH_OK) status=rp2350_crypto_init(&app.crypto,rp2350_entropy_read,&app.entropy);
    Rp2350Flash flash=rp2350_flash_guard_interface(&app.board.guard);
    if(status==AUTH_OK) status=rp2350_provisioning_init(&app.provisioning,&flash,&app.crypto,authorize,NULL);
    uint32_t now=to_ms_since_boot(get_absolute_time());
    rp2350_presence_init(&app.presence,!gpio_get(RP2350_BUTTON_GPIO),now);
    rp2350_presence_begin(&app.presence,1,now);
    for(;;) {
        now=to_ms_since_boot(get_absolute_time());
        if(status==AUTH_OK && rp2350_presence_sample(&app.presence,!gpio_get(RP2350_BUTTON_GPIO),now)==1) {
            app.permission=true;
            status=open_flash(true);
            if(status==AUTH_OK) status=rp2350_provisioning_run(&app.provisioning);
            if(status==AUTH_OK) {
                rp2350_provisioning_close(&app.provisioning);
                rp2350_crypto_free(&app.crypto); auth_secure_zero(&app,sizeof(app));
                watchdog_disable(); rom_reset_usb_boot(0,0);
            }
        }
        if(status!=AUTH_OK) {
            rp2350_provisioning_close(&app.provisioning); rp2350_crypto_free(&app.crypto);
            auth_secure_zero(app.entropy.previous,sizeof(app.entropy.previous));
        }
        bool on=status==AUTH_OK ? now%400U<200U : now%100U<50U;
        gpio_put(PICO_DEFAULT_LED_PIN,!on);
        watchdog_update(); sleep_ms(1);
    }
}
