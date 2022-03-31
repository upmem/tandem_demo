#include <stdint.h>
#include <perfcounter.h>

void wait (uint32_t seconds) {
    /* Reset the counter */
    (void) perfcounter_config(COUNT_CYCLES, true);
    do {
        ;
    } while (perfcounter_get() < (CLOCKS_PER_SEC * seconds));
}