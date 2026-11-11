#!/bin/bash
# Build the LoRa Basics Station testsim variant into build/station/bin/station,
# for tests/test_station.py. Linux builds as upstream does; macOS needs a few
# shims (scripts/station-macos-compat.h) and a stubbed SPI driver, since the
# testsim radio is simulated and the concentrator is never opened.
# macOS needs Xcode's command line tools and `brew install argp-standalone`.
set -euo pipefail

COMMIT=ba4f85d80a438a5c2b659e568cd2d0f0de08e5a7   # v2.0.6
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/build/station
SRC=$OUT/src

if [[ ! -d $SRC ]]; then
    git clone https://github.com/lorabasics/basicstation.git "$SRC"
fi
cd "$SRC"
git checkout -q "$COMMIT"

ARGS=(platform=linux variant=testsim "ARCH.linux=$(gcc -dumpmachine)")

if [[ $(uname) == Darwin ]]; then
    BREW=$(brew --prefix)
    (cd deps/lgw && platform=linux variant=testsim ./prep.sh)
    LGW=deps/lgw/platform-linux/libloragw/src
    cat > $LGW/loragw_spi.native.c <<'STUB'
/* testsim replaces the radio (lgwsim); SPI is never opened. */
#include <stdint.h>
int lgw_spi_open(void **p) { (void)p; return -1; }
int lgw_spi_close(void *t) { (void)t; return -1; }
int lgw_spi_w(void *t, uint8_t m, uint8_t g, uint8_t a, uint8_t d) { return -1; }
int lgw_spi_r(void *t, uint8_t m, uint8_t g, uint8_t a, uint8_t *d) { return -1; }
int lgw_spi_wb(void *t, uint8_t m, uint8_t g, uint8_t a, uint8_t *d, uint16_t s) { return -1; }
int lgw_spi_rb(void *t, uint8_t m, uint8_t g, uint8_t a, uint8_t *d, uint16_t s) { return -1; }
STUB
    sed -i '' 's/clock_nanosleep(CLOCK_MONOTONIC, 0, &dly, &rem);/nanosleep(\&dly, \&rem);/' $LGW/loragw_aux.c
    ARGS+=("CFLAGS.linux.testsim=-g -O0 -D_DARWIN_C_SOURCE -I$BREW/include -include $ROOT/scripts/station-macos-compat.h"
           "LIBS.linux=-llgw -lmbedtls -lmbedx509 -lmbedcrypto -lpthread -L$BREW/lib -largp")
else
    ARGS+=("CFLAGS.linux.testsim=-g -O0")
fi

make "${ARGS[@]}"
mkdir -p "$OUT/bin"
cp build-linux-testsim/bin/station "$OUT/bin/station"
"$OUT/bin/station" --version
