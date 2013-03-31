MAINFILE=butch.c

CFLAGS_OWN=-Wall -D_XOPEN_SOURCE=700
CFLAGS_DBG=-g3 -O0
CFLAGS_OPT=-s -Os

-include config.mak

CFLAGS_RCB_OPT=${CFLAGS_OWN} ${CFLAGS_OPT} ${CFLAGS}
CFLAGS_RCB_DBG=${CFLAGS_OWN} ${CFLAGS_DBG} ${CFLAGS}

all: debug

optimized:
	CFLAGS="${CFLAGS_RCB_OPT}" rcb --force $(RCBFLAGS) ${MAINFILE}

debug:
	CFLAGS="${CFLAGS_RCB_DBG}" rcb --force $(RCBFLAGS) ${MAINFILE}


.PHONY: all optimized debug
