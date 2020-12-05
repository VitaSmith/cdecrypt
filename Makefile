ifeq ($(OS),Windows_NT)
  EXE := .exe
else
  EXE :=
endif

BIN=cdecrypt
SRC=${BIN}.c util.c aes.c sha1.c
OBJ=${SRC:.c=.o}
DEP=${SRC:.c=.d}

# -Wno-sequence-point because *dst++ = dst[-d]; is only ambiguous for people who don't know how CPUs work.
CFLAGS=-std=c99 -pipe -fvisibility=hidden -Wall -Wextra -Werror -Wno-sequence-point -Wno-unknown-pragmas -Wno-multichar -UNDEBUG -DAES_ROM_TABLES -D_GNU_SOURCE -O2
ifeq ($(OS),Windows_NT)
LDFLAGS=-s -municode
else
LDFLAGS=-s
endif

.PHONY: all clean

all: ${BIN}${EXE}

clean:
	${RM} ${BIN} ${OBJ} ${DEP}

${BIN}${EXE}: ${OBJ}
	@echo [L] $@
	@${CC} ${LDFLAGS} -o $@ $^

%.o: %.c
	@echo [C] $<
	@${CC} ${CFLAGS} -MMD -c -o $@ $<

-include ${DEP}
