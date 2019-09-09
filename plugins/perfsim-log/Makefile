CFLAGS += -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I../include -fno-PIE -fPIC -O3
LDFLAGS += -shared
# TODO: Windows
DSOSUF := .so

NAME:= perfsim-log
BIN := $(NAME)$(DSOSUF)

FILES := perfsim-log.o bbv-defs.o simpoints-trace.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(FILES)
	$(CC) $(LDFLAGS) -o $(BIN) $(FILES)

clean:
	rm $(FILES)
	rm $(BIN)
