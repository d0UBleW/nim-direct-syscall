SRC=$(wildcard *.nim)
BIN=$(SRC:%.nim=%)

NFLAGS :=--app:console
NFLAGS +=--cpu:amd64
NFLAGS +=--d:mingw
# NFLAGS +=--d:release

.PHONY: clean

build: $(BIN)

clean:
	rm -f $(BIN)

rebuild: clean build

$(BIN): $(SRC)
	nim c $(NFLAGS) $<
