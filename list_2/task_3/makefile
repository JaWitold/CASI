PROG ?= task_3

all: $(PROG)

# Debug version.
#
$(PROG): main.c

	g++ -O0 -g3 -W -Wall -I../../include -L../../ -o $(PROG) main.c -lssl -lcrypto -lpthread

clean:
	rm -rf $(PROG) *.o *.obj