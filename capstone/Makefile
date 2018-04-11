FLAGS_DEBUG = -g -O0
LDFLAGS += -L/usr/local/lib -lautils -lcapstone

SRCS = capstone.c

all: capstone

capstone: $(SRCS)
	gcc $(CPPFLAGS) $(FLAGS_FLTK) $(FLAGS_DEBUG) $(SRCS) -o capstone $(LDFLAGS)

install:
	install ./capstone /usr/local/bin

link:
	ln -s `pwd`/capstone /usr/local/bin/capstone

clean:
	rm capstone
