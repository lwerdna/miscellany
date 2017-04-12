CPPFLAGS = -std=c++11
FLAGS_DEBUG = -g -O0
LDFLAGS = $(shell fltk-config --use-images --ldstaticflags)
LDFLAGS += -L/usr/local/lib
LDFLAGS += -lre2

all: re2lab

re2lab: Gui.cxx Gui.h logic.cxx
	g++ $(CPPFLAGS) $(FLAGS_FLTK) $(FLAGS_DEBUG) Gui.cxx logic.cxx -o re2lab $(LDFLAGS)

install:
	install ./re2lab /usr/local/bin

clean:
	rm re2lab
	rm -rf re2lab.dSYM
