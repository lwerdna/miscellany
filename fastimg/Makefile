CPPFLAGS = -std=c++11
FLAGS_DEBUG = -g -O0
LDFLAGS = $(shell fltk-config --use-images --ldstaticflags)

all: fastimg

fastimg: Gui.cxx Gui.h DndImage.cxx logic.cxx
	g++ $(CPPFLAGS) $(FLAGS_FLTK) $(FLAGS_DEBUG) Gui.cxx DndImage.cxx logic.cxx -o fastimg $(LDFLAGS)

install:
	install ./fastimg /usr/local/bin

clean:
	rm fastimg
	rm -rf fastimg.dSYM
