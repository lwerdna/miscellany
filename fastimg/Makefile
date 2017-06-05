CPPFLAGS = -std=c++11
FLAGS_DEBUG = -g -O0
LDFLAGS = $(shell fltk-config --use-images --ldstaticflags)
LDFLAGS += -L/usr/local/lib -lautils -lgd

SRCS = Gui.cxx Gui.h DndImage.cxx DndImage.h logic.cxx logic.h

all: fastimg

fastimg: $(SRCS)
	g++ $(CPPFLAGS) $(FLAGS_FLTK) $(FLAGS_DEBUG) Gui.cxx DndImage.cxx logic.cxx -o fastimg $(LDFLAGS)

install:
	install ./fastimg /usr/local/bin

clean:
	rm fastimg
	rm -rf fastimg.dSYM
