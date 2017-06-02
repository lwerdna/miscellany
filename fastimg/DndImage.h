#include <FL/Fl.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Select_Browser.H>
#include <FL/Fl_Widget.H>

#include <FL/Fl_GIF_Image.H>
#include <FL/Fl_JPEG_Image.H>
#include <FL/Fl_PNG_Image.H>
#include <FL/Fl_PNM_Image.H>
#include <FL/Fl_XBM_Image.H>
#include <FL/Fl_XPM_Image.H>

#include <vector>
#include <string>

class DndImage : public Fl_Widget
{
    public:
	Fl_Image *myImage = NULL;

    DndImage(int x, int y, int w, int h, const char *label="");
    int handle(int event);

	void draw(void);
};
