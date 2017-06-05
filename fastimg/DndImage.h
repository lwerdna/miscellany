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
using namespace std;

#define DISPLAY_OPT_TOP_LEFT 1 
#define DISPLAY_OPT_EXPAND_WIDTH 2
#define DISPLAY_OPT_EXPAND_HEIGHT 4
#define DISPLAY_OPT_SHRINK_WIDTH 8
#define DISPLAY_OPT_SHRINK_HEIGHT 16
#define DISPLAY_OPT_MATCH_WIDTH 32
#define DISPLAY_OPT_MATCH_HEIGHT 64

#define IMG_FILE_TYPE_INVALID 0
#define IMG_FILE_TYPE_JPG 1
#define IMG_FILE_TYPE_PNG 2

class DndImage : public Fl_Widget
{
    public:
	vector<uint8_t> imgFileBuf;
	int imgFileType = IMG_FILE_TYPE_INVALID;

	Fl_Image *myImage = NULL;
	bool dndEnabled = true;
	//int displayOpts = DISPLAY_OPT_TOP_LEFT;
	int displayOpts = DISPLAY_OPT_MATCH_WIDTH | DISPLAY_OPT_MATCH_HEIGHT;

	/* constructor */
    DndImage(int x, int y, int w, int h, const char *label="");

	/* fltk stuff */
	void draw(void);
    int handle(int event);
	void resize(int x, int y, int w, int h);

	/* internal crap */
	void displayConversion(void);
	
	/* API */
	void setDisplayOpts(int opts);
	void setDndEnabled(bool enab);
	int getImageDims(int *width, int *height);
};
