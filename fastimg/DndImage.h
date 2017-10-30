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
#define DISPLAY_OPT_CENTER 128

#define IMG_FILE_TYPE_INVALID 0
#define IMG_FILE_TYPE_JPG 1
#define IMG_FILE_TYPE_PNG 2

#define CB_REASON_FILE_OPENED 0

typedef void (*imageCallback)(int);

class DndImage : public Fl_Widget
{
    public:
	/* info on the currently open file */
	string imageFilePath;
	vector<uint8_t> imageFileBuf;
	int imageFileType = IMG_FILE_TYPE_INVALID;

	int displayLocX=0, displayLocY=0;
	imageCallback callback = NULL;

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
	void setInterpolation(int interp);
	void setDndEnabled(bool enab);
	string getImagePath(void);
	int getImageDims(int *width, int *height);
	int loadImage(const char *filePath);
	int writePng(char *filePath);
	void setCallback(imageCallback cb);
};
