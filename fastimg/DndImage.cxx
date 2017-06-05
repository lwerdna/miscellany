/* c */
#include <string.h>
#include <inttypes.h>

/* c++ */
#include <string>
#include <sstream>
#include <vector>
using namespace std;

/* autils */
#include <autils/filesys.hpp>

/* libgd */
#include <gd.h>

/* fltk */
#include <FL/Fl.H>
#include <FL/Fl_Widget.H>

/* us */
#include "DndImage.h"

DndImage::DndImage(int x, int y, int w, int h, const char *label):
    Fl_Widget(x, y, w, h, label)
{
    printf("DndImage constructor\n");
}

void DndImage::displayConversion(void)
{
	gdImagePtr gip = NULL;
	gdImageStruct *gdStruct;
	uint8_t *imgBuf = NULL;
	int imgBufLen;	
	int oldWidth, oldHeight;
	int newWidth, newHeight;

	/* create the gd image */
	switch(imgFileType) {
		case IMG_FILE_TYPE_PNG:
			gip = gdImageCreateFromPngPtr(imgFileBuf.size(), &imgFileBuf[0]);
			break;
		default:
			printf("ERROR: unknown image file type\n");
			goto cleanup;
	}

	if(!gip) {
		printf("ERROR: creating gd image\n");
		goto cleanup;
	}

	/* decide on resize dimensions */	
	gdStruct = (gdImageStruct *)gip;

	oldWidth = gdStruct->sx;
	oldHeight = gdStruct->sy;

	if(displayOpts & DISPLAY_OPT_TOP_LEFT) {
		newWidth = oldWidth;
		newHeight = oldHeight;
	}
	if(displayOpts & DISPLAY_OPT_EXPAND_WIDTH) {
		if(oldWidth < w())
			newWidth = w();
	}
	if(displayOpts & DISPLAY_OPT_EXPAND_HEIGHT) {
		if(oldHeight < h())
			newHeight = h();
	}
	if(displayOpts & DISPLAY_OPT_SHRINK_WIDTH) {
		if(oldWidth > w())
			newWidth = w();
	}
	if(displayOpts & DISPLAY_OPT_SHRINK_HEIGHT) {
		if(oldHeight > h())
			newHeight = h();
	}
	if(displayOpts & DISPLAY_OPT_MATCH_WIDTH) {
		newWidth = w();
	}
	if(displayOpts & DISPLAY_OPT_MATCH_HEIGHT) {
		newHeight = h();
	}

	printf("resize img (%d,%d) -> (%d,%d)\n", oldWidth, oldHeight,
	  newWidth, newHeight);

	/* actually do the resize, if needed */
	if(newWidth != oldWidth || newHeight != oldHeight) {
		gdImageSetInterpolationMethod(gip, GD_BICUBIC_FIXED);
		gdImagePtr tmp = gdImageScale(gip, newWidth, newHeight);
		gdImageDestroy(gip);
		gip = tmp;
	}

	/* allocate a buffer that has the image data */
	imgBuf = (uint8_t *)gdImagePngPtr(gip, &imgBufLen);

	/* wrap that buffer in an FLTK image object */
	if(myImage)
		delete myImage;

	switch(imgFileType) {
		case IMG_FILE_TYPE_PNG:
			myImage = new Fl_PNG_Image("whatever", imgBuf, imgBufLen);
			break;
		default:
			printf("ERROR: unknown image file type\n");
			goto cleanup;
	}

	cleanup:
	if(gip) gdImageDestroy(gip);
	if(imgBuf) gdFree(imgBuf);
	while(0);
}

void DndImage::draw(void)
{
	printf("%s()\n", __func__);

	/* draw to the "current drawing surface"
		see Fl_Surface_Device::surface() and set_current() */

//
	/* coordinates to drawing functions are *window* based, so get coordinates
		of our widget relative to the window */
	int x_ = x();
	int y_ = y();
	int w_ = w();
	int h_ = h();

	fl_push_clip(x_, y_, w_, h_);

	printf("drawing a rectangle sized %d, %d\n", w_, h_);
	fl_rectf(x_, y_, w_, h_, FL_GREEN);

	if(!myImage) return;
	myImage->draw(x_, y_);

	fl_pop_clip();

	return;
}

int DndImage::handle(int event)
{
    int rc = 0; /* 0 if not used or understood, 1 if event was used and can be deleted */
    switch(event) {
        case FL_DND_ENTER:
            //printf("on FL_DND_ENTER\n");
            rc = 1;
            break;
        case FL_DND_DRAG:
            //printf("on FL_DND_DRAG\n");
            rc = 1;
            break;
        case FL_DND_RELEASE:
            //printf("on FL_DND_RELEASE\n");
            rc = 1;
            break;

        case FL_PASTE:
        {
            //printf("got paste event");
            printf("event text: %s\n", Fl::event_text());

			/* parse file name */
			const char *fname = Fl::event_text();
			int len = strlen(fname);
			int newImgFileType;
	
			if(0 == strcasecmp(fname + len - 4, ".jpg")) {
				printf("new jpg image!\n");
				newImgFileType = IMG_FILE_TYPE_JPG;
			}
			else if(0 == strcasecmp(fname + len - 4, ".jpeg")) {
				printf("new jpeg image!\n");
				newImgFileType = IMG_FILE_TYPE_JPG;
			}
			else if(0 == strcasecmp(fname + len - 4, ".png")) {
				printf("new png image!\n");
				newImgFileType = IMG_FILE_TYPE_PNG;
			}
			else {
				printf("ERROR: unrecognized file type: %s\n", fname);
				break;
			}
	
			string errStr;
			vector<uint8_t> newImgFileBuf;
			if(filesys_read(fname, "rb", newImgFileBuf, errStr)) {
				printf("ERROR: %s\n", errStr.c_str());
				break;
			}

			/* k, success, made it here */
			imgFileType = newImgFileType;
			imgFileBuf = newImgFileBuf;
				
			displayConversion();	
			redraw();

            //printf("event length: %d\n", Fl::event_length());

            // dragging a multiple file selection just concats the paths
            // separated by newline, so we have to split them here
//            const char *wtf = Fl::event_text();
//            std::stringstream ss(wtf);
//            std::string line;
//            while(std::getline(ss, line, '\n')) {
//                add(line.c_str());
//            }

            rc = 1;
            break;
        }

        default:
            while(0);
            //printf("got event id: %d\n", event);
    }

    if(rc) return rc;
    else return Fl_Widget::handle(event);
}

void DndImage::resize(int x, int y, int w, int h)
{
	printf("%s()\n", __func__);

	Fl_Widget::resize(x, y, w, h); 

	/* new size means we might have to scale the image */
	displayConversion();
}
	
void DndImage::setDisplayOpts(int opts)
{
	displayOpts = opts;
}

int DndImage::getImageDims(int *width, int *height)
{
	int rc = -1;
	
	gdImagePtr gip = NULL;
	gdImageStruct *gdStruct;

	if(imgFileBuf.size() == 0)
		goto cleanup;

	/* create the gd image */
	switch(imgFileType) {
		case IMG_FILE_TYPE_PNG:
			gip = gdImageCreateFromPngPtr(imgFileBuf.size(), &imgFileBuf[0]);
			break;
		default:
			printf("ERROR: unknown image file type\n");
			goto cleanup;
	}

	if(!gip) {
		printf("ERROR: creating gd image\n");
		goto cleanup;
	}

	gdStruct = (gdImageStruct *)gip;
	*width = gdStruct->sx;
	*height = gdStruct->sy;

	rc = 0;
	cleanup:
	return rc;
}

