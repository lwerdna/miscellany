/* c */
#include <stdlib.h>
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
#include <FL/Fl_Image_Surface.h>

/* us */
#include "DndImage.h"

DndImage::DndImage(int x, int y, int w, int h, const char *label):
    Fl_Widget(x, y, w, h, label)
{
    printf("DndImage constructor\n");
}

/* converts
	FROM: the original raw image (imgBuf)
      TO: the fltk drawable image (imgFl)
   USING: libgd (imgGd) and the size and interpolation settings
*/
void DndImage::displayConversion(void)
{
	gdImagePtr imgGd = NULL;
	gdImageStruct *gdStruct;
	uint8_t *ptr = NULL;
	int len;	
	int oldWidth, oldHeight;
	int newWidth, newHeight;

	/* create the gd image */
	switch(imageFileType) {
		case IMG_FILE_TYPE_PNG:
			imgGd = gdImageCreateFromPngPtr(imgBuf.size(), &imgBuf[0]);
			break;
		case IMG_FILE_TYPE_JPG:
			imgGd = gdImageCreateFromJpegPtr(imgBuf.size(), &imgBuf[0]);
			break;
		default:
			printf("ERROR: unknown image file type\n");
			goto cleanup;
	}

	if(!imgGd) {
		printf("ERROR: creating gd image\n");
		goto cleanup;
	}

	/* decide on resize dimensions */	
	gdStruct = (gdImageStruct *)imgGd;

	oldWidth = newWidth = gdStruct->sx;
	oldHeight = newHeight = gdStruct->sy;

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

	//printf("resize img (%d,%d) -> (%d,%d)\n", oldWidth, oldHeight,
	//  newWidth, newHeight);

	/* actually do the resize, if needed */
	if(newWidth != oldWidth || newHeight != oldHeight) {
		gdImageSetInterpolationMethod(imgGd, (gdInterpolationMethod)interpMethod);
		gdImagePtr tmp = gdImageScale(imgGd, newWidth, newHeight);
		gdImageDestroy(imgGd);
		imgGd = tmp;
	}

	/* decide on display location */
	displayLocX = displayLocY = 0;
	if(displayOpts & DISPLAY_OPT_CENTER) {
		
		int centerPicW = newWidth / 2;
		int centerPicH = newHeight / 2;
		int centerAreaW = w()/2;
		int centerAreaH = h()/2;
		displayLocX = centerAreaW - centerPicW;
		displayLocY = centerAreaH - centerPicH;
	}

	/* wrap that buffer in an FLTK image object */
	if(imgFl)
		delete imgFl;

	switch(imageFileType) {
		case IMG_FILE_TYPE_PNG:
			ptr = (uint8_t *)gdImagePngPtr(imgGd, &len);
			imgFl = new Fl_PNG_Image("whatever", ptr, len);
			break;
		case IMG_FILE_TYPE_JPG:
			ptr = (uint8_t *)gdImageJpegPtr(imgGd, &len, 100 /* quality */);
			imgFl = new Fl_JPEG_Image("whatever", ptr);
			break;
		default:
			printf("ERROR: unknown image file type (%d)\n", imageFileType);
			goto cleanup;
	}

	cleanup:
	if(imgGd) gdImageDestroy(imgGd);
	if(ptr) gdFree(ptr);
	while(0);
}

void DndImage::setInterpolation(int interp)
{
	printf("%s(%d)\n", __func__, interp);
	interpMethod = interp;
	displayConversion();
	redraw();
}

void DndImage::draw(void)
{
	//printf("%s()\n", __func__);

	/* draw to the "current drawing surface"
	  see Fl_Surface_Device::surface() and set_current()

	  coordinates to drawing functions are *window* based, so get coordinates
	  of our widget relative to the window */

	int x_ = x();
	int y_ = y();
	int w_ = w();
	int h_ = h();

	fl_push_clip(x_, y_, w_, h_);

	fl_rectf(x_, y_, w_, h_, FL_GREEN);

	if(!imgFl)
		goto cleanup;

	imgFl->draw(x_ + displayLocX, y_+displayLocY);

	cleanup:
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
            //printf("event text: %s\n", Fl::event_text());

			/* parse file name */
			const char *fpath = Fl::event_text();
			loadImage(fpath);

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

int DndImage::inferFileType(const char *fpath)
{
	int rc = -1;
	int len = strlen(fpath);

	/* check file type */
	if(0 == strcasecmp(fpath + len - 4, ".jpg"))
		rc = IMG_FILE_TYPE_JPG;
	else if(0 == strcasecmp(fpath + len - 4, ".jpeg"))
		rc = IMG_FILE_TYPE_JPG;
	else if(0 == strcasecmp(fpath + len - 4, ".png"))
		rc = IMG_FILE_TYPE_PNG;
	else
		printf("ERROR: unrecognized file type: %s\n", fpath);

	return rc;
}

int DndImage::loadImage(const char *fpath)
{
	printf("%s(%s)\n", __func__, fpath);

	int rc = -1;
	int len = strlen(fpath);
	vector<uint8_t> fbuf;
	string errStr;

	/* check file type */
	int ftype = inferFileType(fpath);
	if(ftype < 0)
		{ printf("ERROR: inferFileType()\n"); goto cleanup; }

	if(filesys_read(fpath, "rb", fbuf, errStr)) {
		printf("ERROR: %s\n", errStr.c_str());
		goto cleanup;
	}

	/* set globals */
	imageFileType = ftype;
	imgBuf = fbuf;
	imageFilePath = fpath;
	
	/* draw it */	
	displayConversion();	
	redraw();

	/* if callback registered, call it */
	if(callback)
		callback(CB_REASON_FILE_OPENED);

	rc = 0;
	cleanup:
	return rc;
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
	bool recalc = (displayOpts != opts);
	displayOpts = opts;
	if(recalc) displayConversion();
}

/* gets the image dimensions
	by temporarily loading the raw image (imgBuf) into libgd (imgGd) */
int DndImage::getImageDims(int *width, int *height)
{
	int rc = -1;
	
	gdImagePtr imgGd = NULL;
	gdImageStruct *gdStruct;

	if(imgBuf.size() == 0)
		goto cleanup;

	/* create the gd image */
	switch(imageFileType) {
		case IMG_FILE_TYPE_PNG:
			imgGd = gdImageCreateFromPngPtr(imgBuf.size(), &imgBuf[0]);
			break;
		case IMG_FILE_TYPE_JPG:
			imgGd = gdImageCreateFromJpegPtr(imgBuf.size(), &imgBuf[0]);
			break;
		default:
			printf("ERROR: unknown image file type (%d)\n", imageFileType);
			goto cleanup;
	}

	if(!imgGd) {
		printf("ERROR: creating gd image\n");
		goto cleanup;
	}

	gdStruct = (gdImageStruct *)imgGd;
	*width = gdStruct->sx;
	*height = gdStruct->sy;

	rc = 0;
	cleanup:
	if(imgGd) gdImageDestroy(imgGd);
	return rc;
}

/* write to a file, but calling draw() on a temporary surface */
int DndImage::writeFile(const char *fpath)
{
	int rc = -1;
	Fl_RGB_Image *imageRGB = NULL;
	gdImagePtr imgGd = NULL;
	int ftype;
	FILE *fp = NULL;
	uint8_t *rgb;
	int w_ = w();
	int h_ = h();
	int oldX, oldY;

	Fl_Surface_Device *surfTmp = NULL;
	Fl_Image_Surface *surfImg = NULL;

	/* check extension */
	ftype = inferFileType(fpath);
	if(ftype < 0)
		{ printf("ERROR: inferFileType()\n"); goto cleanup; }

	/* create a temporary fake surface, swapping it in */
	surfImg = new Fl_Image_Surface(w_, h_);
	surfTmp = Fl_Surface_Device::surface();
	surfImg->set_current();

	/* draw on the fake surface */
	oldX = x();
	oldY = y();
	x(0);
	y(0);	
	draw();
	x(oldX);
	y(oldY);

	/* replace the original surface */
	surfTmp->set_current();

	/* access RGB data by converting to an Fl_RGB_Image */
	imageRGB = surfImg->image();

	if(imageRGB->count() != 1) {
		printf("ERROR: expected data count == 1\n");
		goto cleanup;
	}

	if(imageRGB->d() != 3) {
		printf("ERROR: expected image depth == 3\n");
		goto cleanup;
	}

	if(imageRGB->ld() != 0) {
		printf("ERROR: expected image line data size == 0\n");
		goto cleanup;
	}

	rgb = (uint8_t *) imageRGB->data()[0];

	/* create a gd image */
	imgGd = gdImageCreateTrueColor(w_, h_);
	for(int x=0; x<w_; ++x) {
		for(int y=0; y<h_; ++y) {
			int pixIdx = 3*(w_*y + x);
			uint32_t color = (rgb[pixIdx+0] << 16) | (rgb[pixIdx+1] << 8) | rgb[pixIdx+2];
			gdImageSetPixel(imgGd, x, y, color);
		}
	}

	/* write gd image to file */
	fp = fopen(fpath, "wb");
	if(ftype == IMG_FILE_TYPE_PNG)
		gdImagePng(imgGd, fp);
	else if(ftype == IMG_FILE_TYPE_JPG)
		gdImageJpeg(imgGd, fp, 100);
	fclose(fp);

	/* done */
	rc = 0;
	cleanup:
	//if(imageRGB) 
	//	Fl_Shared_Image::release();
	if(surfImg)
		delete surfImg;
	if(imgGd)
		gdImageDestroy(imgGd);
	return rc;
}
	
string DndImage::getImagePath(void)
{
	return imageFilePath;
}

void DndImage::setCallback(imageCallback cb)
{
	callback = cb;	
}
