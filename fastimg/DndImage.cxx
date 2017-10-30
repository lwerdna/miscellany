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

void DndImage::displayConversion(void)
{
	gdImagePtr gip = NULL;
	gdImageStruct *gdStruct;
	uint8_t *imgBuf = NULL;
	int imgBufLen;	
	int oldWidth, oldHeight;
	int newWidth, newHeight;

	/* create the gd image */
	switch(imageFileType) {
		case IMG_FILE_TYPE_PNG:
			gip = gdImageCreateFromPngPtr(imageFileBuf.size(), &imageFileBuf[0]);
			break;
		case IMG_FILE_TYPE_JPG:
			gip = gdImageCreateFromJpegPtr(imageFileBuf.size(), &imageFileBuf[0]);
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
		gdImageSetInterpolationMethod(gip, GD_BICUBIC_FIXED);
		gdImagePtr tmp = gdImageScale(gip, newWidth, newHeight);
		gdImageDestroy(gip);
		gip = tmp;
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
	if(myImage)
		delete myImage;

	switch(imageFileType) {
		case IMG_FILE_TYPE_PNG:
			imgBuf = (uint8_t *)gdImagePngPtr(gip, &imgBufLen);
			myImage = new Fl_PNG_Image("whatever", imgBuf, imgBufLen);
			break;
		case IMG_FILE_TYPE_JPG:
			imgBuf = (uint8_t *)gdImageJpegPtr(gip, &imgBufLen, 100);
			myImage = new Fl_JPEG_Image("whatever", imgBuf);
			break;
		default:
			printf("ERROR: unknown image file type (%d)\n", imageFileType);
			goto cleanup;
	}

	cleanup:
	if(gip) gdImageDestroy(gip);
	if(imgBuf) gdFree(imgBuf);
	while(0);
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

	if(!myImage) {
		goto cleanup;
	}

	myImage->draw(x_ + displayLocX, y_+displayLocY);

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

int DndImage::loadImage(const char *fpath)
{
	printf("%s(%s)\n", __func__, fpath);

	int rc = -1;
	int len = strlen(fpath);
	vector<uint8_t> fbuf;
	string errStr;

	/* check file type */
	int ftype;
	if(0 == strcasecmp(fpath + len - 4, ".jpg")) {
		printf("new jpg image!\n");
		ftype = IMG_FILE_TYPE_JPG;
	}
	else if(0 == strcasecmp(fpath + len - 4, ".jpeg")) {
		printf("new jpeg image!\n");
		ftype = IMG_FILE_TYPE_JPG;
	}
	else if(0 == strcasecmp(fpath + len - 4, ".png")) {
		printf("new png image!\n");
		ftype = IMG_FILE_TYPE_PNG;
	}
	else {
		printf("ERROR: unrecognized file type: %s\n", fpath);
		goto cleanup;
	}

	if(filesys_read(fpath, "rb", fbuf, errStr)) {
		printf("ERROR: %s\n", errStr.c_str());
		goto cleanup;
	}

	/* set globals */
	imageFileType = ftype;
	imageFileBuf = fbuf;
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

int DndImage::getImageDims(int *width, int *height)
{
	int rc = -1;
	
	gdImagePtr gip = NULL;
	gdImageStruct *gdStruct;

	if(imageFileBuf.size() == 0)
		goto cleanup;

	/* create the gd image */
	switch(imageFileType) {
		case IMG_FILE_TYPE_PNG:
			gip = gdImageCreateFromPngPtr(imageFileBuf.size(), &imageFileBuf[0]);
			break;
		case IMG_FILE_TYPE_JPG:
			gip = gdImageCreateFromJpegPtr(imageFileBuf.size(), &imageFileBuf[0]);
			break;
		default:
			printf("ERROR: unknown image file type (%d)\n", imageFileType);
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

int DndImage::writePng(char *filePath)
{
	int rc = -1;
	Fl_Surface_Device *surfTmp = NULL;
	Fl_RGB_Image *imageRGB = NULL;
	gdImagePtr im = NULL;
	FILE *fp = NULL;
	uint8_t *rgb;
	int w_ = w();
	int h_ = h();

	/* create a temporary fake surface, swapping it in */
	Fl_Image_Surface surfImg(w_, h_);
	surfTmp = Fl_Surface_Device::surface();
	surfImg.set_current();
	
	/* draw on the fake surface */
	int oldX = x();
	int oldY = y();
	x(0);
	y(0);	
	draw();
	x(oldX);
	y(oldY);

	/* replace the original surface */
	surfTmp->set_current();

	/* access RGB data by converting to an Fl_RGB_Image */
	imageRGB = surfImg.image();

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
	im = gdImageCreateTrueColor(w_, h_);
	for(int x=0; x<w_; ++x) {
		for(int y=0; y<h_; ++y) {
			int pixIdx = 3*(w_*y + x);
			uint32_t color = (rgb[pixIdx+0] << 16) | (rgb[pixIdx+1] << 8) | rgb[pixIdx+2];
			gdImageSetPixel(im, x, y, color);
		}
	}

	/* write gd image to file */
	fp = fopen(filePath, "wb");
	gdImagePng(im, fp);
	fclose(fp);

	/* done */
	rc = 0;
	cleanup:
	//if(imageRGB) 
	//	Fl_Shared_Image::release();
	if(im)
		gdImageDestroy(im);
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
