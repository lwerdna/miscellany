#include <string.h>

#include <string>
#include <sstream>

#include <FL/Fl.H>
#include <FL/Fl_Widget.H>

#include "DndImage.h"

DndImage::DndImage(int x, int y, int w, int h, const char *label):
    Fl_Widget(x, y, w, h, label)
{
    printf("DndImage constructor\n");
}

void DndImage::draw(void)
{
	/* draw to the "current drawing surface"
		see Fl_Surface_Device::surface() and set_current() */

//	if(!myImage) return;
//
	/* coordinates to drawing functions are *window* based, so get coordinates
		of our widget relative to the window */
	int x_ = x();
	int y_ = y();
	int w_ = w();
	int h_ = h();

	fl_rectf(x_, y_, w_, h_, FL_GREEN);

	printf("darwing!\n");
	if(myImage) {
		printf("this bitch!\n");	
		myImage->draw(x_, y_);
	}

//	myImage->draw(x_, y_);
//
//	if(ptrPosX >= 0) {
//		fl_color(0x00FF0000);
//		fl_line(x_ + ptrPosX, 0, x_ + ptrPosX, h()); // vert
//		fl_line(0, y_ + ptrPosY, w_, y_ + ptrPosY); // horiz
//	}
//
//	if(isDrag) {
//		fl_color(0xFF000000);
//		fl_line(x_ + dragStartX, y_ + dragStartY, x_ + ptrPosX, y_ + ptrPosY);
//	}
//
////	if(ptrPosX >= 0) {
////		fl_color(0x00FF0000);
////		fl_line(x_ + ptrPosX, 0, x_ + ptrPosX, h()); // vert
////		fl_line(0, y_ + ptrPosY, w_, y_ + ptrPosY); // horiz
////	}
//
//	char buf[64];
//	sprintf(buf, "(%d, %d)", ptrPosX*4, ptrPosY*4);
//
//	/* if ptr in NW quadrant, show text in SE quadrant */
//	int txtPosX = ptrPosX + 5;
//	int txtPosY = ptrPosY + 15;
//
//	if(ptrPosX > (1440/8))
//		txtPosX -= 90;
//	if(ptrPosY > (2560/8))
//		txtPosY -= 20;
//
//	fl_draw(buf, txtPosX, txtPosY);

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

			Fl_Image *newImage = NULL;
			const char *fname = Fl::event_text();
			int len = strlen(fname);
			
			if(0 == strcasecmp(fname + len - 4, ".gif")) {
				printf("new gif image!\n");
				newImage = new Fl_GIF_Image(fname);
			}
			else if(0 == strcasecmp(fname + len - 4, ".jpg")) {
				printf("new jpg image!\n");
				newImage = new Fl_JPEG_Image(fname);
			}
			else if(0 == strcasecmp(fname + len - 4, ".jpeg")) {
				printf("new jpeg image!\n");
				newImage = new Fl_JPEG_Image(fname);
			}
			else if(0 == strcasecmp(fname + len - 4, ".png")) {
				printf("new png image!\n");
				newImage = new Fl_PNG_Image(fname);
			}
			else if(0 == strcasecmp(fname + len - 4, ".pnm")) {
				printf("new pnm image!\n");
				newImage = new Fl_PNM_Image(fname);
			}
			else if(0 == strcasecmp(fname + len - 4, ".xbm")) {
				printf("new xbm image!\n");
				newImage = new Fl_XBM_Image(fname);
			}
			else if(0 == strcasecmp(fname + len - 4, ".xpm")) {
				printf("new xpm image!\n");
				newImage = new Fl_XPM_Image(fname);
			}
			else {
				printf("ERROR: unrecognized file type: %s\n", fname);
				break;
			}
		
			if(newImage) {
				if(myImage) {
					delete myImage;
				}
				myImage = newImage;
				redraw();
			}

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
