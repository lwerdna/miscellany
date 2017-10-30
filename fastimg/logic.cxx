#include <stdio.h>

#include "Gui.h"

/* libgd */
#include <gd.h>

Gui *gui;

void cbDndImage(int reason)
{
	switch(reason)
	{
		case CB_REASON_FILE_OPENED:
		{
			string fpath = gui->resizeImg->getImagePath();
			gui->fpathIn->value(fpath.c_str());
			if(0 == strcmp(gui->fpathOut->value(), "")) {
				gui->fpathOut->value(fpath.c_str());
			}
			break;
		}
	}
}

void cbInterp(Fl_Choice *menu, void *userData)
{
	const Fl_Menu_Item *item = menu->mvalue();

	printf("selected %s\n", item->label());

	/* user_data has the GD define */
	uintptr_t tmp = (uintptr_t)item->user_data();
	int method = (int)tmp;

	gui->resizeImg->setInterpolation(method);
}

void onGuiInit(Gui *gui_, int ac, char **av)
{
	gui = gui_;
	printf("%s()\n", __func__);
	gui->fpathIn->value("");
	gui->fpathOut->value("");
	gui->resizeImg->setCallback(cbDndImage);
	gui->resizeImg->setInterpolation(GD_QUADRATIC);

	/* load interpolation methods menu */
	static Fl_Menu_Item menuItems[] = {
	    { "Quadratic",        0, 0, (void *)GD_QUADRATIC},
	    { "Bell",            0, 0, (void *)GD_BELL},
	    { "Bessel",        0, 0, (void *)GD_BESSEL},
	    { "Bilinear Fixed",        0, 0, (void *)GD_BILINEAR_FIXED},
	    { "Bicubic",        0, 0, (void *)GD_BICUBIC},
	    { "Bicubic Fixed",        0, 0, (void *)GD_BICUBIC_FIXED},
	    { "Blackman",        0, 0, (void *)GD_BLACKMAN},
	    { "Box",        0, 0, (void *)GD_BOX},
	    { "BSpline",        0, 0, (void *)GD_BSPLINE},
	    { "Catmullrom",        0, 0, (void *)GD_CATMULLROM},
	    { "Gaussian",        0, 0, (void *)GD_GAUSSIAN},
	    { "Generalized Cubic",        0, 0, (void *)GD_GENERALIZED_CUBIC},
	    { "Hermite",        0, 0, (void *)GD_HERMITE},
	    { "Hamming",        0, 0, (void *)GD_HAMMING},
	    { "Hannig",        0, 0, (void *)GD_HANNING},
	    { "Mitchell",        0, 0, (void *)GD_MITCHELL},
	    { "Nearest Neighbor",        0, 0, (void *)GD_NEAREST_NEIGHBOUR},
	    { "Power",        0, 0, (void *)GD_POWER},
	    { "Sinc",        0, 0, (void *)GD_SINC},
	    { "Triangle",        0, 0, (void *)GD_TRIANGLE},
	    { "4px Weighted Bilinear",        0, 0, (void *)GD_WEIGHTED4},
	    { "Bilinear",        0, 0, (void *)GD_LINEAR},
	    { 0 }
	};
	gui->interpMethods->copy(menuItems);
	gui->interpMethods->callback((Fl_Callback *)cbInterp);

	/* any command line args? */
	if(ac > 1)
		gui->resizeImg->loadImage(av[1]);
}

void onGuiExit(int retFromFlRun)
{
	printf("%s()\n", __func__);
}

void onResizeWidthChange(int width)
{
	printf("%s()\n", __func__);
	if(width < 8) return;
	DndImage *dimg = gui->resizeImg;
	dimg->size(width, dimg->h());
	gui->tabs->redraw();
}

void onResizeHeightChange(int height)
{
	printf("%s()\n", __func__);
	if(height < 8) return;
	DndImage *dimg = gui->resizeImg;
	dimg->size(dimg->w(), height);
	gui->tabs->redraw();
}

void onSetOriginalDims()
{
	printf("%s()\n", __func__);

	/* ask image display what the file originally specified */
	int width, height;
	if(gui->resizeImg->getImageDims(&width, &height)) {
		printf("ERROR: getImageDims()\n");
		return;
	}

	/* set our width/height fields */
	gui->resizeWidth->value(width);
	gui->resizeHeight->value(height);

	/* resize the image display widget */
	gui->resizeImg->setDisplayOpts(DISPLAY_OPT_TOP_LEFT);
	gui->resizeImg->size(width, height);

	/* redraw everything */
	gui->tabs->redraw();

	cleanup:
	while(0);
}

void onBtnCenter()
{
	//gui->btnCenter->value(0);
	gui->btnCorner->value(0);
	gui->btnStretchNS->value(0);
	gui->btnStretchEW->value(0);
	gui->btnFill->value(0);
	gui->btnClip->value(0);
	gui->resizeImg->setDisplayOpts(DISPLAY_OPT_CENTER);
	gui->tabs->redraw();
}

void onBtnCorner()
{
	gui->btnCenter->value(0);
	//gui->btnCorner->value(0);
	gui->btnStretchNS->value(0);
	gui->btnStretchEW->value(0);
	gui->btnFill->value(0);
	gui->btnClip->value(0);
	gui->resizeImg->setDisplayOpts(DISPLAY_OPT_TOP_LEFT);
	gui->tabs->redraw();
}

void onBtnStretchNS()
{
	gui->btnCenter->value(0);
	gui->btnCorner->value(0);
	//gui->btnStretchNS->value(0);
	gui->btnStretchEW->value(0);
	gui->btnFill->value(0);
	gui->btnClip->value(0);
	gui->resizeImg->setDisplayOpts(DISPLAY_OPT_EXPAND_HEIGHT);
	gui->resizeImg->redraw();
	gui->tabs->redraw();
}

void onBtnStretchEW()
{
	gui->btnCenter->value(0);
	gui->btnCorner->value(0);
	gui->btnStretchNS->value(0);
	//gui->btnStretchEW->value(0);
	gui->btnFill->value(0);
	gui->btnClip->value(0);
	gui->resizeImg->setDisplayOpts(DISPLAY_OPT_EXPAND_WIDTH);
	gui->tabs->redraw();
}

void onBtnFill()
{
	gui->btnCenter->value(0);
	gui->btnCorner->value(0);
	gui->btnStretchNS->value(0);
	gui->btnStretchEW->value(0);
	//gui->btnFill->value(0);
	gui->btnClip->value(0);
	gui->resizeImg->setDisplayOpts(DISPLAY_OPT_MATCH_WIDTH | DISPLAY_OPT_MATCH_HEIGHT);
	gui->tabs->redraw();
}

void onBtnClip()
{
	gui->btnCenter->value(0);
	gui->btnCorner->value(0);
	gui->btnStretchNS->value(0);
	gui->btnStretchEW->value(0);
	gui->btnFill->value(0);
	//gui->btnClip->value(0);
	gui->resizeImg->setDisplayOpts(DISPLAY_OPT_TOP_LEFT);
	gui->tabs->redraw();
}

void onBtnSave()
{
	printf("%s()\n", __func__);

	const char *fpath = gui->fpathOut->value();
	gui->resizeImg->writeFile(fpath);
}

void setAbsoluteResolution(int w, int h)
{
	/* set our width/height fields */
	gui->resizeWidth->value(w);
	gui->resizeHeight->value(h);

	/* resize the image display widget */
	gui->resizeImg->size(w, h);
	gui->resizeImg->setDisplayOpts(DISPLAY_OPT_MATCH_WIDTH | DISPLAY_OPT_MATCH_HEIGHT);

	/* redraw parent */
	gui->tabs->redraw();
}


