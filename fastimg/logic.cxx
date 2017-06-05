#include <stdio.h>

#include "Gui.h"

Gui *gui;

void onGuiInit(Gui *gui_)
{
	gui = gui_;
	printf("%s()\n", __func__);
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


