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
