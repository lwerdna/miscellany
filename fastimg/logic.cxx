#include <stdio.h>

#include "Gui.h"

void onGuiInit(Gui *gui)
{
	printf("%s()\n", __func__);
}

void onGuiExit(int retFromFlRun)
{
	printf("%s()\n", __func__);
}
