void onGuiInit(Gui *gui);
void onGuiExit(int retFromFlRun);

void onResizeWidthChange(int width);
void onResizeHeightChange(int height);

void setAbsoluteResolution(int w, int h);
void onSetOriginalDims();

void cbDndImage(int reason);

void onBtnCenter();
void onBtnCorner();
void onBtnStretchNS();
void onBtnStretchEW();
void onBtnFill();
void onBtnClip();
void onBtnSave();
