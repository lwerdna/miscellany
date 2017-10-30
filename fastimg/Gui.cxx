// generated by Fast Light User Interface Designer (fluid) version 1.0304

#include "Gui.h"
#include "logic.h"

void Gui::cb_resizeWidth_i(Fl_Value_Input*, void*) {
  onResizeWidthChange(resizeWidth->value());
}
void Gui::cb_resizeWidth(Fl_Value_Input* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_resizeWidth_i(o,v);
}

void Gui::cb_resizeHeight_i(Fl_Value_Input*, void*) {
  onResizeHeightChange(resizeHeight->value());
}
void Gui::cb_resizeHeight(Fl_Value_Input* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_resizeHeight_i(o,v);
}

void Gui::cb_resizeBtnSave_i(Fl_Button*, void*) {
  onBtnSave();
}
void Gui::cb_resizeBtnSave(Fl_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_resizeBtnSave_i(o,v);
}

void Gui::cb_Original_i(Fl_Button*, void*) {
  onSetOriginalDims();
}
void Gui::cb_Original(Fl_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_Original_i(o,v);
}

void Gui::cb_btnCenter_i(Fl_Round_Button*, void*) {
  onBtnCenter();
}
void Gui::cb_btnCenter(Fl_Round_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_btnCenter_i(o,v);
}

void Gui::cb_btnCorner_i(Fl_Round_Button*, void*) {
  onBtnCorner();
}
void Gui::cb_btnCorner(Fl_Round_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_btnCorner_i(o,v);
}

void Gui::cb_btnStretchEW_i(Fl_Round_Button*, void*) {
  onBtnStretchEW();
}
void Gui::cb_btnStretchEW(Fl_Round_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_btnStretchEW_i(o,v);
}

void Gui::cb_btnStretchNS_i(Fl_Round_Button*, void*) {
  onBtnStretchNS();
}
void Gui::cb_btnStretchNS(Fl_Round_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_btnStretchNS_i(o,v);
}

void Gui::cb_btnFill_i(Fl_Round_Button*, void*) {
  onBtnFill();
}
void Gui::cb_btnFill(Fl_Round_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_btnFill_i(o,v);
}

void Gui::cb_btnClip_i(Fl_Round_Button*, void*) {
  onBtnClip();
}
void Gui::cb_btnClip(Fl_Round_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_btnClip_i(o,v);
}

void Gui::cb_1024x768_i(Fl_Button*, void*) {
  setAbsoluteResolution(1024,768);
}
void Gui::cb_1024x768(Fl_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_1024x768_i(o,v);
}

void Gui::cb_640x480_i(Fl_Button*, void*) {
  setAbsoluteResolution(640,480);
}
void Gui::cb_640x480(Fl_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_640x480_i(o,v);
}

void Gui::cb_640x360_i(Fl_Button*, void*) {
  setAbsoluteResolution(640,360);
}
void Gui::cb_640x360(Fl_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_640x360_i(o,v);
}

void Gui::cb_960x540_i(Fl_Button*, void*) {
  setAbsoluteResolution(960,540);
}
void Gui::cb_960x540(Fl_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_960x540_i(o,v);
}

void Gui::cb_1920x1080_i(Fl_Button*, void*) {
  setAbsoluteResolution(1920,1080);
}
void Gui::cb_1920x1080(Fl_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_1920x1080_i(o,v);
}

void Gui::cb_320x180_i(Fl_Button*, void*) {
  setAbsoluteResolution(320,180);
}
void Gui::cb_320x180(Fl_Button* o, void* v) {
  ((Gui*)(o->parent()->parent()->parent()->user_data()))->cb_320x180_i(o,v);
}

Fl_Double_Window* Gui::make_window() {
  Fl_Double_Window* w;
  { Fl_Double_Window* o = new Fl_Double_Window(1044, 908, "fastimg");
    w = o; if (w) {/* empty */}
    o->user_data((void*)(this));
    { tabs = new Fl_Tabs(-4, 0, 1061, 896);
      { tabResize = new Fl_Group(-4, 20, 1060, 876, "Resize");
        { resizeWidth = new Fl_Value_Input(47, 24, 41, 20, "width:");
          resizeWidth->callback((Fl_Callback*)cb_resizeWidth);
          resizeWidth->value(1024);
        } // Fl_Value_Input* resizeWidth
        { resizeHeight = new Fl_Value_Input(138, 24, 41, 20, "height:");
          resizeHeight->callback((Fl_Callback*)cb_resizeHeight);
          resizeHeight->value(768);
        } // Fl_Value_Input* resizeHeight
        { resizeBtnSave = new Fl_Button(635, 73, 63, 20, "Save");
          resizeBtnSave->callback((Fl_Callback*)cb_resizeBtnSave);
        } // Fl_Button* resizeBtnSave
        { Fl_Button* o = new Fl_Button(184, 27, 108, 20, "Original Dims");
          o->callback((Fl_Callback*)cb_Original);
        } // Fl_Button* o
        { btnCenter = new Fl_Round_Button(350, 24, 63, 15, "center");
          btnCenter->down_box(FL_ROUND_DOWN_BOX);
          btnCenter->callback((Fl_Callback*)cb_btnCenter);
        } // Fl_Round_Button* btnCenter
        { btnCorner = new Fl_Round_Button(350, 38, 63, 15, "corner");
          btnCorner->down_box(FL_ROUND_DOWN_BOX);
          btnCorner->callback((Fl_Callback*)cb_btnCorner);
        } // Fl_Round_Button* btnCorner
        { // 			
          btnStretchEW = new Fl_Round_Button(410, 38, 63, 15, "stretch EW");
          btnStretchEW->down_box(FL_ROUND_DOWN_BOX);
          btnStretchEW->callback((Fl_Callback*)cb_btnStretchEW);
        } // Fl_Round_Button* btnStretchEW
        { btnStretchNS = new Fl_Round_Button(410, 24, 63, 15, "stretch NS");
          btnStretchNS->down_box(FL_ROUND_DOWN_BOX);
          btnStretchNS->callback((Fl_Callback*)cb_btnStretchNS);
        } // Fl_Round_Button* btnStretchNS
        { btnFill = new Fl_Round_Button(502, 24, 63, 15, "fill");
          btnFill->down_box(FL_ROUND_DOWN_BOX);
          btnFill->callback((Fl_Callback*)cb_btnFill);
        } // Fl_Round_Button* btnFill
        { btnClip = new Fl_Round_Button(502, 38, 63, 15, "clip");
          btnClip->down_box(FL_ROUND_DOWN_BOX);
          btnClip->callback((Fl_Callback*)cb_btnClip);
        } // Fl_Round_Button* btnClip
        { Fl_Button* o = new Fl_Button(3, 47, 92, 20, "1024x768 4:3");
          o->callback((Fl_Callback*)cb_1024x768);
        } // Fl_Button* o
        { Fl_Button* o = new Fl_Button(95, 47, 90, 20, "640x480 4:3");
          o->callback((Fl_Callback*)cb_640x480);
        } // Fl_Button* o
        { Fl_Button* o = new Fl_Button(95, 67, 90, 20, "640x360 16:9");
          o->callback((Fl_Callback*)cb_640x360);
        } // Fl_Button* o
        { Fl_Button* o = new Fl_Button(2, 67, 93, 20, "960x540 16:9");
          o->callback((Fl_Callback*)cb_960x540);
        } // Fl_Button* o
        { Fl_Button* o = new Fl_Button(185, 67, 107, 20, "1920x1080 16:9");
          o->callback((Fl_Callback*)cb_1920x1080);
        } // Fl_Button* o
        { Fl_Button* o = new Fl_Button(185, 47, 107, 20, "320x180 16:9");
          o->callback((Fl_Callback*)cb_320x180);
        } // Fl_Button* o
        { resizeImg = new DndImage(6, 88, 1024, 808);
          resizeImg->box(FL_NO_BOX);
          resizeImg->color(FL_BACKGROUND_COLOR);
          resizeImg->selection_color(FL_BACKGROUND_COLOR);
          resizeImg->labeltype(FL_NORMAL_LABEL);
          resizeImg->labelfont(0);
          resizeImg->labelsize(14);
          resizeImg->labelcolor(FL_FOREGROUND_COLOR);
          resizeImg->align(Fl_Align(FL_ALIGN_CENTER));
          resizeImg->when(FL_WHEN_RELEASE);
        } // DndImage* resizeImg
        { fpathOut = new Fl_Output(635, 47, 406, 24, "output:");
        } // Fl_Output* fpathOut
        { fpathIn = new Fl_Output(635, 22, 406, 22, "input:");
        } // Fl_Output* fpathIn
        tabResize->end();
      } // Fl_Group* tabResize
      { Fl_Group* o = new Fl_Group(0, 20, 1024, 800, "2x2");
        o->hide();
        o->end();
      } // Fl_Group* o
      { Fl_Group* o = new Fl_Group(0, 20, 1024, 800, "4x4");
        o->hide();
        o->end();
      } // Fl_Group* o
      tabs->end();
    } // Fl_Tabs* tabs
    o->end();
  } // Fl_Double_Window* o
  return w;
}

int main(int ac, char **av) {
  Gui gui;
  Fl_Double_Window *w = gui.make_window();
  onGuiInit(&gui, ac, av);
  w->end();
  w->show();
  int rc = Fl::run();
  onGuiExit(rc);
  return rc;
}
