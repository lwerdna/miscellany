#include <stdio.h>
#include <stdlib.h>

#include <string>
using namespace std;

#include <re2/re2.h>
#include <re2/stringpiece.h>
using namespace re2;

#include "Gui.h"

Gui *gui;
Fl_Text_Buffer *bodyBuf = NULL;
Fl_Text_Buffer *styleBuf = NULL;

#define TEXT_SIZE 14
#define N_STYLES 2
static
Fl_Text_Editor::Style_Table_Entry styletable[N_STYLES] = {
    { FL_BLACK,      FL_HELVETICA,         TEXT_SIZE }, // A - Plain
    { FL_RED,        FL_HELVETICA,         TEXT_SIZE } // B - Line commenTEXT_SIZE
};

void onRegexChange()
{
	//printf("%s()\n", __func__);

	// reset highlight data
	string tmp(bodyBuf->length(), 'A');
	styleBuf->text(tmp.c_str());

	// create string around the body
	char *body_ = bodyBuf->text();
	string body(body_);
	free(body_);

	// find all occurances
	string regex = string("(") + gui->regex->value() + string(")");
	StringPiece place(body);
	while(1) {
		string m0;
		if(!RE2::FindAndConsume(&place, regex.c_str(), &m0))
			break;

		if(m0.size() == 0) break;	

		// set highlight data for each
		string::size_type matchIdx = 0;
		string tmp(m0.length(), 'B'); 

		while ((matchIdx = body.find(m0, matchIdx)) != string::npos) {
			styleBuf->replace(matchIdx, matchIdx+m0.length(), tmp.c_str());
		    matchIdx += m0.length();
			//printf("bodyBuf: %s\n", bodyBuf->text());
			//printf("styleBuf: %s\n", styleBuf->text());
		}
		//printf("matched on -%s-\n", m0.c_str());
	}

	gui->body->redraw();
}

void onGuiInitialized(Gui *gui_)
{
	//printf("%s()\n", __func__);
	gui = gui_;

	/* set the text body to start text */
	bodyBuf = new Fl_Text_Buffer();
	bodyBuf->text("Lorem Ipsum 0xDEADBEEF 0xCA4eBebeeee!");

	/* style buf */
	styleBuf = new Fl_Text_Buffer(bodyBuf->length());
	string tmp(bodyBuf->length(), 'A');
	styleBuf->text(tmp.c_str());

	/* body input */
	gui->body->textsize(TEXT_SIZE);
	gui->body->wrap_mode(Fl_Text_Display::WRAP_AT_BOUNDS, 0);
	gui->body->buffer(bodyBuf);
	gui->body->highlight_data(styleBuf, styletable, N_STYLES, 'A', NULL, NULL); 
	
	/* regex input */
	gui->regex->when(gui->regex->when() | FL_WHEN_CHANGED);
	gui->regex->value("[0-9a-fA-F]{2,8}");
	onRegexChange();

}

void onGuiExit(int rc)
{
	//printf("%s()\n", __func__);

	if(bodyBuf)
		delete bodyBuf;
}
