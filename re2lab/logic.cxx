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

void onRegexChange()
{
	printf("%s()\n", __func__);

	char *body_ = bodyBuf->text();
	string body(body_);
	free(body_);

	const char *regex = gui->regex->value();

	StringPiece place(body);
	while(1) {
		StringPiece matchedOn;
		if(!RE2::FindAndConsume(&place, regex, &matchedOn))
			break;
	
		//printf("matched on -%s-\n", matchedOn.c_str());

		printf("place: %s\n", place.data());
	}

}

void onGuiInitialized(Gui *gui_)
{
	printf("%s()\n", __func__);

	gui = gui_;

	/* set the text body to start text */
	bodyBuf = new Fl_Text_Buffer();
	bodyBuf->text("Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book.");
	gui->body->textsize(12);
	gui->body->wrap_mode(Fl_Text_Display::WRAP_AT_BOUNDS, 0);
	gui->body->buffer(bodyBuf);

	gui->regex->when(gui->regex->when() | FL_WHEN_CHANGED);
	gui->regex->value("[^ ][psu]+m");
	onRegexChange();
}

void onGuiExit(int rc)
{
	printf("%s()\n", __func__);

	if(bodyBuf)
		delete bodyBuf;
}
