#!/usr/bin/env python

import os
import sys
import time
import random
from fltk import *

import kblib

# https://www.schemecolor.com/light-pastels.php
palette = [0xfbb3bd00, 0xfdcec600, 0xfcffe000, 0x97f19e00, 0xb39ddc00]

def draw_text_centered(text, x, y):
	(w, h) = fl_measure(text)
	descent = fl_descent()
	fl_draw(text, x-w//2, y+h//2-descent);

def draw_text_topleft(text, x, y, pad_x=1, pad_y=1):
	(w, h) = fl_measure(text)
	descent = fl_descent()
	fl_draw(text, x+pad_x, y+h-descent+pad_y);

def draw_text_botright(text, x, y, pad_x=1, pad_y=1):
	(w, h) = fl_measure(text)
	descent = fl_descent()
	fl_draw(text, x-w-pad_x, y-descent-pad_y);

def draw_text_botleft(text, x, y, pad_x=1, pad_y=1):
	(w, h) = fl_measure(text)
	descent = fl_descent()
	fl_draw(text, x+pad_x, y-descent-pad_y);

def ago_str(t):
	now = time.mktime(time.localtime(None))
	sec = now - t

	years_ago = sec / (365*24*3600)
	months_ago = sec / (30*24*3600)
	weeks_ago = sec / (7*24*3600)
	days_ago = sec / (24*3600)
	hours_ago = sec / 3600

	if years_ago >= 1: return '%.1fyr' % years_ago
	if months_ago >= 1: return '%.1fmo' % months_ago
	if weeks_ago >= 1: return '%.1fwk' % weeks_ago
	if days_ago >= 1: return '%.1fd' % days_ago
	return 'today'

def size_str(sz):
	mb = sz / (1024*1024)
	kb = sz / 1024
	if mb >= 1: return '%.1fmb' % mb
	if kb >= 1: return '%.1fkb' % kb
	return '%db' % sz

db = kblib.db_load()
(window_w, window_h) = (640, 480)
pack = None
buttons = []
(search_x, search_y) = (0, 0)
(pack_x, pack_y) = (0, 32)

#------------------------------------------------------------------------------
# post info fields
#------------------------------------------------------------------------------

inp_fname = None
inp_title = None
inp_date_created = None
inp_date_edited = None
inp_tags = None

def inp_fname_cb(widget):
	print('set new fname: %s' % widget.value())

def inp_title_cb(widget):
	fname = inp_fname.value()
	assert fname in db
	title = widget.value()
	print('set %s title to: %s' % (fname, title))
	kblib.set_front_matter_title(fname, title)
	db[fname]['TITLE'] = title
	kblib.db_save(db)	
	scroll.redraw()

def inp_date_created_cb(widget):
	print('set new date_created: %s' % widget.value())

def inp_date_edited_cb(widget):
	print('set new date_edited: %s' % widget.value())

def inp_tags_cb(widget):
	fname = inp_fname.value()
	assert fname in db
	tags = widget.value()
	tags = tags.replace(', ', ',')
	tags = tags.split(',')
	print('set %s tags to: %s' % (fname, tags))
	kblib.set_front_matter_tags(fname, tags)
	db[fname]['tags'] = tags
	kblib.db_save(db)	
	scroll.redraw()

#------------------------------------------------------------------------------
# search
#------------------------------------------------------------------------------
inp_search = None

def inp_search_cb(widget):
	global scroll, pack, pack_x, pack_y
	pack.clear()
	buttons = []

	expr = widget.value()
	print('searching for -%s-' % widget.value())

	# search for nothing (show all)
	if expr == '':
		for fname in sorted(db, key=lambda x: db[x]['date_edited'], reverse=True):
			tmp = MarkdownFile(fname, pack_x, pack_y + 20*len(buttons), 160, 80, fname)
			buttons.append(tmp)
	# search for tag
	elif expr.startswith('#'):
		tag = expr[1:]
		for fname in sorted(db, key=lambda x: db[x]['date_edited'], reverse=True):
			info = db[fname]
			if not tag in [t.lower() for t in info['tags']]:
				continue
			tmp = MarkdownFile(fname, pack_x, pack_y + 20*len(buttons), 160, 80, fname)
			buttons.append(tmp)				
	# search in titles, filenames
	else:
		expr = expr.lower()
		for fname in sorted(db, key=lambda x: db[x]['date_edited'], reverse=True):
			info = db[fname]
			if not expr in info['fname'].lower() and not expr in info['title'].lower():
				continue
			print('matched on %s' % fname)
			tmp = MarkdownFile(fname, pack_x, pack_y + 20*len(buttons), 160, 80, fname)
			buttons.append(tmp)	


	for b in buttons:
		pack.add(b)

	scroll.scroll_to(0, 0)
	scroll.redraw()

#------------------------------------------------------------------------------
# custom widget representing markdown file
#------------------------------------------------------------------------------

class MarkdownFile(Fl_Button):
	def __init__(self, fname, x, y, w, h, l=None):
		Fl_Button.__init__(self, x, y, w, h, l)
		self.callback(self.clicked)
		self.color = random.choice(palette)
		self.fname = fname

	def clicked(self, widget):
		info = db[self.fname]

		if Fl.event_clicks():
			cmd = 'open %s' % info['fpath']
			os.system(cmd)
		else:
			inp_fname.value(info['fname'])
			inp_title.value(info['title'])
			inp_date_created.value(kblib.epochToISO8601(info['date_created']))
			inp_date_edited.value(kblib.epochToISO8601(info['date_edited']))
			inp_tags.value(', '.join(info['tags']))

	def draw(self):
		info = db[self.fname]

		fname = os.path.basename(info['fpath'])
		fl_draw_box(FL_SHADOW_BOX, self.x(), self.y(), self.w(), self.h(), self.color)
		(center_x, center_y) = (self.x() + self.w()//2, self.y() + self.h()//2)

		# draw title
		draw_text_centered(fname, center_x, center_y)

		# draw file size
		draw_text_botleft(size_str(info['fsize']), self.x(), self.y()+self.h(), 2, 4)

		# draw date
		draw_text_topleft('%s' % ago_str(info['date_edited']), self.x(), self.y())

		# tags
		tags_str = ', '.join(info['tags'])
		draw_text_botright(tags_str, self.x()+self.w(), self.y()+self.h(), 8, 2)

def clear_cb(widget):
	pack.clear()
	scroll.redraw()
	print('you wanna clear shit')

window = Fl_Window(window_w, window_h)
window.label("Knowledge Base")
inp_search = Fl_Input(search_x, search_y, 640, 32)
inp_search.callback(inp_search_cb)
inp_search.when(FL_WHEN_ENTER_KEY)

inp_fname = Fl_Input(380, pack_y, window_w-380-2, 32, 'filename:')
inp_fname.callback(inp_fname_cb)
inp_fname.when(FL_WHEN_ENTER_KEY)
inp_title = Fl_Input(380, pack_y+32, window_w-380-2, 32, 'title:')
inp_title.callback(inp_title_cb)
inp_title.when(FL_WHEN_ENTER_KEY)
inp_date_created = Fl_Input(380, pack_y+64, window_w-380-2, 32, 'created:')
inp_date_created.callback(inp_date_created_cb)
inp_date_created.when(FL_WHEN_ENTER_KEY)
inp_date_edited = Fl_Input(380, pack_y+96, window_w-380-2, 32, 'edited:')
inp_date_edited.callback(inp_date_edited_cb)
inp_date_edited.when(FL_WHEN_ENTER_KEY)
inp_tags = Fl_Input(380, pack_y+128, window_w-380-2, 32, 'tags')
inp_tags.callback(inp_tags_cb)
inp_tags.when(FL_WHEN_ENTER_KEY)

clear = Fl_Button(350, 300, 50, 50, "clear")
scroll = Fl_Scroll(pack_x, pack_y, 320, 480-pack_y)
scroll.type(Fl_Scroll.VERTICAL_ALWAYS)
clear.callback(clear_cb)
window.end()

scroll.begin()
pack = Fl_Pack(pack_x, pack_y, 300, 150)
scroll.end()

pack.begin()
pack.spacing(4)
pack.label("Buttons:")

# load the posts
inp_search_cb(inp_search)

pack.end()

window.show()

Fl.run()
		
