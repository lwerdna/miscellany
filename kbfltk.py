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
(window_w, window_h) = (640, 1024)

text_fields_h = 24

inp_search = None
(search_x, search_y, search_w, search_h) = (0, 0, window_w, text_fields_h)

scroll = None
(scroll_x, scroll_y) = (0, 0+search_h)
(scroll_w, scroll_h) = (window_w//2, 640)

pack = None
(pack_x, pack_y) = (scroll_x+4, scroll_y+4)
(pack_w, pack_h) = (scroll_w-24, scroll_h)

(md_w, md_h) = (20, 80)

calendar = None
(cal_scroll_x, cal_scroll_y) = (0, pack_y+pack_h)
(cal_scroll_w, cal_scroll_h) = (window_w, 64)

buttons = []

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

def inp_search_cb(widget):
	global scroll, pack, pack_x, pack_y
	pack.clear()
	buttons = []

	expr = widget.value()
	print('searching for -%s-' % widget.value())

	# search for nothing (show all)
	if expr == '':
		for fname in sorted(db, key=lambda x: db[x]['date_edited'], reverse=True):
			tmp = MarkdownFile(fname, 0, 0, md_w, md_h, fname)
			buttons.append(tmp)
	# search for tag
	elif expr.startswith('#'):
		tag = expr[1:]
		for fname in sorted(db, key=lambda x: db[x]['date_edited'], reverse=True):
			info = db[fname]
			if not tag in [t.lower() for t in info['tags']]:
				continue
			tmp = MarkdownFile(fname, 0, 0, md_w, md_h, fname)
			buttons.append(tmp)
	# search by date
	elif expr.startswith('date:'):
		date = expr[5:]
		print('searching for date -%s-' % date)
		for fname in sorted(db, key=lambda x: db[x]['date_edited'], reverse=True):
			if date != kblib.epochToISO8601(db[fname]['date_created']):
				continue
			tmp = MarkdownFile(fname, 0, 0, md_w, md_h, fname)
			buttons.append(tmp)
	# search in titles, filenames
	else:
		expr = expr.lower()
		for fname in sorted(db, key=lambda x: db[x]['date_edited'], reverse=True):
			info = db[fname]
			if not expr in info['fname'].lower() and not expr in info['title'].lower():
				continue
			print('matched on %s' % fname)
			tmp = MarkdownFile(fname, 0, 0, md_w, md_h, fname)
			buttons.append(tmp)


	for b in buttons:
		pack.add(b)

	scroll.scroll_to(0, 0)
	scroll.redraw()

#------------------------------------------------------------------------------
# custom widget, github-style calendar
#------------------------------------------------------------------------------

class GithubCalendar(Fl_Widget):
	def __init__(self, x, y, w, h, label=None):
		Fl_Widget.__init__(self, x, y, w, h, label)

	def set_start_time(self, t):
		# back up until monday (possibly entering previous year)
		while 1:
			if time.localtime(t).tm_wday == 0:
				break
			t -= 24*60*60
		self.t0 = t
		self.t1 = time.mktime(time.localtime(None))
		nday = int(self.t1-self.t0)//(24*60*60)
		nweek = (nday+6)//7
		self.resize(self.x(), self.y(), nweek*8, 7*8)

	def handle(self, event):
		if event == FL_PUSH:
			return 1
		if event == FL_RELEASE:
			weeks = (Fl.event_x() - self.x())//8
			days = (Fl.event_y() - self.y())//8
			print('(x,y)=(%d,%d) and (weeks,days)=(%d,%d)' % (Fl.event_x()-self.x(), Fl.event_y()-self.y(), weeks, days))
			t = self.t0 + (7*weeks + days)*24*60*60
			inp_search.value('date:%s' % kblib.epochToISO8601(t))
			inp_search_cb(inp_search)
		return 0

	def draw(self):
		# draw the graph paper
		fl_color(FL_BLACK)
		fl_line_style(FL_SOLID, 1)
		for i in range(1,8):
			fl_line(self.x(), self.y()+8*i, self.x()+self.w(), self.y()+8*i)
		for i in range(0, self.w()//8):
			fl_line(self.x()+8*i, self.y(), self.x()+8*i, self.y()+self.h())

		lookup = {}
		for fname in db:
			key = db[fname]['date_created']
			lookup[key] = lookup.get(key, 0)+1

		for (date, amount) in lookup.items():
			color = 0xebedf000
			if amount==1: color=0x9be9a800
			if amount==2: color=0x40c46300
			if amount==3: color=0x30a14e00
			if amount>=4: color=0x216e3900
			delta = int(date - self.t0)//(24*60*60)
			x = self.x() + 8*(delta//7)
			y = self.y() + 8*(delta%7)
			fl_draw_box(FL_BORDER_BOX, x, y, 8+1, 8+1, color)

#------------------------------------------------------------------------------
# custom widget representing markdown file
#------------------------------------------------------------------------------

class MarkdownFile(Fl_Button):
	def __init__(self, fname, x, y, w, h, l=None):
		Fl_Button.__init__(self, x, y, w, h, l)
		self.callback(self.clicked)
		#self.color = FL_WHITE
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

def btn_delete_cb(widget):
	fname = inp_fname.value()
	assert fname in db
	fpath = os.path.join(kblib.PATH_KB, fname)
	after = os.path.join(kblib.PATH_KB, fname + '.trash')
	print('moving %s -> %s' % (fpath, after))
	os.rename(fpath, after)
	del db[fname]
	kblib.db_save(db)
	scroll.redraw()

window = Fl_Window(window_w, window_h)
window.label("Knowledge Base")
inp_search = Fl_Input(search_x, search_y, 640, text_fields_h)
inp_search.callback(inp_search_cb)
inp_search.when(FL_WHEN_ENTER_KEY)

inp_fname = Fl_Input(380, pack_y + 0*text_fields_h, window_w-380-2, text_fields_h, 'filename:')
inp_fname.callback(inp_fname_cb)
inp_fname.when(FL_WHEN_ENTER_KEY)
inp_title = Fl_Input(380, pack_y + 1*text_fields_h, window_w-380-2, text_fields_h, 'title:')
inp_title.callback(inp_title_cb)
inp_title.when(FL_WHEN_ENTER_KEY)
inp_date_created = Fl_Input(380, pack_y + 2*text_fields_h, window_w-380-2, text_fields_h, 'created:')
inp_date_created.callback(inp_date_created_cb)
inp_date_created.when(FL_WHEN_ENTER_KEY)
inp_date_edited = Fl_Input(380, pack_y + 3*text_fields_h, window_w-380-2, text_fields_h, 'edited:')
inp_date_edited.callback(inp_date_edited_cb)
inp_date_edited.when(FL_WHEN_ENTER_KEY)
inp_tags = Fl_Input(380, pack_y + 4*text_fields_h, window_w-380-2, text_fields_h, 'tags:')
inp_tags.callback(inp_tags_cb)
inp_tags.when(FL_WHEN_ENTER_KEY)

btn_delete = Fl_Button(350, 300, 50, 50, "delete")
btn_delete.callback(btn_delete_cb)

cal_scroll = Fl_Scroll(cal_scroll_x, cal_scroll_y, cal_scroll_w, cal_scroll_h+20)
cal_scroll.type(Fl_Scroll.HORIZONTAL_ALWAYS)
calendar = GithubCalendar(cal_scroll_x+2, cal_scroll_y+2, 0, 0)
oldest = min([db[x]['date_created'] for x in db])
calendar.set_start_time(oldest)
cal_scroll.end()

window.begin()
scroll = Fl_Scroll(scroll_x, scroll_y, scroll_w, scroll_h)
scroll.type(Fl_Scroll.VERTICAL_ALWAYS)
window.end()

scroll.begin()
pack = Fl_Pack(pack_x, pack_y, pack_w, pack_h)
scroll.end()

pack.begin()
pack.spacing(4)
pack.label("Buttons:")

# load the posts
inp_search_cb(inp_search)
#
pack.end()

window.show()
#cal_scroll.scroll_to(calendar.x() + calendar.w(), 0)

Fl.run()

