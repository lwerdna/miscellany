#!/usr/bin/env python3
# display images written to unix socket

import io, os, sys, time, select, socket
import binascii

import Tkinter

from PIL import Image, ImageTk

svr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
svr.bind(('localhost', 31337))
svr.listen(1)

tk = Tkinter.Tk()

label = None

while 1:
	tk.update_idletasks()
	tk.update()

	fdset_r = [svr]
	fdset_r, fdset_w, fdset_e = select.select(fdset_r, [], [], .001)
	if svr in fdset_r:
		cli, addr = svr.accept()
		data = ''
		while 1:
			tmp = cli.recv(4096)
			if not tmp:
				break;
			data += tmp
		cli.close()
		print "received %d bytes %s...%s" % (len(data), binascii.hexlify(data[0:16]), binascii.hexlify(data[-16:]))

		if label:
			label.image = None
			label.destroy()
			label = None
	
		try:	
			image = Image.open(io.BytesIO(data))
			image = image.convert('RGB') # else it won't draw PNG's with transparency
			photo = ImageTk.PhotoImage(image)

			label = Tkinter.Label(tk, image=photo)
			label.image = photo
			label.pack()
		except Exception:
			pass
