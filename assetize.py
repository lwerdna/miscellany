#!/usr/bin/env python

# process image and various resizings into ./assets folder

import os, sys, re, pprint, shutil
import PIL
from PIL import Image

def get_width(fpath):
    image = PIL.Image.open(fpath)
    assert image, 'couldnt open %s' % fpath
    (width, height) = image.size
    return width

assert sys.argv[1:], 'expected path to image as first parameter'
fpath = sys.argv[1]

(dpath, fname) = os.path.split(fpath)
(fbase, fext) = os.path.splitext(fname)
fpath_assets = os.path.join(dpath, 'assets')

assert os.path.exists(fpath_assets), 'expected assets directory neighboring target'
assert os.path.isdir(fpath_assets), 'expected assets to be a directory'

if get_width(fpath) > 320:
    fname_320 = fbase + '_320x' + fext
    fpath_320 = os.path.join(fpath_assets, fname_320)
    cmd = 'convert %s -resize 320x %s' % (fpath, fpath_320)
    #print(cmd)
    os.system(cmd)
    print('\n---- 320x??? ---')
    print('IMAGE SHOW: ![](./assets/%s)' % fname_320)
    #print('[<img src="./assets/%s">](./assets/%s)' % (fname_320, fname))
    #print('IMAGE LINK: <a href="./assets/%s"><img style="float: left;" src="./assets/%s"></a>' % (fname, fname_320))
    print('IMAGE LINK: <a href="./assets/%s"><img src="./assets/%s"></a><br>' % (fname, fname_320))

if get_width(fpath) > 640:
    fname_640 = fbase + '_640x' + fext
    fpath_640 = os.path.join(fpath_assets, fname_640)
    cmd = 'convert %s -resize 640x %s' % (fpath, fpath_640)
    #print(cmd)
    os.system(cmd)
    print('\n---- 640x??? ---')
    print('IMAGE SHOW: ![](./assets/%s)' % fname_640)
    #print('[<img src="./assets/%s">](./assets/%s)' % (fname_640, fname))
    #print('IMAGE_LINK: <a href="./assets/%s"><img style="float: left;" src="./assets/%s"></a>' % (fname, fname_640))
    print('IMAGE_LINK: <a href="./assets/%s"><img src="./assets/%s"></a><br>' % (fname, fname_640))

print('\n---- ORIGINAL ---')
fpath_orig = os.path.join(fpath_assets, fname)
shutil.copy(fpath, fpath_orig)
print('IMAGE SHOW: ![](./assets/%s)' % fname)
#print('IMAGE SHOW: <img style="float: left;" src="./assets/%s">' % (fname))
print('IMAGE SHOW: <img src="./assets/%s">' % (fname))



