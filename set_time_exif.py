#!/usr/bin/env python3

# set file times to photo creation time

import os
import re
import sys
import time
import subprocess

import exif

def get_date_method_a(fpath):
    import exif # pip install exif

    with open(fpath, 'rb') as fp:
        try:
            image = exif.Image(fp)

            if image.has_exif:
                result = image.datetime_original
            else:
                result = 'ERROR: no exif data'

        except Exception as e:
            print(e)
            result = 'ERROR: exception'

    if 0:
        # date is like "2023:11:27 07:13:36"
        struct_time = time.strptime(date, '%Y:%m:%d %H:%M:%S')
        epoch = time.mktime(struct_time)
        print(f'epoch: {epoch}')

    return result

# SLOW, but works for everything
def get_date_method_b(fpath):
    output = subprocess.check_output(['identify', '-verbose', fpath]).decode('utf-8')

    for line in output.splitlines():
        if m := re.search(r'date:create: (.*)', line):
            result = m.group(1)
            break

    return result

def get_date_method_c(fpath):
    from PIL import Image
    from pillow_heif import register_heif_opener # pip install pillow-heif

    register_heif_opener()

    try:
        image = Image.open(fpath)
        exif_data = image.getexif()
        if exif_data:
            for tag, value in exif_data.items():
                tag_name = TAGS.get(tag, tag)
                if tag_name == "DateTimeOriginal":
                    return value
    except Exception as e:
        pass

    return 'ERROR: missing exif tag'

if __name__ == '__main__':
    if sys.argv[1:]:
        fnames = [sys.argv[1]]
    else:
        fnames = []
        for fname in os.listdir('.'):
            _, ext = os.path.splitext(fname)
            if ext.lower() in {'.heic'}:
                fnames.append(fname)

    for fname in fnames:
        date = get_date_method_c(fname)

        if date.startswith('ERROR'):
            continue

    
# KIIP4307.JPG fails
# 
