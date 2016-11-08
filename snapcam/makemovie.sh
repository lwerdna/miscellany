#!/bin/sh
echo "deleting ~/Downloads/temp"
rm ~/Downloads/temp/*

echo "copying files to ~/Downloads/tmp"
cp /Volumes/snapcam/DCIM/100SNAPC/*.JPG ~/Downloads/temp

echo "resizing files"
cd ~/Downloads/temp
mogrify -strip -resize 640x480 *.JPG

echo "encoding files"
ffmpeg -framerate 4 -start_number 0788 -i SNAP%04d.JPG -c:v libx264 -r 30 -pix_fmt yuv420p out.mp4

read -p "Check the video. Delete cam files now?" yn
case $yn in
	[Yy]* ) 
