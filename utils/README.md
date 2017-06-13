These are quick utilities I use frequently. The `make install` target puts them
in /usr/local/bin without the .py extension and I can invoke them like regular
binary, eg: `ftime` or `getpics`.

# ftime.py
* change mtime and atime on files with text-editor-as-gui interaction

# getpics.py
* get pics/vids from Android phone taken in last 24 hours, go back further with command line switches

# decrypt.py
* decrypts my personal files, key derivation is sha1(pass), cipher is XTEA in OFB mode
