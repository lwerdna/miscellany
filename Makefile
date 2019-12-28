
install:
	if [ ! -f "${HOME}/bin/ftime" ]; then ln -s `pwd`/ftime.py ${HOME}/bin/ftime; fi;
	if [ ! -f "${HOME}/bin/getpics" ]; then ln -s `pwd`/getpics.py ${HOME}/bin/getpics; fi;
	if [ ! -f "${HOME}/bin/decrypt" ]; then ln -s `pwd`/decrypt.py ${HOME}/bin/decrypt; fi;
	if [ ! -f "${HOME}/bin/fdump" ]; then ln -s `pwd`/fdump.py ${HOME}/bin/fdump; fi;
	if [ ! -f "${HOME}/bin/cpscreenshot" ]; then ln -s `pwd`/cpscreenshot.py ${HOME}/bin/cpscreenshot; fi;
	if [ ! -f "${HOME}/bin/cpdownload" ]; then ln -s `pwd`/cpdownload.py ${HOME}/bin/cpdownload; fi;
	if [ ! -f "${HOME}/bin/searchbin" ]; then ln -s `pwd`/searchbin.py ${HOME}/bin/searchbin; fi;
	if [ ! -f "${HOME}/bin/replace_in_files" ]; then ln -s `pwd`/replace_in_files.py ${HOME}/bin/replace_in_files; fi;
	if [ ! -f "${HOME}/bin/blog" ]; then ln -s `pwd`/blog.py ${HOME}/bin/blog; fi;
	if [ ! -f "${HOME}/bin/til" ]; then ln -s `pwd`/til.py ${HOME}/bin/til; fi;
	if [ ! -f "${HOME}/bin/vimmv" ]; then ln -s `pwd`/vimmv.py ${HOME}/bin/vimmv; fi;
	if [ ! -f "${HOME}/bin/leetcode" ]; then ln -s `pwd`/leetcode.py ${HOME}/bin/leetcode; fi;
	if [ ! -f "${HOME}/bin/disthumb" ]; then ln -s `pwd`/disthumb.py ${HOME}/bin/disthumb; fi;
	if [ ! -f "${HOME}/bin/md2html" ]; then ln -s `pwd`/md2html.py ${HOME}/bin/md2html; fi;

uninstall:
	if [ -f "${HOME}/bin/ftime" ]; then rm ${HOME}/bin/ftime; fi;
	if [ -f "${HOME}/bin/getpics" ]; then rm ${HOME}/bin/getpics; fi;
	if [ -f "${HOME}/bin/decrypt" ]; then rm ${HOME}/bin/decrypt; fi;
	if [ -f "${HOME}/bin/fdump" ]; then rm ${HOME}/bin/fdump; fi;
	if [ -f "${HOME}/bin/cpscreenshot" ]; then rm ${HOME}/bin/cpscreenshot; fi;
	if [ -f "${HOME}/bin/cpdownload" ]; then rm ${HOME}/bin/cpdownload; fi;
	if [ -f "${HOME}/bin/searchbin" ]; then rm ${HOME}/bin/searchbin; fi;
	if [ -f "${HOME}/bin/replace_in_files" ]; then rm ${HOME}/bin/replace_in_files; fi;
	if [ -f "${HOME}/bin/blog" ]; then rm ${HOME}/bin/blog; fi;
	if [ -f "${HOME}/bin/til" ]; then rm ${HOME}/bin/til; fi;
	if [ -f "${HOME}/bin/vimmv" ]; then rm ${HOME}/bin/vimmv; fi;
	if [ -f "${HOME}/bin/leetcode" ]; then rm ${HOME}/bin/leetcode; fi;
	if [ -f "${HOME}/bin/disthumb" ]; then rm ${HOME}/bin/disthumb; fi;
	if [ -f "${HOME}/bin/md2html" ]; then rm ${HOME}/bin/md2html; fi;
