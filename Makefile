install:
	if [ ! -f "${HOME}/bin/diff-dir" ]; then ln -s `pwd`/diff-dir.py ${HOME}/bin/diff-dir; fi;
	if [ ! -f "${HOME}/bin/ftime" ]; then ln -s `pwd`/ftime.py ${HOME}/bin/ftime; fi;
	if [ ! -f "${HOME}/bin/getpics" ]; then ln -s `pwd`/getpics.py ${HOME}/bin/getpics; fi;
	if [ ! -f "${HOME}/bin/decrypt" ]; then ln -s `pwd`/decrypt.py ${HOME}/bin/decrypt; fi;
	if [ ! -f "${HOME}/bin/fdump" ]; then ln -s `pwd`/fdump.py ${HOME}/bin/fdump; fi;
	if [ ! -f "${HOME}/bin/cpscreenshot" ]; then ln -s `pwd`/cpscreenshot.py ${HOME}/bin/cpscreenshot; fi;
	if [ ! -f "${HOME}/bin/cpdownload" ]; then ln -s `pwd`/cpdownload.py ${HOME}/bin/cpdownload; fi;
	if [ ! -f "${HOME}/bin/mvscreenshot" ]; then ln -s `pwd`/mvscreenshot.py ${HOME}/bin/mvscreenshot; fi;
	if [ ! -f "${HOME}/bin/cpdownload" ]; then ln -s `pwd`/cpdownload.py ${HOME}/bin/cpdownload; fi;
	if [ ! -f "${HOME}/bin/searchbin" ]; then ln -s `pwd`/searchbin.py ${HOME}/bin/searchbin; fi;
	if [ ! -f "${HOME}/bin/replace_in_files" ]; then ln -s `pwd`/replace_in_files.py ${HOME}/bin/replace_in_files; fi;
	if [ ! -f "${HOME}/bin/blog" ]; then ln -s `pwd`/blog.py ${HOME}/bin/blog; fi;
	if [ ! -f "${HOME}/bin/til" ]; then ln -s `pwd`/til.py ${HOME}/bin/til; fi;
	if [ ! -f "${HOME}/bin/threads" ]; then ln -s `pwd`/threads.py ${HOME}/bin/threads; fi;
	if [ ! -f "${HOME}/bin/vimmv" ]; then ln -s `pwd`/vimmv.py ${HOME}/bin/vimmv; fi;
	if [ ! -f "${HOME}/bin/pyleetcode" ]; then ln -s `pwd`/pyleetcode.py ${HOME}/bin/pyleetcode; fi;
	if [ ! -f "${HOME}/bin/pyquick" ]; then ln -s `pwd`/pyquick.py ${HOME}/bin/pyquick; fi;
	if [ ! -f "${HOME}/bin/pytimeit" ]; then ln -s `pwd`/pytimeit.py ${HOME}/bin/pytimeit; fi;
	if [ ! -f "${HOME}/bin/ctimeit" ]; then ln -s `pwd`/ctimeit.py ${HOME}/bin/ctimeit; fi;
	if [ ! -f "${HOME}/bin/md2html" ]; then ln -s `pwd`/md2html.py ${HOME}/bin/md2html; fi;
	if [ ! -f "${HOME}/bin/ftags" ]; then ln -s `pwd`/ftags.py ${HOME}/bin/ftags; fi;
	if [ ! -f "${HOME}/bin/mdtags" ]; then ln -s `pwd`/mdtags.py ${HOME}/bin/mdtags; fi;
	if [ ! -f "${HOME}/bin/disassemble" ]; then ln -s `pwd`/disassemble.py ${HOME}/bin/disassemble; fi;
	if [ ! -f "${HOME}/bin/kb" ]; then ln -s `pwd`/kb.py ${HOME}/bin/kb; fi;
	if [ ! -f "${HOME}/bin/kbfltk" ]; then ln -s `pwd`/kbfltk.py ${HOME}/bin/kbfltk; fi;
	if [ ! -f "${HOME}/bin/pyputprints" ]; then ln -s `pwd`/pyputprints.py ${HOME}/bin/pyputprints; fi;
	if [ ! -f "${HOME}/bin/openpickle" ]; then ln -s `pwd`/openpickle.py ${HOME}/bin/openpickle; fi;
	if [ ! -f "${HOME}/bin/git-conflict-marker-split" ]; then ln -s `pwd`/git-conflict-marker-split.py ${HOME}/bin/git-conflict-marker-split; fi;
	if [ ! -f "${HOME}/bin/lslog" ]; then ln -s `pwd`/lslog.py ${HOME}/bin/lslog; fi;
	if [ ! -f "${HOME}/bin/makeurl" ]; then ln -s `pwd`/makeurl.py ${HOME}/bin/makeurl; fi;
	if [ ! -f "${HOME}/bin/grepbin" ]; then ln -s `pwd`/grepbin.py ${HOME}/bin/grepbin; fi;
	if [ ! -f "${HOME}/bin/binja-dis" ]; then ln -s `pwd`/binja-dis.py ${HOME}/bin/binja-dis; fi;
	if [ ! -f "${HOME}/bin/binja-tlinfo" ]; then ln -s `pwd`/binja-tlinfo.py ${HOME}/bin/binja-tlinfo; fi;
	if [ ! -f "${HOME}/bin/binja-cfg-mermaid" ]; then ln -s `pwd`/binja-cfg-mermaid.py ${HOME}/bin/binja-cfg-mermaid; fi;
	if [ ! -f "${HOME}/bin/binja-cfg-dot" ]; then ln -s `pwd`/binja-cfg-dot.py ${HOME}/bin/binja-cfg-dot; fi;
	if [ ! -f "${HOME}/bin/binja-rip" ]; then ln -s `pwd`/binja-rip.py ${HOME}/bin/binja-rip; fi;
	if [ ! -f "${HOME}/bin/bencode2json" ]; then ln -s `pwd`/bencode2json.py ${HOME}/bin/bencode2json; fi;
	if [ ! -f "${HOME}/bin/ls2markdown" ]; then ln -s `pwd`/ls2markdown.py ${HOME}/bin/ls2markdown; fi;
	if [ ! -f "${HOME}/bin/daily" ]; then ln -s `pwd`/daily.py ${HOME}/bin/daily; fi;
	if [ ! -f "${HOME}/bin/comsplit" ]; then ln -s `pwd`/comsplit.py ${HOME}/bin/comsplit; fi;
	if [ ! -f "${HOME}/bin/commerge" ]; then ln -s `pwd`/commerge.py ${HOME}/bin/commerge; fi;

uninstall:
	if [ -f "${HOME}/bin/diff-dir" ]; then rm ${HOME}/bin/diff-dir; fi;
	if [ -f "${HOME}/bin/ftime" ]; then rm ${HOME}/bin/ftime; fi;
	if [ -f "${HOME}/bin/getpics" ]; then rm ${HOME}/bin/getpics; fi;
	if [ -f "${HOME}/bin/decrypt" ]; then rm ${HOME}/bin/decrypt; fi;
	if [ -f "${HOME}/bin/fdump" ]; then rm ${HOME}/bin/fdump; fi;
	if [ -f "${HOME}/bin/cpscreenshot" ]; then rm ${HOME}/bin/cpscreenshot; fi;
	if [ -f "${HOME}/bin/cpdownload" ]; then rm ${HOME}/bin/cpdownload; fi;
	if [ -f "${HOME}/bin/mvscreenshot" ]; then rm ${HOME}/bin/mvscreenshot; fi;
	if [ -f "${HOME}/bin/cpdownload" ]; then rm ${HOME}/bin/cpdownload; fi;
	if [ -f "${HOME}/bin/searchbin" ]; then rm ${HOME}/bin/searchbin; fi;
	if [ -f "${HOME}/bin/replace_in_files" ]; then rm ${HOME}/bin/replace_in_files; fi;
	if [ -f "${HOME}/bin/blog" ]; then rm ${HOME}/bin/blog; fi;
	if [ -f "${HOME}/bin/til" ]; then rm ${HOME}/bin/til; fi;
	if [ -f "${HOME}/bin/threads" ]; then rm ${HOME}/bin/threads; fi;
	if [ -f "${HOME}/bin/vimmv" ]; then rm ${HOME}/bin/vimmv; fi;
	if [ -f "${HOME}/bin/pyleetcode" ]; then rm ${HOME}/bin/pyleetcode; fi;
	if [ -f "${HOME}/bin/pyquick" ]; then rm ${HOME}/bin/pyquick; fi;
	if [ -f "${HOME}/bin/pytimeit" ]; then rm ${HOME}/bin/pytimeit; fi;
	if [ -f "${HOME}/bin/ctimeit" ]; then rm ${HOME}/bin/ctimeit; fi;
	if [ -f "${HOME}/bin/md2html" ]; then rm ${HOME}/bin/md2html; fi;
	if [ -f "${HOME}/bin/ftags" ]; then rm ${HOME}/bin/ftags; fi;
	if [ -f "${HOME}/bin/mdtags" ]; then rm ${HOME}/bin/mdtags; fi;
	if [ -f "${HOME}/bin/disassemble" ]; then rm ${HOME}/bin/disassemble; fi;
	if [ -f "${HOME}/bin/kb" ]; then rm ${HOME}/bin/kb; fi;
	if [ -f "${HOME}/bin/kbfltk" ]; then rm ${HOME}/bin/kbfltk; fi;
	if [ -f "${HOME}/bin/pyputprints" ]; then rm ${HOME}/bin/pyputprints; fi;
	if [ -f "${HOME}/bin/openpickle" ]; then rm ${HOME}/bin/openpickle; fi;
	if [ -f "${HOME}/bin/git-conflict-marker-split" ]; then rm ${HOME}/bin/git-conflict-marker-split; fi;
	if [ -f "${HOME}/bin/lslog" ]; then rm ${HOME}/bin/lslog; fi;
	if [ -f "${HOME}/bin/makeurl" ]; then rm ${HOME}/bin/makeurl; fi;
	if [ -f "${HOME}/bin/grepbin" ]; then rm ${HOME}/bin/grepbin; fi;
	if [ -f "${HOME}/bin/binja-dis" ]; then rm ${HOME}/bin/binja-dis; fi;
	if [ -f "${HOME}/bin/binja-tlinfo" ]; then rm ${HOME}/bin/binja-tlinfo; fi;
	if [ -f "${HOME}/bin/binja-cfg-mermaid" ]; then rm ${HOME}/bin/binja-cfg-mermaid; fi;
	if [ -f "${HOME}/bin/binja-cfg-dot" ]; then rm ${HOME}/bin/binja-cfg-dot; fi;
	if [ -f "${HOME}/bin/binja-rip" ]; then rm ${HOME}/bin/binja-rip; fi;
	if [ -f "${HOME}/bin/bencode2json" ]; then rm ${HOME}/bin/bencode2json; fi;
	if [ -f "${HOME}/bin/ls2markdown" ]; then rm ${HOME}/bin/ls2markdown; fi;
	if [ -f "${HOME}/bin/daily" ]; then rm ${HOME}/bin/daily; fi;
	if [ -f "${HOME}/bin/comsplit" ]; then rm ${HOME}/bin/comsplit; fi;
	if [ -f "${HOME}/bin/commerge" ]; then rm ${HOME}/bin/commerge; fi;
