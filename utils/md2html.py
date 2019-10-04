#!/usr/bin/env python

import sys
import markdown # pip install Markdown, https://github.com/Python-Markdown/markdown

header = '''
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>My test page</title>
    <style>
      table {
        border: 1px solid black;
      }
      td, th {
        border: 1px solid black;
        padding: 2px;
      }
      code {
        background-color: #E0E0E0;
      }
      pre {
        background-color: #E0E0E0;
        padding: 4px;
      }
      blockquote {
        background-color: pink;
      }
    </style>
  </head>
  <body>
'''

footer = '''
  </body>
</html>
'''

if __name__ == '__main__':
	(infile, outfile) = (sys.argv[1], sys.argv[2])

	with open(infile) as fp:
		md = fp.read()

	html = markdown.markdown(md, extensions=['tables', 'fenced_code', 'toc'])

	with open(outfile, 'w') as fp:
		fp.write(header)
		fp.write(html)
		fp.write(footer)

