#!/usr/bin/env python

import sys
import markdown # pip install Markdown, https://github.com/Python-Markdown/markdown

title = 'UNTITLED'

if sys.argv[2:]:
	title = sys.argv[2]

header = '''
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>%s</title>
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
''' % title

footer = '''
  </body>
</html>
'''

infile = sys.argv[1]
with open(infile) as fp:
	md = fp.read()

# kinda equivalent to command line invocation: markdown2 -x fenced-code-blocks -x highlightjs-lang -x tables ./index.md
sys.stdout.write(header)
html = markdown.markdown(md, extensions=['tables', 'fenced_code', 'toc'])
sys.stdout.write(html)
sys.stdout.write(footer)

