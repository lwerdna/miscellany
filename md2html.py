#!/usr/bin/env python3

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
        background-color: #ccffff;
      }
      pre code {
        background-color: inherit;
      }
      pre.plain {
      }
      pre.code {
        margin-left: 1.5em;
        margin-right: 1.5em;
        border: 1px dotted;
        padding-top: 5px;
        padding-left: 5px;
        padding-bottom: 5px;
        background-color: #ccffff;
      }
      pre.dialogue {
        margin-left: 1.5em;
        margin-right: 1.5em;
        border: 1px dotted;
        padding-top: 5px;
        padding-left: 5px;
        padding-bottom: 5px;
        background-color: #ffddff;
      }
      blockquote {
        background-color: pink;
      }
      img.link {
        border-width: 1px;
        border-style: solid;
        border-color: blue;
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

