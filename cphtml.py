#!/usr/bin/env python

import os
import re
import sys
import json
import pprint

import markdown

this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(this_dir)
import cplib

header = '''
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>%s</title>
    <style>
      /* default code (usually inline) */
      code {
        background-color: #ccffff;
      }

      /* code that's inside a pre */
      pre code {
        background-color: inherit;
      }

      /* default pre */
      pre {
        border-radius: 8px;
        padding: 4px;
        background-color: #d0d0d0;
      }

      table {
        border: 1px solid black;
      }
      td, th {
        border: 1px solid black;
        padding: 2px;
      }

      code.language-terminal {
        color: #FFFFFF;
      }

      pre.not([class]) {
        background-color: #c0c0c0;
      }

      pre.terminal {
        background-color: #303030;
      }
      code.terminal {
        color: #ffffff;
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
      div.row {
        background-color: red;
        display: flex;
        width: 100%%;
      }
      div.column {
        flex: 1;
        padding: 0px;
      }
    </style>
  </head>
  <body>
'''

footer = '''
  </body>
</html>
'''

def post_process(md):
    md = re.sub(r'<LEFT>(.*?)</LEFT>',
                   r'<div class="row"><div class="column">\1</div>',
                   md, flags=re.DOTALL)
    md = re.sub(r'<RIGHT>(.*?)</RIGHT>',
                   r'<div class="column">\1</div></div>',
                   md, flags=re.DOTALL)
    return md

def md2html(md):
    extension_specs = ['tables', 'toc', 'fenced_code']
    extension_configs = {
        'tables': {},
        'fenced_code' : {},
        'toc': {}
    }
    html = markdown.markdown(md, extensions=extension_specs, extension_configs=extension_configs)

    html = post_process(html)
    
    return html

if __name__ == '__main__':
    entries = cplib.get_entries()
    #print(json.dumps(entries, indent=4))

    print(header % 'MyBlog')

    for entry in entries:
        if not entry['lines']:
            continue

        print(f'<div class="entry">')

        md = '\n'.join(entry['lines'])
        html = md2html(md)

        print(html)

        print(f'</div>')

        break

    print(footer)
