#!/usr/bin/env python

# KB (knowledge base) to HTML

from kblib import *

def gen_blog():
	import markdown

	html_css = '''
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
      h1,h2,h3,h4 {
        margin-bottom: 0;
      }
      pre {
        background-color: #E0E0E0;
        padding: 4px;
      }
      blockquote {
        background-color: pink;
      }
'''

	html_header = '''
	<!DOCTYPE html>
	<html>
	  <head>
	    <meta charset="utf-8">
	    <title>%s</title>
	    <style>
	''' + html_css + '''
	    </style>
	  </head>
	  <body>
'''

	html_footer = '''
	  </body>
	</html>
'''

	global database
	db_load()

#	<fname>: {
#				'mtime': file modification time (float),
#				'date_created': creation time (float),
#				'date_edited': edit time (float),
#				'tags': tags (list),
#			}
	print(html_header % 'My Blog')

	for fname in sorted(database, key=lambda fname: database[fname]['date_created']):
		if not 'publish' in database[fname]['tags']:
			continue

		title = database[fname].get('title', 'Untitled')
		date_c = epochToISO8601(database[fname]['date_created'])
		date_m = epochToISO8601(database[fname]['date_edited'])
		tags = [t for t in database[fname]['tags'] if t != 'publish']

		print('<h3>%s</h3>' % title)
		print('created: %s<br>' % date_c)
		if date_m and date_m != date_c:
			print('updated: %s<br>' % date_m)
		tag_links = ['<a href=tags_%s.html>#%s</a>' % (tag, tag) for tag in tags]
		if tag_links:
			print('tags: ' + ' '.join(tag_links), end='')

		with open(fname, 'r') as fp:
			lines = fp.readlines()

		# eat front matter
		if lines[0].startswith('---'):
			i = 1
			while not lines[i].startswith('---'):
				i += 1
			lines = lines[i+1:]

		if fname.endswith('.txt'):
			print('<pre>')
			print(''.join(lines))
			print('</pre>')

		elif fname.endswith('.md'):
			html = markdown.markdown(''.join(lines), extensions=['tables', 'fenced_code', 'toc'])
			print(html)

	print(html_footer)

