#!/usr/bin/env python

import re
import sys

from newspaper import Article

url = sys.argv[1]
print('seeking %s' % url)
article = Article(url)
article.download()
article.parse()

fname = re.sub(r'[^\w]', '_', article.title) + '.txt'
print('saving to %s' % fname)
with open(fname, 'w') as fp:
	print('saved from %s' % url)
	print('')
	print(article.title)
	print('')
	print(','.join(article.authors))
	print('')
	print(article.text)
