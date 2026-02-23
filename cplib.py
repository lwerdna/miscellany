#!/usr/bin/env python

import os, sys, re, pprint

def tags_equal(a, b):
    if a.startswith('#'):
        a = a[1:]
    if b.startswith('#'):
        b = b[1:]
    return a.lower() == b.lower()

def tag_included(a, tag_list):
    for b in tag_list:
        if tags_equal(a, b):
            return True

    return False

# removes tags from a line
# 'Hello, world! #Foo #Bar' -> ('Hello, world!', ['Foo', 'Bar'])
def untag_line(line):
    tags = []
    while m := re.match(r'^(.*) #(\w+)$', line):
        tags.append(m.group(2))
        line = m.group(1)
    return (line, tags)

def is_line_tagged(line):
    return bool(re.search(r' #\w+$', line))

def get_filename():
    if temp := next((x for x in sys.argv[1:] if os.path.exists(x) and os.path.isfile(x)), None):
        fpath = temp
    else:
        fpath = next((x for x in ['Commonplace.md', 'log.md', 'journal.md'] if os.path.exists(x)), None)

    return fpath

def get_entries():
    fpath = get_filename()
    if not fpath:
        raise Exception('cannot find a commonplace notes file')

    entries = []

    STATE = 'OUTSIDE'
    in_code_fence = False

    date = None
    elines = [] # entry lines
    line_idx_start, line_idx_end = None, None

    with open(fpath) as fp:
        for line_idx, line in enumerate(fp):
            line = line.strip()

            if line.startswith('```'):
                if len(line) > 3:
                    in_code_fence = True
                else:
                    in_code_fence = False
                continue

            if STATE == 'INSIDE':
                # done with entry?
                if line.startswith('}') and not in_code_fence:
                    # collect tags
                    line, tags = untag_line(line)
                    # start is the index of the line starting with '{'
                    # end is the index of the line starting with '}'
                    entries.append({'date':date, 'lines':elines, 'start':line_idx_start, 'end':line_idx, 'tags':tags})
                    # done, reset
                    elines = []
                    STATE = 'OUTSIDE'
                else:
                    elines.append(line)

            elif STATE == 'OUTSIDE':
                # pick up latest date
                if m := re.match(r'^# (\d\d\d\d-\d\d-\d\d)', line):
                    date = m.group(1)
                # start an entry?
                elif line.startswith('{'):
                    line_idx_start = line_idx
                    STATE = 'INSIDE'
                # skip code blocks outside of entries (which may contain {...} and get confused for entries)

                # is it a single-line entry that ends with tags?
                elif not line.startswith('{') and is_line_tagged(line):
                    line, tags = untag_line(line)
                    entries.append({'date':date, 'lines':[line], 'start':line_idx, 'end':line_idx, 'tags':tags})

            else:
                # toss the line
                pass

    # filter out pornography
    kill_list = []
    for i, entry in enumerate(entries):
        if set(t.lower() for t in entry['tags']).intersection({'porn', 'pr0n', 'pron'}):
            kill_list.append(i)
    for i in reversed(kill_list):
        del(entries[i])

    return entries
