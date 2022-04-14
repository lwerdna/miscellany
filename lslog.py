#!/usr/bin/env python

import os, sys, re, pprint
from collections import defaultdict
import urllib

from functools import reduce
from operator import add

from nltk import tokenize

from kblib import *

def get_first_sentence(text):
    sentences = tokenize.sent_tokenize(text)
    first = sentences[0]
    return first

def parse_tags_line(line):
    result = []
    while True:
        line = line.strip()
        #breakpoint()
        m = re.match(r'^.*(#(\w+))$', line) or re.match(r'^.*(tag:(\w+))$', line)
        if not m: break
        result.append(m.group(2))
        line = line[:-len(m.group(1))]
    result = [tag[0].upper() + tag[1:] for tag in result]
    return result

def parse_tags_entry(lines):
    last_line = lines[-1]
    assert last_line.startswith('</ENTRY>')
    second_last_line = lines[-2]
    tags = parse_tags_line(second_last_line)
    return tags

def tags_to_string(tags):
    return ' '.join([f'{tag}' for tag in sorted(tags)])
    #return ' '.join([f'{tag_to_color(tag)}{tag}\x1B[0m' for tag in tags])

def parse_notes_md(fpath, database):
    with open(fpath) as fp:
        lines = fp.readlines()

    i = 0
    date = None
    while i < len(lines):
        line = lines[i]
        i += 1

        if m := re.match(r'^# (\d\d\d\d-\d\d-\d\d).*', line):
            date = m.group(1)
            continue

        elif m := re.match(r'^MICROBLOG> (.*)$', line):
            tags = parse_tags_line(line)

            contents = m.group(1)
            first_sentence = get_first_sentence(contents)
            if len(first_sentence) > 64:
                first_sentence = first_sentence[0:64] + '...'

            database[date].append({
                'type': 'MICROBLOG',
                'title': first_sentence,
                'tags': tags
            })

        elif m := re.match(r'^<ENTRY title="(.*?)"', line):
            title = m.group(1)

            entry_lines = [line]
            while True:
                line = lines[i]
                entry_lines.append(line)
                i += 1
                if line.startswith('</ENTRY>'):
                    break

            tags = parse_tags_entry(entry_lines)

            database[date].append({
                'type': 'ENTRY',
                'title': title,
                'tags': tags
            })

def terminal_link_file(fpath, text):
    return '\x1B]8;;file://%s\x1B\\%s\x1B]8;;\x1B\\' % (urllib.parse.quote(fpath), text)

# collect paths with date directory structure like <root>/YYYY/MM/DD
def get_date_paths(root):
    result = []

    years = [d for d in os.listdir(root) if re.match(r'^\d\d\d\d$', d)]

    for year in years:
        months = [d for d in os.listdir(os.path.join(root, year)) if re.match(r'^\d\d$', d)]
        
        for month in months:
            days = [d for d in os.listdir(os.path.join(root, year, month)) if re.match(r'^\d\d$', d)]

            for day in days:
                full_path = os.path.join(root, year, month, day)
                if os.path.isdir(full_path):
                    result.append(full_path)

    return result

# given a path, create entries for files in date dirs, like <root>/2020/04/01/dominator-tree.py
def parse_attachments(root, database):
    blacklist_files = {'.DS_Store'}
    blacklist_dirs = {'assets'}

    for dpath in get_date_paths(root):
        for name in os.listdir(dpath):
            fpath = os.path.join(dpath, name)

            if os.path.isfile(fpath) and name in blacklist_files:
                continue
            elif os.path.isdir(fpath) and name in blacklist_dirs:
                continue

            links = None
            if os.path.isdir(fpath):
                links = terminal_link_file(fpath, 'D')
            else:
                dpart = os.path.split(fpath)[0]
                links = terminal_link_file(dpart, 'D') + terminal_link_file(fpath, 'F')

            (year, month, day) = re.search(r'/(\d\d\d\d)/(\d\d)/(\d\d)/', fpath).group(1,2,3)
            database[f'{year}-{month}-{day}'].append({
                'type': 'ATTACHMENT',
                #'title': fpath,
                #'title': fpath[fpath.index(date + '/') + len(date)+1:]
                #'title': terminal_link_file(left, 'DIR') + ' ' + terminal_link_file(fpath, right)
                'title': links + ' ' + name
            })

def width_output():
    if sys.stdout.isatty():
        return os.get_terminal_size(sys.stdout.fileno()).columns
    else:
        return 128

def print_entries(entries):
    width = width_output()

    for entry in entries:
        if entry['type'] == 'ATTACHMENT':
            print('    ' + entry['title'])
        else:
            left = '  ' + entry['title']
            right = tags_to_string(entry['tags'])
            print(left + right.rjust(width - len(left)))

def perform_ls(database, limit=1024):
    # collect entries until limit reached
    entries = []
    for date in sorted(database):
        for e in database[date]:
            e['date'] = date
            entries.append(e)
        if len(entries) >= limit:
            break
    entries = entries[0:limit]
        
    print_entries(entries)
    return

    now = ISO8601ToEpoch(epochToISO8601('now'))

    time_thresholds = [
        (0, 'REMAINDER'),
        (now-3*365*24*3600, 'LAST THREE YEARS'),
        (now-365*24*3600, 'LAST YEAR'),
        (now-4*30*24*3600, 'LAST QUARTER'),
        (now-30*24*3600, 'LAST MONTH'),
        (now-7*24*3600, 'LAST WEEK'),
        (now-24*3600, 'LAST DAY'),
    ]

    width = width_output()
    for (threshold, description) in time_thresholds:
        dates = [date_str for date_str in database
                      if ISO8601ToEpoch(date_str) >= threshold
                      and not date_str in seen
                     ]

        if not dates:
            continue

        cprint(description.center(width, ' '), 'white', 'on_blue')
        entries = reduce(add, [database[d] for d in dates], [])

        if len(seen)>0:
            print()
        print_entries(entries)
            
        seen.update(dates)
        if len(seen) > limit:
            break

if __name__ == '__main__':
    database = defaultdict(lambda: [])

    # parse notes.md
    fpath = os.path.join(os.environ['HOME'], 'fdumps', 'journals', 'notes.md')
    parse_notes_md(fpath, database)

    dpath = os.path.join(os.environ['HOME'], 'fdumps', 'heap')
    parse_attachments(dpath, database)

    perform_ls(database)

