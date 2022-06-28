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
    tags = []
    while True:
        line = line.strip()
        m = re.match(r'^.*(#(\w+))$', line) or re.match(r'^.*(tag:(\w+))$', line)
        if not m: break
        tags.append(m.group(2))
        line = line[:-len(m.group(1))]
    tags = [tag[0].upper() + tag[1:] for tag in tags]
    return (tags, line.rstrip())

# example:
# 'Hello World #tag1 #tag2.txt' ->
#   (['tag1', 'tag2'], 'Hello World.txt')
def parse_tags_filename(fname):
    (root, ext) = os.path.splitext(fname)
    (tags, root) = parse_tags_line(root)
    return (tags, root+ext)

def parse_tags_entry(lines):
    last_line = lines[-1]
    assert last_line.startswith('</ENTRY>')
    second_last_line = lines[-2]
    (tags, _) = parse_tags_line(second_last_line)
    return tags

def tags_to_string(tags):
    return ' '.join([f'{tag}' for tag in sorted(tags)])
    #return ' '.join([f'{tag_to_color(tag)}{tag}\x1B[0m' for tag in tags])

def collect_notes(fpath, database):
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
            (tags, line) = parse_tags_line(line)

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
def collect_files(root, database):
    blacklist_files = {'.DS_Store'}
    blacklist_dirs = {'assets'}

    for dpath in get_date_paths(root):
        for fname in os.listdir(dpath):
            fpath = os.path.join(dpath, fname)

            if os.path.isfile(fpath) and fname in blacklist_files:
                continue
            elif os.path.isdir(fpath) and fname in blacklist_dirs:
                continue

            title = ''
            title_linked = ''

            (tags, fname) = parse_tags_filename(fname)
            title += fname
            title_linked += fname

            links = None
            if os.path.isdir(fpath):
                title += ' (D)'
                title_linked += f' ({terminal_link_file(fpath, "D")})'
            else:
                dpart = os.path.split(fpath)[0]
                title += ' (DF)'
                title_linked += f' ({terminal_link_file(dpart, "D")}{terminal_link_file(fpath, "F")})'

            (year, month, day) = re.search(r'/(\d\d\d\d)/(\d\d)/(\d\d)/', fpath).group(1,2,3)
            database[f'{year}-{month}-{day}'].append({
                'type': 'FILE',
                'title': title,
                'title_linked': title_linked,
                'tags': tags
            })

def width_output():
    if sys.stdout.isatty():
        return os.get_terminal_size(sys.stdout.fileno()).columns
    else:
        return 128

def perform_ls(database, limit=1024):
    # collect entries from database
    # database = {'2022-05-02': [entry, entry, ...],
    #             '2022-01-03': [entry, entry, ...],
    #             ...}
    entries = []
    for date in sorted(database): # oldest at [0], eg: ['2022-01-01', '2022-01-02', '2022-01-03', ...]
        for e in database[date]:
            e['date'] = date
            entries.append(e)
        if len(entries) >= limit:
            break
    entries = entries[0:limit]

    now = ISO8601ToEpoch(epochToISO8601('now'))

    thresholds = [
        [0, 'REMAINDER', False],
        [now-3*365*24*3600, 'LAST THREE YEARS', False],
        [now-365*24*3600, 'LAST YEAR', False],
        [now-4*30*24*3600, 'LAST QUARTER', False],
        [now-30*24*3600, 'LAST MONTH', False],
        [now-7*24*3600, 'LAST WEEK', False],
        [now-3*24*3600, 'LAST THREE DAYS', False],
        [now-24*3600, 'LAST DAY', False],
    ]

    # print a threshold fence?
    for entry in entries:
        for thresh in thresholds:
            if ISO8601ToEpoch(entry['date']) > thresh[0] and thresh[2]==False:
                print(thresh[1])
                thresh[2] = True

        indent = '  '
        width = width_output()
        right = tags_to_string(entry['tags']) + ' ' + entry['date']
        if entry['type'] == 'FILE':
            left = indent  + entry['title_linked']
            print(left + right.rjust(width - (len(indent) + len(entry['title']))))
        else:
            left = indent + entry['title']
            print(left + right.rjust(width - len(left)))

if __name__ == '__main__':
    database = defaultdict(lambda: [])

    # parse notes.md
    fpath = os.path.join(os.environ['HOME'], 'fdumps', 'journals', 'notes.md')
    collect_notes(fpath, database)

    dpath = os.path.join(os.environ['HOME'], 'fdumps', 'heap')
    collect_files(dpath, database)

    perform_ls(database)

