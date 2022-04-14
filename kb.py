#!/usr/bin/env python

# CLI interface to kb (knowledge base)

import time
import json

from kblib import *

#------------------------------------------------------------------------------
# misc
#------------------------------------------------------------------------------

# central place to decide how to edit a file (vim, gvim, macvim, typora, etc.)
def edit_file(fpath, method='macvim'):
    if method == 'macvim':
        os.system('open -a macvim %s' % fpath)
    elif method == 'typora':
        os.system('open -a typora %s' % fpath)
    elif method == 'gvim':
        os.system('gvim %s +' % fpath)
    elif method == 'vim':
        os.system('vim %s +' % fpath)


#------------------------------------------------------------------------------
# output stuff
#------------------------------------------------------------------------------

def db_print(fname):
    database = db_load()

    fnames = [fname] if fname else sorted(database)
    for fname in fnames:
        print(fname)
        info = database[fname]
        width = max([len(x) for x in info])
        for key in sorted(info):
            print('\t%s: %s' % (key.ljust(width), info[key]))

    print('%d files listed' % len(fnames))

def print_columns(fnames):
    column_width = 32
    column_quantity = os.get_terminal_size().columns // column_width
    column_quantity = max(column_quantity, 1)

    #fnames = sorted(fnames, key=lambda x: database[x]['date_edited'])
    fnames = sorted(fnames)

    while fnames:
        line = ''
        for fname in fnames[0:column_quantity]:
            tmp = fname.ljust(column_width)
            line += tmp
            # if this filename breaks the look, go to new line
            if len(tmp) > column_width:
                break

        print(line)
        fnames = fnames[column_quantity:]

def terminal_link_file(fpath, text):
    return '\x1B]8;;file://%s\x1B\\%s\x1B]8;;\x1B\\' % (fpath, text)

def perform_ls(limit=8):
    database = db_load()

    current = None
    for fname in sorted(database, key=lambda k: database[k]['date_edited'], reverse=True)[0:limit]:
        date = pretty_time(database[fname]['date_edited'])
        if date != current:
            if current:
                print()
            cprint(date, attrs=['bold'])
            #cprint(pm, 'white', 'on_blue')
            current = date

        title = database[fname]['title']
        if not title or title == 'Untitled':
            print(terminal_link_file(database[fname]['fpath'], fname))
        else:
            print(terminal_link_file(database[fname]['fpath'], title) + (' (%s)' % fname))

        #print('    ', fname)

def perform_ls2(limit, tags=[]):
    database = db_load()

    # if tags are specified, filter entries that have tags
    if tags:
        tags = [x[1:] if x.startswith('#') else x for x in tags]

        dbtemp = {}
        for fname in database:
            if set(database[fname]['tags']).isdisjoint(tags):
                continue
            dbtemp[fname] = database[fname]
        database = dbtemp

    seen = set()
    width = os.get_terminal_size().columns
    now = ISO8601ToEpoch(epochToISO8601('now'))

    time_thresholds = [
        (now-24*3600, 'LAST DAY'),
        (now-7*24*3600, 'LAST WEEK'),
        (now-30*24*3600, 'LAST MONTH'),
        (now-4*30*24*3600, 'LAST QUARTER'),
        (now-365*24*3600, 'LAST YEAR'),
        (now-3*365*24*3600, 'LAST THREE YEARS'),
        (0, 'REMAINDER')
    ]

    for (threshold, description) in time_thresholds:
        collection = [x for x in database if database[x]['date_edited'] >= threshold and not x in seen]
        if collection:
            if len(seen)>0:
                print()
            cprint(description.center(width, ' '), 'white', 'on_blue')
            print_columns(collection)
        seen.update(collection)
        if len(seen) > limit:
            break

#------------------------------------------------------------------------------
# main
#------------------------------------------------------------------------------

def usage():
    print('kb ls            list files in clickable column')
    print('kb ls2           list files date menu')
    print('kb new           create new file')
    print('kb #tag          search for tag')
    print('kb update        refresh the database if needed')
    print('kb forceupdate   refresh the database')
    print('kb rfm <file>    read front matter')
    print('kb forget        clear the database')
    print('kb j             create/view today\'s journal')
    print('kb nodate        show files without create date')

if __name__ == '__main__':
    cmd = ''
    if sys.argv[1:]:
        cmd = sys.argv[1]

    arg0 = None
    if sys.argv[2:]:
        arg0 = sys.argv[2]

    if cmd == 'blog':
        gen_blog()
    elif cmd == 'update':
        db_update()
    elif cmd == 'forceupdate':
        db_update(True)
    elif cmd == 'forget':
        db_save({})
    elif cmd == 'dump':
        fname = None
        if sys.argv[2:]:
            fname = sys.argv[2]
        db_print(fname)
    elif cmd == 'ls':
        perform_ls(16 if not arg0 else int(arg0))
    elif cmd == 'ls2':
        perform_ls2(32 if not arg0 else int(arg0))
    elif cmd == 'rfm':
        front_matter = read_front_matter(arg0)
        print(front_matter)

    elif cmd == 'rm':
        src = arg0
        dst = os.path.join('/tmp', src)
        if not os.path.exists(src):
            raise Exception('cannot delete %s, doesn\'t exist' % src)
        print('deleting %s, backup copied to %s' % (src, dst))
        shutil.copyfile(src, dst)
        os.unlink(src)
    elif cmd in ['tags', 'tag', 'lstag', 'lstags', 'lst']:
        perform_ls(1000000, sys.argv[2:])

    # is it a tag? (probably will have to escape this on your shell, like: `kb \#book`)
    elif cmd.startswith('#'):
        perform_ls(1000000, sys.argv[1:])

    elif cmd == 'new':
        fname = gen_fname()
        fpath = os.path.join(PATH_KB, fname)
        initialize_post(fpath)
        edit_file(fpath, 'typora')

    elif cmd in ['journal', 'j']:
        title = 'Journal %s' % epochToISO8601('now')
        fname = gen_fname_journal()
        fpath = os.path.join(PATH_KB, fname)
        if not os.path.exists(fpath):
            print('creating %s' % fpath)
            initialize_post(fpath, title)
            fpath_templ = os.path.join(os.environ['HOME'], 'journal_template.md')
            if os.path.exists(fpath_templ):
                print('appending %s' % fpath_templ)
                open(fpath, 'a+').write(open(fpath_templ, 'r').read())
        print('opening %s' % fpath)
        #edit_file(fpath, 'gvim')
        edit_file(fpath)

    elif cmd == 'test1':
        # show files without metadata
        fnames = [x for x in os.listdir(PATH_KB) if (x.endswith('.md') or x.endswith('.txt'))]
        fpaths = [os.path.join(PATH_KB, x) for x in fnames]
        for fpath in fpaths:
        #for fpath in ['18al.md']:
            fmatter = read_front_matter(fpath)
            if not 'UNIQUE_ID' in fmatter:
                set_front_matter_uid(fpath)
#            if not 'DATE_CREATED' in fmatter:
#                set_front_matter_date_created(fpath, epochToISO8601(get_date_created(fpath)))
#            if not 'DATE_MODIFIED' in fmatter:
#                set_front_matter_date_modified(fpath, epochToISO8601(get_date_edited(fpath)))

    elif cmd == 'test2':
        # show files with old style metadata
        fnames = [x for x in os.listdir(PATH_KB) if (x.endswith('.md') or x.endswith('.txt'))]
        fpaths = [os.path.join(PATH_KB, x) for x in fnames]
        for fpath in fpaths:
            data = None
            with open(fpath) as fp:
                data = fp.read()
                while data.endswith(' ') or data.endswith('\n'):
                    data = data[0:-1]
                if not data.endswith('-->'):
                    continue
                mark = data.rfind('<!--')
                front_matter = data[mark:]
                print(fpath)
                print('OLD FRONT MATTER:')
                print(front_matter)

                lines = front_matter.split('\n')
                lines = [l.strip() for l in lines]
                lines = [l.replace('<!--', '--') for l in lines]
                lines = [l.replace('-->', '--') for l in lines]
                for i in range(len(lines)):
                    if lines[i].startswith('TAGS: '):
                        tmp = lines[i][6:]
                        if '#' in tmp:
                            tmp = tmp.replace('#', '')
                        if not ',' in tmp:
                            tmp = tmp.replace(' ', ',')
                        if '[' in tmp:
                            lines[i] = 'TAGS: %s' % tmp
                        else:
                            lines[i] = 'TAGS: [%s]' % tmp
                        break
                front_matter = '\n'.join(lines)
                print('NEW FRONT MATTER:')
                print(front_matter)

            data = data[0:mark]

            with open(fpath, 'w') as fp:
                fp.write(front_matter)
                fp.write('')
                fp.write(data)

    # assume it's a filename
    elif not cmd:
        usage()
    else:
        fname = cmd
        assert fname
        if not (fname.endswith('.md') or fname.endswith('.txt')):
            fname = fname + '.md'
        if os.path.exists(fname):
            print('opening', fname)
        else:
            print('creating', fname)
            initialize_post(fname)

        edit_file(fname, 'typora')

