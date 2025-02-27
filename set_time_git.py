#!/usr/bin/env python

# based on:
# https://stackoverflow.com/questions/78174010/what-is-the-most-efficient-method-to-get-the-last-modification-time-of-every-fil

import os
import sys
import time
import datetime
import subprocess

commit = "HEAD"

start = time.time()

# Collect all files actually managed by git.
# git ls-tree -r --name-only HEAD
commit_paths = set(subprocess.check_output(["git", "ls-tree", "-r", "--name-only", commit], text=True).strip().split('\n'))

print(f"[{time.time() - start:.4f}] git ls-tree finished")

print('\n'.join(commit_paths))

path_times = {}

# git log --name-status --pretty=time=%cI
git_log_out = subprocess.check_output(["git", "log", "--name-status", '--pretty=time=%cI'], text=True).splitlines()
current_time = None
for line in git_log_out:
    if not line:
        continue
    if line.startswith("time="):
        current_time = datetime.datetime.fromisoformat(line.removeprefix("time="))
        # current_time: datetime.datetime object
        continue

    assert current_time is not None
    
    mod_type, path = line.split('\t', maxsplit=1)
    # Added (A)
    # Copied (C)
    # Deleted (D)
    # Modified (M)
    # Renamed (R)
    # have their type (i.e. regular file, symlink, submodule, ) changed (T)
    # are Unmerged (U)
    # are Unknown (X)
    # or have had their pairing Broken (B)
    if mod_type != 'M':
        continue

    if path in commit_paths and path not in path_times:
        print(f'file {path} will be set to {current_time}')
        path_times[path] = current_time

print(f"[{time.time() - start:.4f}] git log finished")

counter = 0
for path, time_ in path_times.items():
    print(f'setting modified time of -{path}- to: {time_}')

    atime = os.path.getatime(path)
    mtime = time_.timestamp()

    os.utime(path, (atime, mtime))

    if (counter := counter+1) > 4:
        break

