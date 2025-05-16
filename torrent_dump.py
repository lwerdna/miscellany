#!/usr/bin/env python

import sys
import pprint
import hashlib
import bencodepy

def torrent2dict(fpath):
    with open(fpath, 'rb') as f:
        return bencodepy.decode(f.read())

def get_name(fpath):
    tdict = torrent2dict(fpath)
    tinfo = tdict[b'info']
    return tinfo[b'name'].decode('utf-8')

def dump(fpath):
    tdict = torrent2dict(fpath)

    import pprint
    pprint.pprint(tdict)

def extract_filenames_and_hashes(torrent_file_path):
    # Load and decode the torrent file
    with open(torrent_file_path, 'rb') as f:
        torrent_data = f.read()

    torrent_dict = bencodepy.decode(torrent_data)

    # Extract the 'info' dictionary which contains the file metadata
    info_dict = torrent_dict[b'info']
    pprint.pprint(info_dict)

    breakpoint()

    # Compute the info hash (SHA1 hash of the 'info' dictionary)
    raw_info = torrent_dict[b'info']
    info_hash = hashlib.sha1(bencodepy.encode(raw_info)).hexdigest()
    print(f'Info Hash: {info_hash}')

    # Get the piece length and the pieces hashes
    piece_length = info_dict[b'piece length']
    pieces = info_dict[b'pieces']

    # Decode file names and paths (they can be nested for multi-file torrents)
    files = []
    if b'files' in info_dict:
        for file in info_dict[b'files']:
            path = "/".join([part.decode() for part in file[b'path']])
            files.append(path)
    else:
        # Single file torrent, just take the file name from the path
        files.append(info_dict[b'name'].decode())

    # Print the filenames
    print(f"Files in torrent (total pieces: {len(pieces) // 20}):")
    for file in files:
        print(f" - {file}")

    # Print the hashes for the pieces
    print(f"\nPiece hashes (first 5 shown):")
    for i in range(0, min(5, len(pieces) // 20)):  # Just show first 5 for brevity
        piece_hash = pieces[i * 20: (i + 1) * 20]  # Each piece hash is 20 bytes (160 bits)
        print(f"Piece {i + 1}: {piece_hash.hex()}")

def usage():
    print('read the source')
    exit(-1)

if __name__ == '__main__':
    cmd, fpath = sys.argv[1:]
    if cmd in ['getname', 'get_name']:
        print(get_name(fpath))

    if cmd == 'dump':
        dump(fpath)

    if cmd in ['dumpinfo', 'dump_info']:
        dump(fpath)

    #extract_filenames_and_hashes(sys.argv[1])
