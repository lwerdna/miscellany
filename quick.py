#!/usr/bin/env python

import os, sys, re

import colorama
from colorama import Fore, Back, Style

options = [
    ('1.0', 'github: arch-arm64', lambda: os.system('open https://github.com/Vector35/arch-arm64')),
    ('1.1', 'github: arch-armv7', lambda: os.system('open https://github.com/Vector35/arch-armv7')),

    ('2.0', 'aarch64 documentation', lambda: os.system('open file:///Users/andrewl/Downloads/A64_ISA_xml_v9A-2021-03/ISA_A64_xml_v9A-2021-03/xhtml/')),
    ('2.1', 'aarch32 documentation', lambda: os.system('open file:///Users/andrewl/Downloads/AArch32_ISA_xml_v87A-2020-12/ISA_AArch32_xml_v87A-2020-12/xhtml/')),

]

palette = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]

if __name__ == '__main__':
    colorama.init()

    if sys.argv[1:]:
        sc = sys.argv[1]

        for (shortcut, descr, func) in options:
            if shortcut.replace('.','') == sc:
                func()
                break
        else:
            print('ERROR: shortcut %s not found' % sc)

    else:
        for (shortcut, descr, func) in options:
            color = palette[int(shortcut[0])]
            print(shortcut, color + descr + Style.RESET_ALL)
            #print(color + shortcut + Style.RESET_ALL, descr)
