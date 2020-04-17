#!/usr/bin/env python3

def tag_to_color(tag):
	(fgBlack, fgWhite, fgDefault) = ('\x1B[30m', '\x1B[97m', '\x1B[39m')
	(bgRed, bgGreen, bgOrange, bgBlue, bgPurple, bgCyan, bgLightGray,
	  bgDarkGray, bgLightRed, bgLightGreen, bgYellow, bgLightBlue,
	  bgLightPurple, bgLightCyan, bgWhite, bgDefault) = ('\x1B[41m', '\x1B[42m',
	  '\x1B[43m', '\x1B[44m', '\x1B[45m', '\x1B[46m', '\x1B[47m', '\x1B[100m',
	  '\x1B[101m', '\x1B[102m', '\x1B[103m', '\x1B[104m', '\x1B[105m',
	  '\x1B[106m', '\x1B[107m', '\x1B[49m')

	c1 = fgWhite + bgRed
	c2 = fgWhite + bgGreen
	c3 = fgWhite + bgOrange
	c4 = fgWhite + bgBlue
	c5 = fgWhite + bgPurple
	c6 = fgBlack + bgCyan
	c7 = fgBlack + bgLightGray
	c8 = fgWhite + bgDarkGray
	c9 = fgWhite + bgLightRed
	c10 = fgBlack + bgLightGreen
	c11 = fgBlack + bgYellow
	c12 = fgBlack + bgLightBlue
	c13 = fgBlack + bgLightPurple
	c14 = fgBlack + bgLightCyan
	c15 = fgBlack + bgWhite
	cDefault = fgDefault + bgDefault

	colors = [c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15]

	return colors[sum(map(ord, list(tag))) % len(colors)]

