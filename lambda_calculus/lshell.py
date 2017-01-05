#!/usr/bin/env python

import os
import sys

###############################################################################
# TOKENIZING STUFF
###############################################################################
class TID:
	LAMBDA,LCID,DOT,SPACE = range(4)

class Token:
	def __init__(self,ident,val=None):
		self.ident, self.val = ident, val

	def __str__(self):
		if self.ident == TID.LAMBDA: return "LAMBDA"
		if self.ident == TID.DOT: return "DOT"
		if self.ident == TID.SPACE: return "SPACE"
		if self.ident == TID.LCID: return "LCID\"%s\"" % self.val
		raise("unknown token id: %d" % self.ident)

class TokenManager:
	def __init__(self, tokenList):
		self.tokenList = tokenList
		self.i = 0

	def reset(self):
		self.i = 0

	def peek(self, nAhead=0):
		if (self.i + nAhead) >= len(self.tokenList):
			return None
		return self.tokenList[self.i + nAhead]
	
	def consume(self):
		if (self.i) >= len(self.tokenList):
			return None
		return self.tokenList[self.i]

	def isDone(self):
		return self.peek() == None

	def __str__(self):
		result = []
		for k in range(self.i, len(self.tokenList)):
			result.append("%d: %s" % (k, str(self.tokenList[k])))
		return "\n".join(result)

def tokenize(line):
	tokens = []
	line = line.rstrip()
	chars = list(line)

	i = 0
	while i < len(chars):
		c = chars[i]
		if c == '\\':
			tokens.append(Token(TID.LAMBDA))
			i += 1
		elif c.isspace():
			tokens.append(Token(TID.SPACE))
			while i<len(chars) and chars[i].isspace():
				i += 1
		elif c == '.':
			tokens.append(Token(TID.DOT))
			i += 1
		elif c.islower():
			value = ''
			while i<len(chars) and chars[i].isalpha():
				value += chars[i]
				i += 1
			tokens.append(Token(TID.LCID, value))
		else:
			raise("tokenizing on \"%s...\"" % chars[i:i+8])

	return TokenManager(tokens)

###############################################################################
# PARSING
###############################################################################

class Term:
	def __init__(self):
		pass

class Variable(Term):
	def __init__(self, name):
		self.name = name

class Abstraction(Term):
	def __init__(self, variable, term):
		self.variable = variable
		self.term = term

class Application(Term):
	def __init__(self, termA, termB):
		self.termA = termA
		self.termB = termB

def parse(tokens):
	pass

###############################################################################
# MAIN
###############################################################################
if __name__ == '__main__':
	for line in sys.stdin:
		tokenMgr = tokenize(line)

		print tokenMgr
