#!/usr/bin/env python

import os
import sys

###############################################################################
# TOKENIZING STUFF
###############################################################################
class TID:
	LAMBDA,LCID,DOT,LPAREN,RPAREN = range(5)

class Token:
	def __init__(self,ident,val=None):
		self.ident, self.val = ident, val

	def __str__(self):
		lookup = {TID.LAMBDA:'LAMBDA', TID.LCID:'LCID', TID.DOT:'DOT', \
			TID.LPAREN:'LPAREN', TID.RPAREN:'RPAREN'}

		if self.ident == TID.LCID:
			return 'LCID"%s"' % self.val
		elif self.ident in lookup:
			return lookup[self.ident]
		else:
			raise("unknown token id: %d" % self.ident)

	def __eq__(self, lhs):
		# can compare directly to ints
		if type(lhs) == type(self.ident):
			return lhs == self.ident

		# or to other tokens
		return self.ident == lhs.ident and \
			self.val == lhs.val

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
	
	def consume(self, expected=None):
		if self.isEnd():
			raise("token list is empty")

		tok = self.tokenList[self.i]
		self.i += 1

		if expected and tok != expected:
			raise("expected token %s but got instead %s" % (expected, tok))
		
		return tok	

	def isEnd(self):
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
		elif c == '(':
			tokens.append(Token(TID.LPAREN))
			i += 1
		elif c == ')':
			tokens.append(Token(TID.RPAREN))
			i += 1
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

#------------------------------------------------------------------------------

def parse_prec0(tokenMgr):
	if tokenMgr.peek() == TID.LAMBDA:
		tokenMgr.consume(TID.LAMBDA)
		var = Variable( tokenMgr.consume(TID.LCID).val )
		tokenMgr.consume(TID.DOT)
		term = parse_prec0(tokenMgr)
		return Abstraction(var, term)
	else:
		return parse_prec1(tokenMgr)

def parse_prec1(tokenMgr):
	tmp = parse_prec2(tokenMgr)
	
def parse_prec1_(tokenMgr):
	if not tokenMgr.isDone():
		parse_prec0(tokenMgr)
		
def parse_prec2(tokenMgr):
	if tokenMgr.peek() == TID.LPAREN:
		tokenMgr.consume(TID.LPAREN)
		term = parse_prec0(tokenMgr)
		tokenMgr.consume(TID.RPAREN)
	elif tokenMgr.peek() == TID.LCID:
		return Variable( tokenMgr.consume(TID.LCID).val )
	else:
		raise("expected open parenthesis or lcid")

def parse(tokenMgr):
	parseTree = parse_prec0(tokenMgr)

	if tokenMgr.isEnd():
		return parseTree

	raise("parse is done, but tokens remain %s...", tokenMgr.peek())

###############################################################################
# MAIN
###############################################################################
if __name__ == '__main__':
	for line in sys.stdin:
		line = line.rstrip()

		print "input: " + line

		tokenMgr = tokenize(line)

		print tokenMgr
