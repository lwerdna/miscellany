#!/usr/bin/env python

import os
import sys
import pdb

###############################################################################
# TOKENIZING STUFF
###############################################################################
class TID:
	LAMBDA,LCID,DOT,LPAREN,RPAREN = range(5)

	@staticmethod
	def id2str(ident):
		lookup = {TID.LAMBDA:'LAMBDA', TID.LCID:'LCID', TID.DOT:'DOT', \
			TID.LPAREN:'LPAREN', TID.RPAREN:'RPAREN'}
		if not ident in lookup:
			raise Exception("unknown token id: %d" % ident)
		return lookup[ident]
	
class Token:
	def __init__(self,ident,val=None):
		self.ident, self.val = ident, val

	def __str__(self):
		lookup = {TID.LAMBDA:'LAMBDA', TID.LCID:'LCID', TID.DOT:'DOT', \
			TID.LPAREN:'LPAREN', TID.RPAREN:'RPAREN'}

		if self.ident == TID.LCID:
			return 'LCID"%s"' % self.val
		else:
			return TID.id2str(self.ident)

	def __eq__(self, rhs):
		result = None

		if rhs == None:
			result = False
		# can compare directly to ints
		elif type(rhs) == type(self.ident):
			result = rhs == self.ident
		# or to other tokens
		else:
			result = self.ident == rhs.ident and self.val == rhs.val

		return result

	def __ne__(self, rhs):
		return not self.__eq__(rhs)

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
	
	def consume(self, expectTid=None):
		if self.isEnd():
			raise Exception("token list is empty")

		tok = self.tokenList[self.i]
		self.i += 1

		if expectTid != None and tok != expectTid:
			raise Exception("expected token %s but got instead %s" % (TID.id2str(expectTid), tok))
		
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
			raise Exception("tokenizing on \"%s...\"" % chars[i:i+8])

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

	def printTree(self, depth=0):
		print ' ' * 2*depth,
		print 'Variable "%s"' % self.name

class Abstraction(Term):
	def __init__(self, variable, term):
		self.variable = variable
		self.term = term

	def printTree(self, depth=0):
		print ' ' * 2*depth,
		print 'Abstraction'
		self.variable.printTree(depth+1)
		self.term.printTree(depth+1)

class Application(Term):
	def __init__(self, termA, termB):
		self.termA = termA
		self.termB = termB

	def printTree(self, depth=0):
		print ' ' * 2*depth,
		print 'Application'
		self.termA.printTree(depth+1)
		self.termB.printTree(depth+1)

#------------------------------------------------------------------------------

def parse_prec0(mgr):
	if mgr.peek() == TID.LAMBDA:
		mgr.consume(TID.LAMBDA)
		var = Variable( mgr.consume(TID.LCID).val )
		mgr.consume(TID.DOT)
		term = parse_prec0(mgr)
		return Abstraction(var, term)
	else:
		return parse_prec1(mgr)

def parse_prec1(mgr):
	p2 = parse_prec2(mgr)
	p1 = parse_prec1_(mgr)
	
	if p1:
		return Application(p2, p1)
	else:
		return p2
	
def parse_prec1_(mgr):
	if mgr.isEnd(): # empty string
		return None
	p0 = parse_prec0(mgr)
	p1 = parse_prec1_(mgr)
	if p1:
		return Application(p0, p1)
	return p0
		
def parse_prec2(mgr):
	tok = mgr.peek()
	if tok == TID.LPAREN:
		mgr.consume(TID.LPAREN)
		term = parse_prec0(mgr)
		mgr.consume(TID.RPAREN)
	elif tok == TID.LCID:
		return Variable( mgr.consume(TID.LCID).val )
	else:
		raise Exception("expected open parenthesis or lcid (got instead: %s)" % tok)

# can never get these parsers perfect myself
#  thanks to: int-e, monochrom, tadeuzagallo
def parse(mgr):
	parseTree = parse_prec0(mgr)

	if mgr.isEnd():
		return parseTree

	raise Exception("parse is done, but tokens remain %s...", mgr.peek())

###############################################################################
# MAIN
###############################################################################
if __name__ == '__main__':
	for line in sys.stdin:
		line = line.rstrip()

		print "input: " + line

		tokenMgr = tokenize(line)
		print 'tokens'
		print '------'
		print tokenMgr

		print ''

		ast = parse(tokenMgr)
		print 'parse tree'
		print '----------'
		print ast.printTree()
