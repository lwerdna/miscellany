#!/usr/bin/env python3

# goal: type "ctimeit" to quickly get an environment to comparison test two execution times

import os
import sys

boilerplate = '''#include <stdio.h>
#include <stdlib.h>

#include <time.h> 
#include <sys/time.h> 

#define DATA_SIZE 100000000
int data[DATA_SIZE];

void init(void)
{
	int i;
	srand(time(NULL));
	for(i=0; i<DATA_SIZE; ++i)
		data[i] = rand();
}

int method0(void)
{
	int i, result = 3;
	for(i=0; i<DATA_SIZE; ++i)
		result += data[i];
	return result;
}

int method1(void)
{
	int i, result = 3;
	for(i=0; i<(DATA_SIZE/2); ++i)
		result = result + data[i] + data[DATA_SIZE-1-i];
	return result;
}

void time_method0()
{
	double delta;
	struct timespec t0,t1;
	
	clock_gettime(CLOCK_MONOTONIC, &t0);
	printf("method0(): %d\\n", method0());
	clock_gettime(CLOCK_MONOTONIC, &t1);

	delta = (double)(t1.tv_nsec - t0.tv_nsec) / 1000000000.0;
	delta += (double)t1.tv_sec - t0.tv_sec;
	printf("method0() took %f wallclock seconds\\n", delta);
}

void time_method1()
{
	double delta;
	struct timespec t0,t1;
	
	clock_gettime(CLOCK_MONOTONIC, &t0);
	printf("method1(): %d\\n", method1());
	clock_gettime(CLOCK_MONOTONIC, &t1);

	delta = (double)(t1.tv_nsec - t0.tv_nsec) / 1000000000.0;
	delta += (double)t1.tv_sec - t0.tv_sec;
	printf("method1() took %f wallclock seconds\\n", delta);
}

int main(int ac, char **av)
{
	init();
	time_method0();
	time_method1();
}
'''

fpath = '/tmp/ctimeit.c'
if sys.argv[1]:
    fpath = sys.argv[1]

print(f'writing {fpath}')
with open(fpath, 'w') as fp:
	fp.write(boilerplate)

#os.system('chmod +x %s' % fpath)
os.system('open -a macvim ' + fpath)
#os.system('open -a geany ' + fpath)

