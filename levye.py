#!/usr/bin/env python

__VERSION__ = '0.1'
__AUTHOR__ = 'Galkan'
__DATE__ = '16.07.2014'

try:
	from lib.main import Main
except ImportError,e:
        import sys
        sys.stdout.write("%s\n" %e)
        sys.exit(1)


if __name__ == "__main__":

	levye = Main()
	levye.run(levye.args.brute)
