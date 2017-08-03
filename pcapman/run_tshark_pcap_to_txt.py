#! /usr/bin/env python

'''
Convert a pcap data file to text.
Usage : run_tshark_pcap_to_txt <inputfile> <outputdir>

inputfile is the input data file you are converting. the full path is required.
outputdir is the directory inwhich the text file is stored. 

'''
 
import sys
import getopt

from tshark_pcap_to_txt import dat_to_txt

def main():
    # parse command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.error, msg:
        print msg
        print "for help use --help"
        sys.exit(2)
    # process options
    for o, a in opts:
        if o in ("-h", "--help"):
            print __doc__
            sys.exit(0)
    # process arguments
    print args
    try :
        dat_to_txt(str(args[0]),str(args[1]))
    except IndexError :
        dat_to_txt(str(args[0]))

if __name__ == "__main__":
    main()
