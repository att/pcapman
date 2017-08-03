#This code loads csv files into dataframes 

import os  
import sys
import pandas as pd
import numpy as np
import datetime as datetime

def PandasLoader(afile,names = [],size=1000, sep="\t"):
    if not os.path.isfile(afile):
        print "Error in reading Input File. Please specifiy correct file and directory for input"
        #retun None
    else:
        #bfile = GetTop(afile,size)
        if len(names) > 0:
            pandf=pd.read_csv(afile, names=names, sep=sep, nrows = size, header = 1)
        else:
            pandf=pd.read_csv(afile, sep=sep, nrows = size)
        return pandf
