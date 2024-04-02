import os, sys
import numpy as np, pandas as pd
import matplotlib.pyplot as plt

def main(filename):
    datas = pd.read_csv(filename, index_col="No.")

if __name__ == "__main__":
    try:
        filename = sys.argv[sys.argv.index("-f") + 1]
    except:
        print("Please set a file '-f <filename>'")
        exit(1)
        
    main(filename=filename)