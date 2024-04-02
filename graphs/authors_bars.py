import os, sys
import numpy as np, pandas as pd
import matplotlib.pyplot as plt

def main(filename):
    datas = pd.read_csv(filename, index_col="No.")
    
    def f(token):
        for each in ("192.168", "255.255"):
            if each in token:
                return False
        return True
    
    sources = datas.get("Source").value_counts().sort_index()
    destinations = datas.get("Destination").value_counts().sort_index()
    
    sub_datas = pd.DataFrame({
        "sources": sources,
        "destinations": destinations
    })
    
    sub_datas.plot.barh(stacked=True)
    plt.show()

if __name__ == "__main__":
    try:
        filename = sys.argv[sys.argv.index("-f") + 1]
    except:
        print("Please set a file '-f <filename>'")
        exit(1)
        
    main(filename=filename)