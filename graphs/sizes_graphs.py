import os, sys
import numpy as np, pandas as pd
import matplotlib.pyplot as plt

def main(filename):
    datas = pd.read_csv(filename, index_col="No.")
    
    accuracy = 1
    
    times = np.array(datas.get("Time")) // accuracy
    n = int(np.max(times)) + 1
    
    protocols = list(datas.get("Protocol"))
    lengths = list(datas.get("Length"))
    
    d = {}
    
    for i in range(len(protocols)):
        if d.get(protocols[i], None) == None:
            d[protocols[i]] = [0] * n
        
        j = int(times[i])
        value = d[protocols[i]][j]
        d[protocols[i]][j] = (value + lengths[i]) / 2
        
    xs = np.arange(0, n, 1)
        
    for key in d.keys():
        plt.plot(xs, d[key])
        
    plt.legend(tuple(d.keys()))
        
    plt.show()

if __name__ == "__main__":
    try:
        filename = sys.argv[sys.argv.index("-f") + 1]
    except:
        print("Please set a file '-f <filename>'")
        exit(1)
        
    main(filename=filename)
