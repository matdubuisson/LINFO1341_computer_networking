import os, sys
import numpy as np, pandas as pd
import matplotlib.pyplot as plt

def main(filename):
    datas = pd.read_csv(filename, index_col="No.")

    timing = 1
    n = int(np.max(datas["Time"]) // timing) + 1
    times = {}
    
    for each in datas.iterrows():
        time = float(each[1][0])
        time //= timing
        type = each[1][3]
        
        if times.get(type, None) == None:
            times[type] = [0] * n
        
        times[type][int(time)] += 1
    
    xs = np.arange(0, n, 1)
    
    for type in times.keys():
        plt.plot(xs, times[type])
        
    plt.xlabel("1 unit == {0} seconds".format(timing))
    plt.ylabel("N requests")
    plt.legend(list(times.keys()))
    plt.show()

if __name__ == "__main__":
    try:
        filename = sys.argv[sys.argv.index("-f") + 1]
    except:
        print("Please set a file '-f <filename>'")
        exit(1)
        
    main(filename=filename)