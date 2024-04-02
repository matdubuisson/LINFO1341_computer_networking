import numpy as np, pandas as pd
import matplotlib.pyplot as plt

# speed = [0.1, 17.5, 40, 48, 52, 69, 88]

# lifespan = [2, 8, 70, 1.5, 25, 12, 28]

# index = ['snail', 'pig', 'elephant',

#          'rabbit', 'giraffe', 'coyote', 'horse']

# df = pd.DataFrame({'speed': speed,

#                    'lifespan': lifespan}, index=index)

# ax = df.plot.barh()

dic = {}

with open("dns_names.txt", "r") as f:
    for line in f.readlines():
        id, name, count, is_cname = line.split(",")
        id = int(id)
        count = int(count)
        is_cname = is_cname.strip()
        
        if dic.get(name, None) == None:
            dic[name] = [0, 0, 0]
        
        if id == 0:
            dic[name][0] += count
        elif is_cname == "True":
            dic[name][2] += count
        else:
            dic[name][1] += count

q = []
a = []
ac = []

for key in dic.keys():
    x, y, z = dic[key]
    q.append(x)
    a.append(y)
    ac.append(z)

df = pd.DataFrame({
    "queries": q,
    "answers": a,
    "answers to cname": ac
}, index=list(dic.keys()))

df.plot.barh(stacked=False)
plt.show()