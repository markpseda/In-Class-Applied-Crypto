import read_params
from read_params import params

x, y = params['Gener']

A = params['A']
B = params['B']

P = params['Prime']

first = x * x * x + A * x + B - y*y
second = first % P

print("=============")
print(first)
print("=============")
print(second)
print("=============")