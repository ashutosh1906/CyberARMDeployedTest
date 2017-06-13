from z3 import *

smt = Solver()
a = [Int('a_%s'%(i)) for i in range(5)]
print a
cons = ([a[i]==0 for i in range(5)])
smt.add(cons)
cons_re = ([(a[i]==(a[i]+1)) for i in range(5)])
smt.add(cons_re)

satisfiability = smt.check()
if satisfiability == z3.sat:
    print "Model is ---> "
    recommended_CDM = smt.model()

print recommended_CDM