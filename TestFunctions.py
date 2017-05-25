import time
import math
a= [2,3,5,1,23,1,2,3,1,4,3,1,4,3,2,8,5,4,2]
def testFunction():
    start_time_1 = time.time()
    print start_time_1
    b = []
    for aa in a:
        b.append(aa)
    print "Mul %s " % (reduce(lambda x,y:x*y,b))
    start_time_2 = time.time()
    print "Difference %s" % (start_time_2-start_time_1)
    start_time_2 = time.time()
    b = []
    for aa in a:
        b.append(math.log10(aa))
    end_time = time.time()
    print "Difference %s" % (end_time - start_time_2)
    print
if __name__=="__main__":
    testFunction()