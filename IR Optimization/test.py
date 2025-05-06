import angr,claripy
import copy
import pyvex
import time
#
import deepdiff
#
from invert import list2stmtlist
#

#############################
# Verify correctness of IR statement optimization
# Compare the differences between original and optimized IR
# Verify whether the IR transformation from invert.py is correct
# Use deepdiff to check changes in IR
#############################

# Create instance 1 (original binary project)
project=angr.Project("./a2",auto_load_libs=False)
# Create instance 2 (IR loaded from file)
file=open('./branching.txt')
IRSB_list=file.read().split('\n')
file.close()
irsb_old=project.factory.block(addr=0x4011e9).vex
result=list2stmtlist(IRSB_list,irsb_old)

for i in result.statements:
    print(i)

diff=deepdiff.DeepDiff(irsb_old,result)
print(diff)