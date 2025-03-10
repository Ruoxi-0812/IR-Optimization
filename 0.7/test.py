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
# 验证 IR 语句优化是否正确
# 比较优化前后的 IR 差异，验证 invert.py 的 IR 语句转换是否正确。
# 对比原始 IR 和优化后的 IR
# 使用 deepdiff 检查 IR 变化
#############################

#创建实例1
project=angr.Project("./a2",auto_load_libs=False)
#创建实例2
file=open('./IR1.txt')
IRSB_list=file.read().split('\n')
file.close()
irsb_old=project.factory.block(addr=0x4011e9).vex
result=list2stmtlist(IRSB_list,irsb_old)

for i in result.statements:
    print(i)

diff=deepdiff.DeepDiff(irsb_old,result)
print(diff)