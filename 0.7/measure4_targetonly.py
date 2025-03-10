import angr,claripy
import copy
import pyvex
import time
from invert import list2stmtlist
import logging

#############################
# 动态符号执行 
# 使用 动态符号执行（DSE） 执行目标程序，同时 测量 IRSB 的执行时间，优化执行效率。
# 使用 invert.py 的优化 IR 进行动态符号执行（DSE），并 记录 IR 语句的执行时间。
# 通过 循环运行 DSE 100 次，计算平均执行时间，验证优化是否有效。
############################
#logging.getLogger('angr').setLevel(logging.DEBUG)
############################
#计时器存储区(addr,time_used)
block=[]#for process
block_track=[]
############################
#预设变量
#需要测量的块的起始地址
block_addr=0x4011e9
#文件地址
file_path="./a2"
#IR替换文件位置
IRfile_path='./IR1.txt'
############################
#创建实例
project=angr.Project(file_path,auto_load_libs=False)
#创建IRSB结构
file=open(IRfile_path)
IRSB_list=file.read().split('\n')
file.close()
irsb_old=project.factory.block(addr=block_addr).vex
result=list2stmtlist(IRSB_list,irsb_old)
############################
##HOOK声明区域

############################process
old_process=copy.deepcopy(angr.engines.SuccessorsMixin.process)
def hook_process(self, state, *args, **kwargs):#处理一个block
    r=old_process(self, state, *args, **kwargs)
    return r
############################syscall
old_process_successors_syscall=copy.deepcopy(angr.engines.SimEngineSyscall.process_successors)
def hook_process_successors_syscall(self, successors, **kwargs):
    r=old_process_successors_syscall(self, successors, **kwargs)
    return r
############################unicorn
old_process_successors_unicorn=copy.deepcopy(angr.engines.SimEngineUnicorn.process_successors)
def hook_process_successors_unicorn(self, successors, **kwargs):
    r=old_process_successors_unicorn(self, successors, **kwargs)
    return r
old__execute_symbolic_instrs=copy.deepcopy(angr.engines.SimEngineUnicorn._execute_symbolic_instrs)
def hook__execute_symbolic_instrs(self, syscall_data):
    r=old__execute_symbolic_instrs(self, syscall_data)
    return r
old__execute_block_instrs_in_vex=copy.deepcopy(angr.engines.SimEngineUnicorn._execute_block_instrs_in_vex)
def hook__execute_block_instrs_in_vex(self, block_details):
    #print('<_execute_block_instrs_in_vex>')
    r=old__execute_block_instrs_in_vex(self, block_details)
    return r
############################heavy
old_process_successors_heavy=copy.deepcopy(angr.engines.HeavyVEXMixin.process_successors)
def hook_process_successors_heavy(self, successors, **kwargs):
    r=old_process_successors_heavy(self, successors, **kwargs)
    return r
############################faliure
old_process_successors_failure=copy.deepcopy(angr.engines.SimEngineFailure.process_successors)
def hook_process_successors_failure(self, successors, **kwargs):
    r=old_process_successors_failure(self, successors, **kwargs)
    return r
############################hooks
old_process_successors_hooks=copy.deepcopy(angr.engines.HooksMixin.process_successors)
def hook_process_successors_hooks(self, successors, **kwargs):
    r=old_process_successors_hooks(self, successors, **kwargs)
    return r
############################track
old_process_successors_track=copy.deepcopy(angr.engines.TrackActionsMixin.process_successors)
def hook_process_successors_track(self, successors, **kwargs):
    r=old_process_successors_track(self, successors, **kwargs)
    return r
    #its from heavy,but used here
old_handle_vex_block=copy.deepcopy(angr.engines.HeavyVEXMixin.handle_vex_block)
def hook_handle_vex_block(self, irsb):
    global block_track
    start2=time.time()
    r=old_handle_vex_block(self, irsb)
    end2=time.time()
    time_used=round((end2-start2)*1000,2)
    if irsb.addr==block_addr:
        addr=hex(irsb.addr)
        block_track.append((addr,time_used))
        #print(addr,time_used,'ms')
    return r
old__handle_vex_stmt=copy.deepcopy(angr.engines.HeavyVEXMixin._handle_vex_stmt)
def hook__handle_vex_stmt(self, stmt):
    try:
        r=old__handle_vex_stmt(self, stmt)
    except Exception as e:
        print('<_handle_vex_stmt>',stmt)
        print(f"An error occurred: {e}")
    return r
old__handle_vex_expr=copy.deepcopy(angr.engines.HeavyVEXMixin._handle_vex_expr)
def hook__handle_vex_expr(self, expr):
    try:
        r=old__handle_vex_expr(self, expr)
    except Exception as e:
        print('<_handle_vex_expr>',expr)
        print(f"An error occurred: {e}")
    return r
#lift
old_lift_vex=copy.deepcopy(angr.engines.HeavyVEXMixin.lift_vex)
def hook_lift_vex(
self,
addr=None,
state=None,
clemory=None,
insn_bytes=None,
offset=None,
arch=None,
size=None,
num_inst=None,
traceflags=0,
thumb=False,
extra_stop_points=None,
opt_level=None,
strict_block_end=None,
skip_stmts=False,
collect_data_refs=False,
cross_insn_opt=None,
load_from_ro_regions=False,
 **kwargs  
):
    if addr==block_addr:
        #print('lift_vex:',addr,state,clemory,insn_bytes,offset,arch,size,num_inst,traceflags,thumb,extra_stop_points,opt_level,strict_block_end,skip_stmts,collect_data_refs,cross_insn_opt,load_from_ro_regions)
        #r=result
        r=old_lift_vex(self,addr,state,clemory,insn_bytes,offset,arch,size,num_inst,traceflags,thumb,extra_stop_points,opt_level,strict_block_end,skip_stmts,collect_data_refs,cross_insn_opt,load_from_ro_regions,**kwargs)
    else:
        r=old_lift_vex(self,addr,state,clemory,insn_bytes,offset,arch,size,num_inst,traceflags,thumb,extra_stop_points,opt_level,strict_block_end,skip_stmts,collect_data_refs,cross_insn_opt,load_from_ro_regions,**kwargs)
    #r.pp()
    return r
############################soot
old_process_successors_soot=copy.deepcopy(angr.engines.SootMixin.process_successors)
def hook_process_successors_soot(self, successors, **kwargs):
    #print('soot')
    r=old_process_successors_soot(self, successors, **kwargs)
    return r
#

############################
#替换声明区域
angr.engines.SuccessorsMixin.process=hook_process
angr.engines.SimEngineSyscall.process_successors=hook_process_successors_syscall
angr.engines.SimEngineUnicorn.process_successors=hook_process_successors_unicorn
angr.engines.HeavyVEXMixin.process_successors=hook_process_successors_heavy
angr.engines.SimEngineFailure.process_successors=hook_process_successors_failure
angr.engines.HooksMixin.process_successors=hook_process_successors_hooks
angr.engines.TrackActionsMixin.process_successors=hook_process_successors_track
angr.engines.SootMixin.process_successors=hook_process_successors_soot

#angr.engines.SimEngineUnicorn._execute_symbolic_instrs=hook__execute_symbolic_instrs
#angr.engines.SimEngineUnicorn._execute_block_instrs_in_vex=hook__execute_block_instrs_in_vex

angr.engines.HeavyVEXMixin.handle_vex_block=hook_handle_vex_block
angr.engines.HeavyVEXMixin._handle_vex_stmt=hook__handle_vex_stmt
angr.engines.HeavyVEXMixin._handle_vex_expr=hook__handle_vex_expr
angr.engines.HeavyVEXMixin.lift_vex=hook_lift_vex


############################
#执行
def analyze():#输出一个用时#analyze会输出什么取决于blocktrack里有什么。
    global block_track
    block_track=[]#清空block_track

    #simgr的初始化必须在此处进行
    initial_state=project.factory.entry_state()
    simgr = project.factory.simulation_manager(initial_state)
    simgr.explore(find=0x4012a4)
    
    for i in range(len(block_track)):
        if block_track[i]==(-1,-1):#快速识别
            continue
        for j in range(i+1,len(block_track)):#j一定在i之后
            if block_track[j][0]==block_track[i][0]:#出现重复addr，因为已排序，所以新的block一定更快
                block_track[j]=(-1,-1)#清除
    block_track.sort(key=lambda x: x[1], reverse=True)#把被清除的排在最后
    for i in range(len(block_track)-1,-1,-1):#从后往前
        if block_track[i]==(-1,-1):
            block_track.pop()
    #for i in block_track:
    #    print(i)
    return block_track[0][1]





############################
#统计
for i in range(100):#100次，每10次取平均算一次
    r=0
    for j in range(10):
        t=analyze()
        r+=t
    r=r/10
    print(r)

analyze()
