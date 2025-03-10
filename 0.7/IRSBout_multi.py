import angr,claripy
import os

#############################
# 二进制程序的静态分析工具：
# 分析二进制程序的 IR
# 提取二进制程序的控制流信息（CFG)
# 解析所有基本块的 IR 语句块（IRSB）
#############################
#读取当前路径下的所有二进制文件(可选)
current_directory = os.getcwd()
all_files = os.listdir(current_directory)
#所有文件名
files = [file for file in all_files if os.path.isfile(file) and ('.'not in file or '.exe' in file[-4:])]#只读取没有后缀名的文件
#所有已读取的project
project_list=[]
for filename in files:
    project_list.append(angr.Project("./"+filename,auto_load_libs=False))
#静态控制流图
cfg=[]
for p in project_list:
    cfg.append(p.analyses.CFGFast())
#获取所有的块地址
block_addr_list=[]
for c in cfg:
    block_addr_list.append([node.addr for node in c.nodes()])

#index是block的序号，addr_list是一组入口地址列表。
def typecheck(project):
    if type(project) is str:#传入str
        if project in files:#如果有这个项目
            project=files.index(project)#获取序号
            block_addresses=block_addr_list[project]
            project=project_list[project]#获取项目
            return project,block_addresses
        else:
            print('Do not exist')
            return None
    elif type(project) is int:#传入int
        if project<=len(block_addr_list):
            block_addresses=block_addr_list[project]
            project=project_list[project]
            return project,block_addresses
        else:
            print('Do not exist')
            return None
    else:
        print('?')
        return None
#帮助
def HELP():
    print('函数:\nshow_statements(index_of_project/name_of_project,index_of_block)\nget_statements(index_of_project/name_of_project,index_of_block)\nget_all_statements(index_of_project/name_of_project)(return List of IRSB)\nget_block_counts(index_of_project/name_of_project)')
    print('write_all_to_file(index_of_project/name_of_project,filename)\nwrite_all_stmt_to_file(index_of_project/name_of_project,filename)')
    print('所有文件名-files\n所有已读取的project-project_list\n静态控制流图-cfg\n所有的块地址-block_addr_list\n')
    print('示例1:get_statements(\'test_issue\',15)如果返回值是None则表示索引越界')
    print('示例2:while 1:if get_statements(\'test_issue\',15) is not None:Instructions\n')
    print('有具体需要请使用angr的标准接口，这里只是提供一点方便。\nuse \'HELP()\'for help')
#打印
def show_statements(project=0,index=0):
    project,block_addresses=typecheck(project)
    if project == None:
        return None
    try:
        addr=block_addresses[index]
    except:
        #print('错误：一般是超范围')
        return None
    for i in project.factory.block(addr=addr).vex.statements:
        i.pp()
#获取
#请注意len需要-1才能使用，因为序号从0开始。
def get_block_counts(project=0):
    project,block_addresses=typecheck(project)
    if project == None:
        return None
    return len(block_addresses)
#返回类型是List[statement]
#你可以使用迭代器访问
def get_statements(project=0,index=0):
    project,block_addresses=typecheck(project)
    if project == None:
        return None
    try:
        addr=block_addresses[index]
    except:
        print('错误：一般是超范围')
        return None
    return project.factory.block(addr=addr).vex.statements
#返回类型是List[IRSB]
#你可以使用迭代器访问
#需要注意的是,需要使用result[i]来访问某个块，需要使用result[i].statements[j]来访问具体的语句
def get_all_statements(project=0):
    project,block_addresses=typecheck(project)
    if project == None:
        return None
    result=[]
    for addr in block_addresses:
        result.append(project.factory.block(addr=addr).vex)
    return result
#
def write_all_to_file(project=0,filename=None):
    f=open(filename,'a')
    L=get_all_statements(project)
    for irsb in L:
        text=irsb.__str__()
        f.write(text)
        f.write('\n')
    f.close()
def write_all_stmt_to_file(project=0,filename=None):
    f=open(filename,'a')
    L=get_all_statements(project)#irsb
    for irsb in L:
        f.write('IRSB from:'+str(hex(irsb.addr)+'\n'))
        for stmt in irsb.statements:
            data=stmt.__str__()
            f.write(data)
            f.write('\n')
        f.write('\n')
    f.close()    
        
    
#
HELP()


# 运行这个文件
project = angr.Project("./a2", auto_load_libs=False)
# 输出 x86_64
print(project.arch)
irsb = project.factory.block(0x4011e9).vex
irsb.pp()

print(get_block_counts("c"))
show_statements("c", 10)

all_irsb = get_all_statements("c")
for irsb in all_irsb:
    print(irsb)