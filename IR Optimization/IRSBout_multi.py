import angr,claripy
import os

#############################
# Static analysis tool for binary programs:
# Analyze the IR (Intermediate Representation) of binary programs
# Extract control flow information (CFG) of binary programs
# Parse the IR statement blocks (IRSB) of all basic blocks
#############################
# Read all binary files in the current directory (optional)
current_directory = os.getcwd()
all_files = os.listdir(current_directory)
# All filenames
files = [file for file in all_files if os.path.isfile(file) and ('.'not in file or '.exe' in file[-4:])]# Only read files without an extension or with ".exe" in the last 4 characters
# All loaded projects
project_list=[]
for filename in files:
    project_list.append(angr.Project("./"+filename,auto_load_libs=False))
# Static Control Flow Graphs
cfg=[]
for p in project_list:
    cfg.append(p.analyses.CFGFast())
# Get addresses of all blocks
block_addr_list=[]
for c in cfg:
    block_addr_list.append([node.addr for node in c.nodes()])

# `index` is the block's sequence number; `addr_list` is a list of entry addresses.
def typecheck(project):
    if type(project) is str:
        if project in files:
            project=files.index(project)
            block_addresses=block_addr_list[project]
            project=project_list[project]
            return project,block_addresses
        else:
            print('Do not exist')
            return None
    elif type(project) is int:
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
# Help function
def HELP():
    print('Functions:\nshow_statements(index_of_project/name_of_project,index_of_block)\nget_statements(index_of_project/name_of_project,index_of_block)\nget_all_statements(index_of_project/name_of_project)(return List of IRSB)\nget_block_counts(index_of_project/name_of_project)')
    print('write_all_to_file(index_of_project/name_of_project,filename)\nwrite_all_stmt_to_file(index_of_project/name_of_project,filename)')
    print('All filenames - files\nAll loaded projects - project_list\nStatic control flow graphs - cfg\nAll block addresses - block_addr_list\n')
    print('Example 1: get_statements(\'test_issue\',15). If the return value is None, it indicates an index out of range')
    print('Example 2: while 1: if get_statements(\'test_issue\',15) is not None: Instructions\n')
    print('For specific needs, please use the standard angr interfaces. This is just for convenience.\nUse \'HELP()\' for help')

# Print
def show_statements(project=0,index=0):
    project,block_addresses=typecheck(project)
    if project == None:
        return None
    try:
        addr=block_addresses[index]
    except:
        #print('Wrong')
        return None
    for i in project.factory.block(addr=addr).vex.statements:
        i.pp()

# Get statements
# Note that len needs to subtract 1 before use because the index starts from 0
def get_block_counts(project=0):
    project,block_addresses=typecheck(project)
    if project == None:
        return None
    return len(block_addresses)
# Return type is List[statement]
# You can use an iterator to access
def get_statements(project=0,index=0):
    project,block_addresses=typecheck(project)
    if project == None:
        return None
    try:
        addr=block_addresses[index]
    except:
        print('Wrong')
        return None
    return project.factory.block(addr=addr).vex.statements
# Return type is List[IRSB]
# You can use an iterator to access
# Note: to access a block, use result[i]; to access a specific statement, use result[i].statements[j]
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


# run
project = angr.Project("./a2", auto_load_libs=False)
# x86_64
print(project.arch)
irsb = project.factory.block(0x4011e9).vex
irsb.pp()

print(get_block_counts("counter"))
show_statements("counter", 10)

all_irsb = get_all_statements("counter")
for irsb in all_irsb:
    print(irsb)