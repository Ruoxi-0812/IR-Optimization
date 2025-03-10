import angr
import os
import pyvex
import time

# 读取当前路径下的所有二进制文件
current_directory = os.getcwd()
all_files = os.listdir(current_directory)
files = [file for file in all_files if os.path.isfile(file) and ('.' not in file or '.exe' in file[-4:])]

# 所有已读取的project
project_list = []
for filename in files:
    project_list.append(angr.Project("./" + filename, auto_load_libs=False))

# 静态控制流图
cfg = []
for p in project_list:
    cfg.append(p.analyses.CFGFast())

# 获取所有的块地址
block_addr_list = []
for c in cfg:
    block_addr_list.append([node.addr for node in c.nodes()])

# 检查项目和块地址
def typecheck(project):
    if isinstance(project, str):
        if project in files:
            project = files.index(project)
            block_addresses = block_addr_list[project]
            project = project_list[project] #获取项目
            return project, block_addresses
        else:
            print('Project does not exist.')
            return None
    elif isinstance(project, int):
        if project < len(block_addr_list):
            block_addresses = block_addr_list[project]
            project = project_list[project]
            return project, block_addresses
        else:
            print('Project does not exist.')
            return None

# 识别IR中的无用语句
# 根据语句类型更新或检测无用语句
def identify_redundant_statements(statements):
    used_temps = set()
    redundant_statements = []

    def extract_temps(expr):
        temps = set()
        if isinstance(expr, pyvex.expr.RdTmp):
            temps.add(expr.tmp)
        elif hasattr(expr, "args"):
            for arg in expr.args:
                temps.update(extract_temps(arg))
        return temps

    for stmt in reversed(statements):
        if isinstance(stmt, pyvex.stmt.WrTmp):
            # 如果语句是写入临时变量
            if stmt.tmp not in used_temps:
                redundant_statements.append(stmt)
            else:
                used_temps.update(extract_temps(stmt.data))
        elif isinstance(stmt, pyvex.stmt.Put):
             # 如果语句是写入寄存器，提取数据中的临时变量
            used_temps.update(extract_temps(stmt.data))
        elif isinstance(stmt, pyvex.stmt.Store):
            # 如果语句是存储到内存，提取存储地址和数据中的临时变量
            used_temps.update(extract_temps(stmt.addr))
            used_temps.update(extract_temps(stmt.data))
        elif isinstance(stmt, pyvex.stmt.Exit):
            # 如果语句是条件跳转，提取跳转条件中的临时变量
            used_temps.update(extract_temps(stmt.guard))

    return list(reversed(redundant_statements))

# 删除无用语句，保留必要的IR指令。
# 执行优化后的 IR
def execute_optimized_ir(project, block_addr, optimized_statements):
    state = project.factory.blank_state(addr=block_addr)
    state.block().vex.statements = optimized_statements  # 替换为优化后的语句
    simgr = project.factory.simulation_manager(state)

    try:
        simgr.run()
        print("优化的 IR 执行成功")
    except Exception as e:
        print(f"优化 IR 执行失败: {e}")

# 计算执行时间，进行对比前后
def measure_execution_time(func, *args, repeat=5):
    times = []
    for _ in range(repeat):
        start = time.time()
        func(*args)
        times.append(time.time() - start)
    return sum(times) / len(times)

# 保存为file
def save_statements_to_file(statements, filename):
    with open(filename, "w") as f:
        for stmt in statements:
            f.write(f"{stmt}\n")
    print(f"{filename}")

# 运行主程序
project, block_addresses = typecheck('program')
if project:
    # 提取原始的IR表示
    statements = project.factory.block(addr=block_addresses[0]).vex.statements

    # 提取无用语句
    redundant_statements = identify_redundant_statements(statements)

    # print冗余语句
    print("冗余语句:")
    if redundant_statements:
        for stmt in redundant_statements:
            stmt.pp()
    else:
        print("未检测到冗余语句")

    # print所有 IR 语句
    print("原始 IR 语句:")
    for stmt in statements:
        stmt.pp()

    # 提取优化后的 IR
    optimized_statements = [stmt for stmt in statements if stmt not in redundant_statements]
    
    block_addr = block_addresses[0]

    # 性能分析
    # 对比优化性能前后的执行时间
    original_time = measure_execution_time(execute_optimized_ir, project, block_addr, statements)
    print(f"优化前执行时间: {original_time} 秒")

    optimized_time = measure_execution_time(execute_optimized_ir, project, block_addr, optimized_statements)
    print(f"优化后执行时间: {optimized_time} 秒")

    # 保存优化后的IR
    save_statements_to_file(optimized_statements, "optimized_statements.txt")
