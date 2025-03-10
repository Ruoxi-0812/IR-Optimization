import angr
import time
import openai
import os
import pyvex
import re
import deepdiff

# API Key
openai.api_key = os.getenv("OPENAI_API_KEY")

# 文件
BINARY_FILE = "./a2"
IR_FILE = "IR1.txt"
OPTIMIZED_IR_FILE = "IR1_optimized_llm.txt"
BLOCK_ADDR = 0x4011e9  

# 提取 VEX IR 代码
def extract_ir():
    project = angr.Project(BINARY_FILE, auto_load_libs=False)
    irsb = project.factory.block(addr=BLOCK_ADDR).vex
    with open(IR_FILE, "w") as f:
        f.write(str(irsb))
    return irsb

# 计算 IR 代码的执行时间
def measure_total_execution_time():
    project = angr.Project(BINARY_FILE, auto_load_libs=False)
    state = project.factory.blank_state(addr=BLOCK_ADDR)
    
    start_time = time.perf_counter()
    simgr = project.factory.simulation_manager(state)
    simgr.run()
    end_time = time.perf_counter()
    
    return end_time - start_time 

# 计算最慢的 IR 语句
def measure_execution_time(irsb):
    times = {}
    for stmt in irsb.statements:
        start_time = time.perf_counter()
        try:
            angr.engines.HeavyVEXMixin().handle_vex_stmt(stmt)
        except Exception as e:
            print(f"执行 IR 语句时出错: {stmt}, 错误: {e}")
        end_time = time.perf_counter()
        exec_time = end_time - start_time
        times[stmt] = exec_time
    
    sorted_times = sorted(times.items(), key=lambda x: x[1], reverse=True)
    print("\n最慢的 5 条 IR 语句：")
    for stmt, exec_time in sorted_times[:5]:
        print(f"{exec_time} 秒 - {stmt}")
    return sorted_times

# 统计 IR 语句数量
def count_ir_statements(ir_code):
    return len(ir_code.strip().split("\n"))

# 统计关键 IR 指令优化
def count_ir_operations(ir_code):
    operations = ["PUT", "LOAD", "STORE", "ADD", "SUB", "MUL", "DIV", "CMP", "JMP"]
    counts = {op: len(re.findall(rf'\b{op}\b', ir_code)) for op in operations}
    return counts

# 统计临时变量
def count_temp_vars(ir_code):
    temp_vars = re.findall(r't(\d+)', ir_code)
    unique_vars = set(temp_vars)
    max_temp_var = max(map(int, temp_vars)) if temp_vars else 0
    return len(unique_vars), max_temp_var

# 进行符号执行
def symbolic_execution():
    project = angr.Project(BINARY_FILE, auto_load_libs=False)
    state = project.factory.entry_state(addr=BLOCK_ADDR)
    simgr = project.factory.simulation_manager(state)
    simgr.explore()
    print(f"符号执行: 可行路径数 {len(simgr.found)}, 结束路径数 {len(simgr.deadended)}")
    return len(simgr.found) + len(simgr.deadended)

# 生成优化 IR
def generate_optimized_ir(ir_code):
    response = openai.ChatCompletion.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": 
            "优化 VEX IR 代码，确保符合 VEX 语法，减少执行时间。\n"
            "1. **减少不必要的寄存器存取**（避免过多的 `PUT()` 和 `GET()` 操作）。\n"
            "2. **优化控制流**（减少 `JMP`，优化 `CMP` 逻辑）。\n"
            "3. **减少临时变量的创建和使用**。\n"
            "4. **减少冗余计算**（合并相邻的算术运算，减少 `ADD`、`SUB`、`MUL`、`DIV` 的重复计算）。\n"
            "5. **优化 `NEXT: PUT(rip)` 逻辑，避免直接从 `rsp` 读取地址，改为从 `rbp` 读取。\n"
            "请对以下 VEX IR 代码进行优化："
            },
            {"role": "user", "content": f"{ir_code}"}
        ],
        max_tokens=3000
    )
    return response["choices"][0]["message"]["content"].strip()

# 验证优化 IR 代码
def save_and_verify_ir(optimized_ir_code):
    if not optimized_ir_code or not optimized_ir_code.strip():
        return None

    optimized_ir_code = optimized_ir_code.strip()
    if not optimized_ir_code.startswith("IRSB {"):
        optimized_ir_code = "IRSB {\n" + optimized_ir_code

    if not optimized_ir_code.endswith("}"):
        optimized_ir_code += "\n}"

    with open(OPTIMIZED_IR_FILE, "w") as f:
        f.write(optimized_ir_code)

    return optimized_ir_code

# 结构对比
def compare_ir_structures(original_ir, optimized_ir):
    diff = deepdiff.DeepDiff(original_ir, optimized_ir, ignore_order=True)
    return diff

# main
def main():
    irsb = extract_ir()
    
    # 计算执行时间
    measure_execution_time(irsb)
    
    # 读取原始 IR
    with open(IR_FILE, "r") as f:
        original_ir = f.read()

    # 测量优化前 IR 执行时间
    original_execution_time = measure_total_execution_time()
    
    # 统计优化前信息
    original_stmt_count = count_ir_statements(original_ir)
    original_operations = count_ir_operations(original_ir)
    original_temp_count, original_max_temp = count_temp_vars(original_ir)
    original_symbolic_paths = symbolic_execution()
    
    # 生成优化 IR
    optimized_ir = generate_optimized_ir(original_ir)
    with open(OPTIMIZED_IR_FILE, "w") as f:
        f.write(optimized_ir)
    
    # 统计优化后信息
    optimized_stmt_count = count_ir_statements(optimized_ir)
    optimized_operations = count_ir_operations(optimized_ir)
    optimized_temp_count, optimized_max_temp = count_temp_vars(optimized_ir)
    optimized_symbolic_paths = symbolic_execution()
    
    # 结构对比
    diff = compare_ir_structures(original_ir, optimized_ir)

    # 测量优化后 IR 执行时间
    optimized_execution_time = measure_total_execution_time()

    # 优化前后的执行时间
    print(f"原始 IR 执行时间: {original_execution_time:.6f} 秒")
    print(f"优化后 IR 执行时间: {optimized_execution_time:.6f} 秒")
    
    # 输出优化结果
    print("优化前后对比结果:")
    print(f"IR 语句数量: {original_stmt_count} -> {optimized_stmt_count}")
    print(f"关键指令变化: {original_operations} -> {optimized_operations}")
    print(f"临时变量数量: {original_temp_count} -> {optimized_temp_count} (最大变量: t{original_max_temp} -> t{optimized_max_temp})")
    print(f"符号执行可行路径: {original_symbolic_paths} -> {optimized_symbolic_paths}")
    print(f"VEX 结构变化: {diff}")

if __name__ == "__main__":
    main()