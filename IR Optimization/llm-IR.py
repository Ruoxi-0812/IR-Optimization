import angr
import time
import openai
import os
import re
import difflib
from concurrent.futures import ThreadPoolExecutor

# API Key
openai.api_key = os.getenv("OPENAI_API_KEY")

BINARY_FILE = "./complexprog"
IR_FILE = "complexprog.txt"
OPTIMIZED_IR_FILE = "complexprog_llm.txt"

# Extract VEX IR
def extract_ir():
    project = angr.Project(BINARY_FILE, auto_load_libs=False)
    cfg = project.analyses.CFGFast()
    all_ir_blocks = []

    with open(IR_FILE, "w") as f:
        for func in cfg.kb.functions.values():
            for block in func.blocks:
                try:
                    irsb = project.factory.block(block.addr).vex
                    f.write(str(irsb) + "\n")
                    all_ir_blocks.append((block.addr, irsb))
                except Exception as e:
                    print(f"Skipping {hex(block.addr)}: {e}")

    print(f"Successfully extracted IR code for {len(all_ir_blocks)} basic blocks")
    return all_ir_blocks

# Simulate execution time of each statement (mocked)
def simulate_statement_cost(stmt):
    cost_weights = {
        'PUT': 2.0,
        'LD': 1.8,
        'ST': 1.8,
        'ADD': 1.5,
        'SUB': 1.5,
        'MUL': 2.5,
        'DIV': 3.0,
        'CALL': 3.5
    }
    for op, weight in cost_weights.items():
        if op in stmt:
            return (stmt, weight)
    return (stmt, 1.0)

# Use large language model to optimize
def generate_optimized_ir(ir_stmt):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a VEX IR optimization expert. Please optimize the following **single** VEX IR statement, keeping the semantics unchanged. Only optimize performance where structurally allowed. Do not add extra statements, do not expand into blocks. Maintain VEX IR syntax and return exactly one statement."},
                {"role": "user", "content": ir_stmt}
            ],
            max_tokens=300,
        )
        return response["choices"][0]["message"]["content"].strip()
    except Exception:
        return ir_stmt

# Clean LLM output
def clean_gpt_ir_output(ir_stmt):
    lines = ir_stmt.strip().split("\n")
    cleaned = []
    for line in lines:
        line = line.strip()
        if line == "" or line.startswith("`") or "explanation" in line or "Therefore" in line or line.startswith("This line"):
            continue
        if line.startswith("------ IMark") or re.match(r"^(PUT|t\d+|LD|ST|\-|\().*", line):
            cleaned.append(line)
    return cleaned

# Optimize top-n slowest statements
def optimize_top_n_slowest_statements(irsb_list, n=50):
    all_stmts = []
    for addr, irsb in irsb_list:
        for stmt in irsb.statements:
            all_stmts.append((addr, str(stmt)))

    with ThreadPoolExecutor(max_workers=4) as pool:
        stmt_costs = list(pool.map(lambda pair: simulate_statement_cost(pair[1]), all_stmts))

    sorted_stmts = sorted(stmt_costs, key=lambda x: x[1], reverse=True)
    top_stmts = [s for s, _ in sorted_stmts[:n]]

    print(f"\nStarting optimization for the top {n} slowest statements")
    optimized_map = {}

    with ThreadPoolExecutor(max_workers=4) as pool:
        optimized_results = list(pool.map(generate_optimized_ir, top_stmts))

    for orig, opt in zip(top_stmts, optimized_results):
        optimized_map[orig] = clean_gpt_ir_output(opt)

    optimized_blocks = []
    for addr, irsb in irsb_list:
        new_stmts = []
        for stmt in irsb.statements:
            stmt_str = str(stmt)
            if stmt_str in optimized_map:
                new_stmts.extend(optimized_map[stmt_str])
            else:
                new_stmts.append(stmt_str)
        optimized_blocks.append((addr, new_stmts))

    with open(OPTIMIZED_IR_FILE, "w") as f:
        for addr, stmts in optimized_blocks:
            f.write(f"IRSB @ {hex(addr)} {{\n")
            for s in stmts:
                f.write(s + "\n")
            f.write("}\n\n")
    print(f"\nOptimization result saved to {OPTIMIZED_IR_FILE}")

# Utility functions
def count_ir_statements(ir_code):
    return len(ir_code.strip().split("\n"))

def count_ir_operations(ir_code):
    ops = ["PUT", "LD", "ST", "ADD", "SUB", "MUL", "DIV", "CMP", "JMP"]
    counts = {}
    for op in ops:
        pattern = rf'\b{op}[a-zA-Z0-9_]*\b'
        matches = re.findall(pattern, ir_code)
        counts[op] = len(matches)
    return counts

def count_temp_vars(ir_code):
    temp_vars = re.findall(r't(\d+)', ir_code)
    temp_ids = list(map(int, temp_vars))
    unique_vars = set(temp_ids)
    max_temp_var = max(temp_ids) if temp_ids else 0
    return len(unique_vars), max_temp_var

def measure_total_execution_time():
    project = angr.Project(BINARY_FILE, auto_load_libs=False)
    cfg = project.analyses.CFGFast()
    total, count = 0, 0
    for func in cfg.kb.functions.values():
        for block in func.blocks:
            try:
                state = project.factory.blank_state(addr=block.addr)
                simgr = project.factory.simulation_manager(state)
                start = time.perf_counter()
                simgr.run(n=1)
                end = time.perf_counter()
                total += (end - start)
                count += 1
            except:
                pass
    return total

def main():
    irsb_list = extract_ir()
    if not irsb_list:
        return

    with open(IR_FILE, "r") as f:
        original_ir = f.read()

    orig_time = measure_total_execution_time()

    original_stmt_count = count_ir_statements(original_ir)
    original_ops = count_ir_operations(original_ir)
    original_temp_vars = count_temp_vars(original_ir)

    print("Original IR Info:")
    print(f"Statement count: {original_stmt_count}")
    print(f"Operation statistics: {original_ops}")
    print(f"Temporary variables: {original_temp_vars}")

    optimize_top_n_slowest_statements(irsb_list, n=50)

    opt_time = measure_total_execution_time()

    with open(OPTIMIZED_IR_FILE, "r") as f:
        optimized_ir = f.read()

    optimized_stmt_count = count_ir_statements(optimized_ir)
    optimized_ops = count_ir_operations(optimized_ir)
    optimized_temp_vars = count_temp_vars(optimized_ir)

    print("\nOptimized IR Info:")
    print(f"Statement count: {optimized_stmt_count}")
    print(f"Operation statistics: {optimized_ops}")
    print(f"Temporary variables: {optimized_temp_vars}")

    print("\nPreview of Differences (first 10 lines):")
    diff = list(difflib.unified_diff(
        original_ir.splitlines(),
        optimized_ir.splitlines(),
        fromfile='Original IR',
        tofile='Optimized IR',
        lineterm=''
    ))
    for line in diff[:15]:
        print(line)

    print(f"\nOriginal execution time: {orig_time:.6f} seconds")
    print(f"Optimized execution time: {opt_time:.6f} seconds")

if __name__ == "__main__":
    main()

# python llm-IR.py > output1.txt
# IR: counter.txt  Binary: counter
# IR optimized: counter_llm.txt

# python llm-IR.py > output2.txt
# IR: branching.txt  Binary: a2
# IR optimized: branching_llm.txt

# python llm-IR.py > output3.txt
# IR: matrix.txt  Binary: matrix
# IR optimized: matrix_llm.txt

# python llm-IR.py > output4.txt
# IR: methcall.txt  Binary: methcall
# IR optimized: methcall_llm.txt

# python llm-IR.py > output5.txt
# IR: objinst.txt  Binary: objinst
# IR optimized: objinst_llm.txt

# python llm-IR.py > output6.txt
# IR: heapsort.txt  Binary: heapsort
# IR optimized: heapsort_llm.txt

# python llm-IR.py > output7.txt
# IR: random.txt  Binary: random
# IR optimized: random_llm.txt

# python llm-IR.py > output8.txt
# IR: bigtest.txt  Binary: bigtest
# IR optimized: bigtest_llm.txt

# python llm-IR.py > output9.txt
# IR: bigprog.txt  Binary: bigprog
# IR optimized: bigprog_llm.txt

# python llm-IR.py > output10.txt
# IR: complexprog.txt  Binary: complexprog
# IR optimized: complexprog_llm.txt


