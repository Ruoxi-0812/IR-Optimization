import copy
import angr
import pyvex

#############################
# Optimizes the IR statements of the program
# A reverse engineering tool that parses binary programs into pyvex VEX IR, performs IR optimization, and generates new IRSBs
# Designed for the angr framework
# Features to be implemented in this version:
# 1. Allow registers as parameters: can parse and convert IR instructions involving registers
# 2. Simplified operation process: optimize the handling of IR statements through mapping tables and function encapsulation
# 3. Dynamically construct and modify IR statement blocks (IRSB):
#    - Able to parse textual IR instructions into pyvex IR representations
#    - Generate executable IRSBs (IR statement blocks)
# 4. Used by angr for symbolic execution and program analysis
# Mainly used for IR statement transformation and optimization
#############################

file=open('./branching.txt')
IRSB_list=file.read().split('\n')
file.close()
#############################
# Lookup table
reg_list=[]
Type_table={'I1':'Ity_I1','I8':'Ity_I8','I16':'Ity_I16','I32':'Ity_I32','I64':'Ity_I64','I128':'Ity_I128'}
Op_table=['PUT','STl']
Const_table={'1':pyvex.const.U1,'8':pyvex.const.U8,'16':pyvex.const.U16,'32':pyvex.const.U32,'64':pyvex.const.U64}
End_table={'big':'???','little':'Iend_LE'}
#############################
def optype_check(str_of_int):# Note: input is str
    length=len(str_of_int)-2
    if length==1:#0x1
        return '1'
    elif length==2:#0xff
        return '8'
    elif length==4:#0xffff
        return '16'
    elif length==8:#0xffff_ffff
        return '32'
    elif length==16:#0xffff_ffff_ffff_ffff
        return '64'
    elif length==32:#0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff
        return '128'
    else:#default64
        return '64'
#############################
#C:pyvex.Const
#O:(int)offset
#R:register_name
#T:temp
#C&T
def buildpara_CT(value):
    if value[0]=='t':#T
        value=pyvex.expr.RdTmp(int(value[1:]))
    else:#C
        optype=optype_check(value)
        value=pyvex.expr.Const(Const_table[optype](int(value,16)))
    return value
#C&T&R
def buildpara_CTR(value,arch):
    value = value.strip(';') 
    if value[0]=='t':#T
        value=pyvex.expr.RdTmp(int(value[1:]))
    elif value[:2]=='0x':#C
        optype=optype_check(value)
        value=pyvex.expr.Const(Const_table[optype](int(value,16)))
    else:
        value=arch.get_register_offset(value)
    return value
#O&R
def buildpara_OR(offset,arch):
    if offset[:6]=='offset':
        offset=int(offset[7:])
    else:
        offset=arch.get_register_offset(offset)
    return offset
#SC&T&R #SC: special Const, no external structure
def buildpara_SCTR(value,arch):
    if value[0]=='t':#T
        value=pyvex.expr.RdTmp(int(value[1:]))
    elif value[:2]=='0x':#C
        optype=optype_check(value)
        value=Const_table[optype](int(value,16))
    else:
        value=arch.get_register_offset(value)
    return value
#Get parameter
def str2stmt(str_of_stmt,arch):# Input a str, return a vex statement
    parts = str_of_stmt.split()  # Split string by spaces
    length = len(parts) # Compute length to handle spacing issues
    #
    if length==0:
        return None
    #
    #Separator type
    if parts[1][:5]=="IMark":#IMark
        #print('<Separator>',str_of_stmt)
        return pyvex.stmt.IMark(int(parts[1][6:-1], 16), int(parts[2][:-1]), int(parts[3][:-1]))#addr,len,delta
        #IMark has no effect, can be optimized away
    #Assignment type
    elif parts[0][0]=='t':
        #print('<Assignment>',str_of_stmt)
        var=int(parts[0][1:])#Remove 't'
        expr=parts[2]
        if expr[0]=='t' or expr[:2]=='0x':
            value=expr
            value=buildpara_CT(value)
            return pyvex.stmt.WrTmp(var,value)
        elif expr[:3]=='GET':#GET
            ty=Type_table[expr.split('(')[0][4:]]
            #offset = hex/reg/tmp
            offset=expr.split('(')[1][:-1]#Content inside the parentheses
            offset=buildpara_OR(offset,arch)
            #print(ty,offset,pyvex.stmt.WrTmp(var,pyvex.expr.Get(offset,ty)))
            #pyvex.expr.Get(offset,ty)
            return pyvex.stmt.WrTmp(var,pyvex.expr.Get(offset,ty))
        elif expr[:3]=='Add' or expr[:3]=='Sub' or expr[:3]=='Xor' or expr[:3]=='And' or expr[:2]=='Or':#All binary operations
            #expr=Add64(t64, /expr=Add64(0xff,
            #expr2=0xff) / expr2=t64)
            op='Iop_'+expr.split('(')[0]
            if length==4:#Has space
                value1=expr.split('(')[1][:-1]#t64/0xff
                value2=parts[3][:-1]#t64/0xff
            else:#no space
                temp=expr.split('(')[1].split(',')
                value1=temp[0]#t64/0xff
                value2=temp[1][:-1]#t64/0xff
            #print(op,value1,value2)
            value1=buildpara_CT(value1)
            value2=buildpara_CT(value2)
            return pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2]))
        elif expr[:4]=='LDle':# LD, le means little endian
            ty=expr.split('(')[0][5:]
            addr=expr.split('(')[1][:-1]#t16/0xff
            if addr[0]=='t':#t16
                addr=int(addr[1:])
            else:#0xff
                addr=int(addr,16)
            #print(ty,addr,pyvex.stmt.WrTmp(var,pyvex.expr.Load(End_table['little'],Type_table[ty],pyvex.expr.RdTmp(addr))))
            return pyvex.stmt.WrTmp(var,pyvex.expr.Load(End_table['little'],Type_table[ty],pyvex.expr.RdTmp(addr)))
        elif expr[:4]=='Mull' or expr[:6]=='DivMod':#Mull
            op='Iop_'+expr.split('(')[0]
            if length==4:#has space
                value1=expr.split('(')[1][:-1]#t64/0xff
                value2=parts[3][:-1]#t64/0xff
            else:#no space
                temp=expr.split('(')[1].split(',')
                value1=temp[0]#t64/0xff
                value2=temp[1][:-1]#t64/0xff
            #print(op,optype,value1,value2)
            value1=buildpara_CT(value1)
            value2=buildpara_CT(value2)
            #print(pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2])))
            return pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2]))
        elif expr[:3]=='Sar' or expr[:3]=='Sal' or expr[:3]=='Shl' or expr[:3]=='Shr':#Sar, shift operations
            op='Iop_'+expr.split('(')[0]
            if length==4:#has space
                value1=expr.split('(')[1][:-1]#t64/0xff
                value2=parts[3][:-1]#t64/0xff
            else:#no space
                temp=expr.split('(')[1].split(',')
                value1=temp[0]#t64/0xff
                value2=temp[1][:-1]#t64/0xff
            value1=buildpara_CT(value1)
            value2=buildpara_CT(value2)
            #print(op,optype,value1,value2)
            #print(pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2])))
            return pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2]))
        elif expr[:3]=='Cmp':#Cmp
            #value1/value2 can be t/h type
            #t230, /0x0000000000000001)
            op='Iop_'+expr.split('(')[0]#
            if length==4:#has space
                value1=expr.split('(')[1][:-1]#t64/0xff
                value2=parts[3][:-1]#t64/0xff
            else:#no space
                temp=expr.split('(')[1].split(',')
                value1=temp[0]#t64/0xff
                value2=temp[1][:-1]#t64/0xff
            value1=buildpara_CT(value1)
            value2=buildpara_CT(value2)
            #print(ty)
            #print(value1)
            #print(value2)
            #print(pyvex.stmt.WrTmp(var,pyvex.expr.Unop(op,[value1,value2])))
            return pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2]))
        else:#parsing class, expr = <[bit][type]to[bit]> (value)
            if ',' not in expr:#single parameter
                op='Iop_'+expr.split('(')[0]#<--->#note: due to naming, all can be resolved using Iop_ prefix
                value=expr.split('(')[1][:-1]#T&C
                value=buildpara_CT(value)
                #print(var,op,value)
                return pyvex.stmt.WrTmp(var,pyvex.expr.Unop(op,[value]))
            else:#currently only HL, belongs to arithmetic class
                op='Iop_'+expr.split('(')[0]#<--->#note: due to naming, all can be resolved using Iop_ prefix
                if length==4:#has space
                    value1=expr.split('(')[1][:-1]#t64/0xff
                    value2=parts[3][:-1]#t64/0xff
                else:
                    temp=expr.split('(')[1][:-1].split(',')
                    value1=temp[0]
                    value2=temp[1]
                value1=buildpara_CT(value1)
                value2=buildpara_CT(value2)
                #print(var,op,value)
                return pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2]))
    #Operation type
    elif parts[0][:3] in Op_table:
        #print('<Operation>',str_of_stmt)
        inst=parts[0]
        var=parts[2]
        if inst[:3]=='PUT':#PUT
            #Note: need to determine data type from data length / U64:16+2
            #Note 2: both LHS and RHS can be either type
            offset=inst[4:-1]
            #var: CTR
            #offset: OR
            con=buildpara_CTR(var,arch)
            offset=buildpara_OR(offset,arch)
            #print(con,offset)
            #print(pyvex.stmt.Put(data,offset))
            return pyvex.stmt.Put(con,offset)
        elif inst[:4]=='STle':
            addr=inst[5:-1]
            #data: CTR
            #addr: OR
            data=buildpara_CTR(var,arch)
            addr=buildpara_CTR(addr,arch)
            return pyvex.stmt.Store(addr,data,End_table['little'])
        else:#unknown for now
            return None
    #Branch type
    else: #usually only at the last statement, so it's recommended to copy old_block directly
        #but note: division includes built-in division-by-zero checks
        #print('<Branch>',str_of_stmt)
        #print(parts)
        if parts[0]=='if': #handle if statements, mainly for div
            guard=parts[1][1:-1]#T
            dst=parts[5][:-1]#C#special type, just use Uxx
            jk=parts[6]#str
            offsIP=parts[3][4:-1]#OR
            #print(guard, dst, jk, offsIP)
            guard=buildpara_CTR(guard,arch)
            dst=buildpara_SCTR(dst,arch)
            offsIP=buildpara_OR(offsIP,arch)
            
            return pyvex.stmt.Exit(guard=guard, dst=dst, jk=jk, offsIP=offsIP)
        else:
            return None
    
def list2stmtlist(list_of_stmts,irsb_old):#return new IRSB
    irsb=copy.deepcopy(irsb_old)#normal copy won't copy recursively defined elements
    irsb.statements=[]
    for i in [1,1,2,2,1,1,1,2,1,1,1,2,1,2]:
        if i ==1:
            irsb.tyenv.add('Ity_I32')
        else:
            irsb.tyenv.add('Ity_I64')
    for stmt_str in list_of_stmts:#statements in str format
        #try:
            stmt_str=stmt_str[8:]
            #print(stmt_str)
            stmt_vex=str2stmt(stmt_str,irsb_old.arch)
            if stmt_vex!=None: #none will be ignored
                irsb.statements.append(stmt_vex)
        #except:
        #    print('Some Mistakes',stmt_str)
    #The last statement must be an exit, so copy the original one
    irsb.statements.append(irsb_old.statements[-1])
    return irsb
        
#############################

project = angr.Project("./a2", auto_load_libs=False)
#VEX IR
irsb_old = project.factory.block(addr=0x4011e9).vex#0x0411886
#IR 
# print(irsb_old.pp()) 
# with open("IR1.txt", "w") as f:
#    f.write(irsb_old.__str__())

#############################
result = list2stmtlist(IRSB_list, irsb_old)

#save the optimized IR code to a file
with open("branching_optimized.txt", "w") as f:
    for stmt in result.statements:
        f.write(str(stmt) + "\n")

print("Optimized IR code")
for stmt in result.statements:
    print(stmt)

print("Original IR code")
for stmt in irsb_old.statements:
    print(stmt)