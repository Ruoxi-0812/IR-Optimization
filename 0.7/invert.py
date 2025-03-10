import copy
import angr
import pyvex

#############################
#0.7版本
# 优化 目标程序的 IR 语句
#逆向分析工具，将二进制程序解析为 pyvex VEX IR，进行IR优化，生成新的IRSB
#适用于angr框架
#这个版本需要实现的功能是：
#1. 允许寄存器作为参数 :可以解析并转换涉及寄存器的 IR 指令。
#2. 更加简化的操作过程 :通过映射表和函数封装，优化 IR 语句的处理流程
#3. 动态构建和修改 IR 语句块（IRSB）：
#   - 能够将文本格式的 IR 指令 解析成 pyvex 的 IR 表示，
#   - 并生成可执行的 IRSB（IR 语句块）。
# 4. 用于 angr 进行符号执行和程序分析
# 被 test.py 和 measure4_targetonly.py 调用
# 主要进行IR语句转换和优化
#############################
file=open('./IR1.txt')
IRSB_list=file.read().split('\n')
file.close()
#############################
#查找表
reg_list=[]
#定义一些映射表
Type_table={'I1':'Ity_I1','I8':'Ity_I8','I16':'Ity_I16','I32':'Ity_I32','I64':'Ity_I64','I128':'Ity_I128'}
Op_table=['PUT','STl']
Const_table={'1':pyvex.const.U1,'8':pyvex.const.U8,'16':pyvex.const.U16,'32':pyvex.const.U32,'64':pyvex.const.U64}
End_table={'big':'???','little':'Iend_LE'}
#############################
def optype_check(str_of_int):#需要注意的是，这里接收str
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
    else:#默认64
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
#SC&T&R #SC：特殊Const，无外部结构
def buildpara_SCTR(value,arch):
    if value[0]=='t':#T
        value=pyvex.expr.RdTmp(int(value[1:]))
    elif value[:2]=='0x':#C
        optype=optype_check(value)
        value=Const_table[optype](int(value,16))
    else:
        value=arch.get_register_offset(value)
    return value
#获取参数
def str2stmt(str_of_stmt,arch):#输入一个str，返回一个vex语句
    parts = str_of_stmt.split()  # 将字符串按空格分割成部分\
    length = len(parts) # 计算长度从而处理空格问题
    #
    if length==0:
        return None
    #
    #分隔型
    if parts[1][:5]=="IMark":#第二部分是IMark
        #print('<分隔>',str_of_stmt)
        return pyvex.stmt.IMark(int(parts[1][6:-1], 16), int(parts[2][:-1]), int(parts[3][:-1]))#addr,len,delta
        #IMark无任何作用，直接优化掉
    #赋值型
    elif parts[0][0]=='t':#变量开头是赋值型
        #print('<赋值>',str_of_stmt)
        var=int(parts[0][1:])#不含t
        expr=parts[2]#右侧表达式
        if expr[0]=='t' or expr[:2]=='0x':
            value=expr
            value=buildpara_CT(value)
            return pyvex.stmt.WrTmp(var,value)
        elif expr[:3]=='GET':#GET
            ty=Type_table[expr.split('(')[0][4:]]
            #offset = hex/reg/tmp
            offset=expr.split('(')[1][:-1]#括号内的内容
            offset=buildpara_OR(offset,arch)
            #print(ty,offset,pyvex.stmt.WrTmp(var,pyvex.expr.Get(offset,ty)))
            #pyvex.expr.Get(offset,ty)
            return pyvex.stmt.WrTmp(var,pyvex.expr.Get(offset,ty))
        elif expr[:3]=='Add' or expr[:3]=='Sub' or expr[:3]=='Xor' or expr[:3]=='And' or expr[:2]=='Or':#所有二进制运算
            #expr=Add64(t64, /expr=Add64(0xff,
            #expr2=0xff) / expr2=t64)
            op='Iop_'+expr.split('(')[0]
            if length==4:#有空格
                value1=expr.split('(')[1][:-1]#取出内容物t64/0xff
                value2=parts[3][:-1]#取出内容物t64/0xff
            else:#没有空格
                temp=expr.split('(')[1].split(',')
                value1=temp[0]#取出内容物t64/0xff
                value2=temp[1][:-1]#取出内容物t64/0xff
            #print(op,value1,value2)
            value1=buildpara_CT(value1)
            value2=buildpara_CT(value2)
            return pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2]))
        elif expr[:4]=='LDle':#LD,le表示小端序
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
            if length==4:#有空格
                value1=expr.split('(')[1][:-1]#取出内容物t64/0xff
                value2=parts[3][:-1]#取出内容物t64/0xff
            else:#没有空格
                temp=expr.split('(')[1].split(',')
                value1=temp[0]#取出内容物t64/0xff
                value2=temp[1][:-1]#取出内容物t64/0xff
            #print(op,optype,value1,value2)
            value1=buildpara_CT(value1)
            value2=buildpara_CT(value2)
            #print(pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2])))
            return pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2]))
        elif expr[:3]=='Sar' or expr[:3]=='Sal' or expr[:3]=='Shl' or expr[:3]=='Shr':#Sar#这个应该是移位
            op='Iop_'+expr.split('(')[0]
            if length==4:#有空格
                value1=expr.split('(')[1][:-1]#取出内容物t64/0xff
                value2=parts[3][:-1]#取出内容物t64/0xff
            else:#没有空格
                temp=expr.split('(')[1].split(',')
                value1=temp[0]#取出内容物t64/0xff
                value2=temp[1][:-1]#取出内容物t64/0xff
            value1=buildpara_CT(value1)
            value2=buildpara_CT(value2)
            #print(op,optype,value1,value2)
            #print(pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2])))
            return pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2]))
        elif expr[:3]=='Cmp':#Cmp
            #value1/value2可以是t/h类型
            #t230, /0x0000000000000001)
            op='Iop_'+expr.split('(')[0]#
            if length==4:#有空格
                value1=expr.split('(')[1][:-1]#取出内容物t64/0xff
                value2=parts[3][:-1]#取出内容物t64/0xff
            else:#没有空格
                temp=expr.split('(')[1].split(',')
                value1=temp[0]#取出内容物t64/0xff
                value2=temp[1][:-1]#取出内容物t64/0xff
            value1=buildpara_CT(value1)
            value2=buildpara_CT(value2)
            #print(ty)
            #print(value1)
            #print(value2)
            #print(pyvex.stmt.WrTmp(var,pyvex.expr.Unop(op,[value1,value2])))
            return pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2]))
        else:#解析类，expr=<[bit][type]to[bit]> (value)
            if ',' not in expr:#单参数
                op='Iop_'+expr.split('(')[0]#<--->#注，由于命名原因，全部可以通过Iop_前缀完成
                value=expr.split('(')[1][:-1]#T&C
                value=buildpara_CT(value)
                #print(var,op,value)
                return pyvex.stmt.WrTmp(var,pyvex.expr.Unop(op,[value]))
            else:#目前只有HL，属于算数类
                op='Iop_'+expr.split('(')[0]#<--->#注，由于命名原因，全部可以通过Iop_前缀完成
                if length==4:#有空格
                    value1=expr.split('(')[1][:-1]#取出内容物t64/0xff
                    value2=parts[3][:-1]#取出内容物t64/0xff
                else:
                    temp=expr.split('(')[1][:-1].split(',')
                    value1=temp[0]
                    value2=temp[1]
                value1=buildpara_CT(value1)
                value2=buildpara_CT(value2)
                #print(var,op,value)
                return pyvex.stmt.WrTmp(var,pyvex.expr.Binop(op,[value1,value2]))
    #操作型
    elif parts[0][:3] in Op_table:
        #print('<操作>',str_of_stmt)
        inst=parts[0]
        var=parts[2]
        if inst[:3]=='PUT':#PUT
            #注：需要用数据长度来判断数据类型/U64:16+2
            #注2：左侧右侧都是双可能
            offset=inst[4:-1]#获取括号内的内容
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
        else:#暂未可知
            return None
    #分支型
    else:#一般只存在于最后一句，所以我建议统一复制old_block
        #但需要注意的是，除法会自带检测是否除0。
        #print('<分支>',str_of_stmt)
        #print(parts)
        if parts[0]=='if':#处理if型，主要是针对div
            guard=parts[1][1:-1]#T
            dst=parts[5][:-1]#C#特殊类型，直接取Uxx
            jk=parts[6]#str
            offsIP=parts[3][4:-1]#OR
            #print(guard, dst, jk, offsIP)
            guard=buildpara_CTR(guard,arch)
            dst=buildpara_SCTR(dst,arch)
            offsIP=buildpara_OR(offsIP,arch)
            
            return pyvex.stmt.Exit(guard=guard, dst=dst, jk=jk, offsIP=offsIP)
        else:
            return None
    
def list2stmtlist(list_of_stmts,irsb_old):#返回IRSB
    irsb=copy.deepcopy(irsb_old)#普通的copy不会复制递归定义
    irsb.statements=[]
    for i in [1,1,2,2,1,1,1,2,1,1,1,2,1,2]:
        if i ==1:
            irsb.tyenv.add('Ity_I32')
        else:
            irsb.tyenv.add('Ity_I64')
    for stmt_str in list_of_stmts:#str格式的stmt
        #try:
            stmt_str=stmt_str[8:]
            #print(stmt_str)
            stmt_vex=str2stmt(stmt_str,irsb_old.arch)
            if stmt_vex!=None:  #None会被忽略
                irsb.statements.append(stmt_vex)
        #except:
        #    print('Some Mistakes',stmt_str)
    #最后一句一定是退出，可以复制原语句
    irsb.statements.append(irsb_old.statements[-1])
    return irsb
        
#############################

project = angr.Project("./a2", auto_load_libs=False)
# 获取 VEX IR 代码
irsb_old = project.factory.block(addr=0x4011e9).vex#0x0411886
# IR 代码
# print(irsb_old.pp()) 
# with open("IR1.txt", "w") as f:
#    f.write(irsb_old.__str__())

#这个是假设的输入

#############################
result = list2stmtlist(IRSB_list, irsb_old)

# 将优化后的 IR 代码保存到文件
with open("IR1_optimized.txt", "w") as f:
    for stmt in result.statements:
        f.write(str(stmt) + "\n")

print("优化后的 IR 代码")
for stmt in result.statements:
    print(stmt)

print("原始 IR 代码")
for stmt in irsb_old.statements:
    print(stmt)