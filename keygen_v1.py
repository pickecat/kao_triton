import sys
# from idc import *
# from idautils import *
from triton import *

ADDR_CHECK = 0x4010EC
ADDR_CIPHER = 0x4093A8
ADDR_TEXT = 0x409185
ADDR_EBP = 0x18f980
TEXT = "0how4zdy81jpe5xfu92kar6cgiq3lst7"
cipher = None

def prepare(s):
    s = s.replace('-', '')
    s = list(bytearray.fromhex(s)) 
    ps = []
    for i in xrange(8):
        p = list(s[i*4:i*4+4])
        p.reverse()
        ps.extend(p)

    return ps # reduce(lambda x, y: str(x)+str(y), ps)

# To import opcodes from IDA Pro
#
# code = []
# for i in FuncItems(ADDR_CHECK):
#     code.append((i, GetManyBytes(i, NextHead(i) - i)))
#
# print code

code = {0x4010EC: '\x55',                     # push    ebp
        0x4010ED: '\x8b\xec',                 # mov     ebp, esp
        0x4010EF: '\x83\xc4\xdc',             # add     esp, -24h
        0x4010F2: '\xb9\x20\x00\x00\x00',     # mov     ecx, 20h
        0x4010F7: '\xbe\xa8\x93\x40\x00',     # mov     esi, offset cipher
        0x4010FC: '\x8d\x7d\xdf',             # lea     edi, [ebp+string1]
        0x4010FF: '\x8b\x55\x08',             # mov     edx, [ebp+arg_0]
        0x401102: '\x8b\x5d\x0c',             # mov     ebx, [ebp+arg_4]
                                              # loc_401105:
        0x401105: '\xac',                     # lodsb
        0x401106: '\x2a\xc3',                 # sub     al, bl
        0x401108: '\x32\xc2',                 # xor     al, dl
        0x40110A: '\xaa',                     # stosb
        0x40110B: '\xd1\xc2',                 # rol     edx, 1
        0x40110D: '\xd1\xc3',                 # rol     ebx, 1
        0x40110F: '\xe2\xf4'}                 # loop    loc_401105

def keygen(cipher):
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86)

    ctx.setConcreteRegisterValue(ctx.registers.ebp, ADDR_EBP)
    ctx.setConcreteRegisterValue(ctx.registers.esp, 0x18f95b)
    ctx.setConcreteRegisterValue(ctx.registers.eax, 0)
    ctx.setConcreteRegisterValue(ctx.registers.eip, 0x4010ec)

    ctx.setConcreteMemoryAreaValue(ADDR_CIPHER, cipher)
    ctx.setConcreteMemoryAreaValue(ADDR_TEXT, list(map(ord, TEXT)))
    edx = ctx.convertRegisterToSymbolicVariable(ctx.getRegister(REG.X86.EDX))
    ebx = ctx.convertRegisterToSymbolicVariable(ctx.getRegister(REG.X86.EBX))
    keys = [ctx.convertMemoryToSymbolicVariable(MemoryAccess(ADDR_EBP-0x21, 1)) for i in xrange(32)]

    ast = ctx.getAstContext()
    expr = []

    ip = 0x4010ec
    while ip < 0x401111:
        inst = Instruction()
        inst.setOpcode(code[ip])
        inst.setAddress(ip)

        ctx.processing(inst)

        ip = ctx.buildSymbolicRegister(ctx.registers.eip).evaluate()

    for i in xrange(32):
        r_ast = ast.bv(ord(TEXT[i]), 8)
        l_id = ctx.getSymbolicMemoryId(ADDR_EBP-0x21+i)
        l_ast = ctx.getAstFromId(l_id)
        ex = ast.equal(l_ast, r_ast)
        expr.append(ex)

    expr = ast.land(expr)


    model = ctx.getModel(expr)
 
    c1 = model[edx.getId()].getValue()
    c2 = model[ebx.getId()].getValue()
    
    return c1, c2


if __name__ == "__main__":
    cipher = prepare(sys.argv[1])
    c1, c2 = keygen(cipher)

    print "%x-%x" % (c1, c1 ^ c2)
