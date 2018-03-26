import sys
# from idc import *
# from idautils import *
from triton import *
from z3 import *

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

    return ps 

# code = []
# for i in FuncItems(ADDR_CHECK):
#     code.append((i, GetManyBytes(i, NextHead(i) - i)))
#
# print code

code = ['\xac',                     # lodsb
        '*\xc3',                    # sub     al, bl
        '2\xc2',                    # xor     al, dl
        '\xaa',                     # stosb
        '\xd1\xc2',                 # rol     edx, 1
        '\xd1\xc3']                 # rol     ebx, 1


def keygen(cipher):
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86)

    ctx.setConcreteRegisterValue(ctx.registers.ebp, ADDR_EBP)
    ctx.setConcreteRegisterValue(ctx.registers.esp, 0x18f95b)
    ctx.setConcreteRegisterValue(ctx.registers.eax, 0)
    ctx.setConcreteRegisterValue(ctx.registers.ecx, 0x20)
    ctx.setConcreteRegisterValue(ctx.registers.esi, ADDR_CIPHER)
    ctx.setConcreteRegisterValue(ctx.registers.edi, ADDR_EBP - 0x21)
    ctx.setConcreteRegisterValue(ctx.registers.eip, 0x401105)

    ctx.setConcreteMemoryAreaValue(ADDR_CIPHER, cipher)
    ctx.setConcreteMemoryAreaValue(ADDR_TEXT, list(map(ord, TEXT)))
    edx = ctx.convertRegisterToSymbolicVariable(ctx.getRegister(REG.X86.EDX))
    ebx = ctx.convertRegisterToSymbolicVariable(ctx.getRegister(REG.X86.EBX))
    keys = [ctx.convertMemoryToSymbolicVariable(MemoryAccess(ADDR_EBP-0x21, 1)) for i in xrange(32)]

    ctx.setAstRepresentationMode(AST_REPRESENTATION.SMT)

    ast = ctx.getAstContext()
    expr = []

    ip = 0x401105
    for i in xrange(32):
        for j in code:
            inst = Instruction()
            inst.setOpcode(j)
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

    sast = convert(ctx, expr)
    
    return sast

def convert(ctx, asserts):
    sast = ""
    tsym = ctx.getSymbolicExpressions()
    for ek in sorted(tsym.keys()):
        e = tsym[ek].getAst()
        if e.getKind() == AST_NODE.VARIABLE:
            sast += "(declare-fun ref!%d () (_ BitVec %d))\n" % (ek, e.getBitvectorSize())
    nodes = []
    for ek in filter(lambda x: tsym[x].getAst().getKind() <> AST_NODE.VARIABLE, sorted(tsym.keys())):
        nodes.append("let ((ref!%d %s))" % (ek, tsym[ek].getAst()))

    # print reduce(lambda x, y: "%s (%s)" % (x, y), reversed(nodes))
    def fold(x, y):
        if not isinstance(y, list):
            raise TypeError
        if len(y) == 1:
            return y[0]
        return "%s\n(%s)" % (x, fold(y[0], y[1:]))

    nodes = ["assert"] + nodes
    nodes[-1] += '\n' + str(asserts)
    sast += '(' + fold(nodes[0], nodes[1:]) + ')'

    return sast

if __name__ == "__main__":
    cipher = prepare(sys.argv[1])
    expr = keygen(cipher)
   
    s = z3.Solver()
    cs = z3.parse_smt2_string(expr)
    s.assert_exprs(cs)
    s.check()
    m = s.model()

    edx, ebx = m.decls()
    edx, ebx = m[edx].as_long(), m[ebx].as_long()
    
    print "%x-%x" % (edx, edx ^ ebx)
