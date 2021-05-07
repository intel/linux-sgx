#!/usr/bin/env python
#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

__version__ = '1.0.1'
import sys
import os
import re 
import shutil
import argparse

LOCK = 'lock'
REP = 'rep[a-z]*'
REX = 'rex(?:\.[a-zA-Z]+)?'
SCALAR = '(?:(?:[+-]\s*)?(?:[0-9][0-9a-fA-F]*|0x[0-9a-fA-F]+))'
IMMEDIATE = '(?:%s[hb]?)' %(SCALAR)
REG = '(?:[a-zA-Z][a-zA-Z0-9]*)'
SYM = '(?:[_a-zA-Z][_a-zA-Z0-9]*(?:@[0-9a-zA-Z]+)?)'
LABEL = '(?:[._a-zA-Z0-9]+)'
SEP = '(?:(?:^|:)\s*)'
PFX = '(?:%s\s+)?' %(REX)
CONST = '(?:(?:%s|%s|%s)(?:\s*[/*+-]\s*(?:%s|%s|%s))*)' %(SYM, SCALAR, LABEL, SYM, SCALAR, LABEL)
OFFSET = '(?:%s|%s|%s\s*:\s*(?:%s|%s|))' %(CONST, SYM, REG, CONST, SYM)
MEMORYOP = '(?:\[*(?:[a-zA-Z]+\s+)*(?:%s\s*:\s*%s?|(?:%s\s*)?\[[^]]+\]\]*))' %(REG, CONST, OFFSET)
ANYOP = '(?:%s|%s|%s|%s|%s)' %(MEMORYOP, IMMEDIATE, REG, SYM, LABEL)
MEMORYOP = '(?:%s|(?:[a-zA-Z]+\s+(?:ptr|PTR)\s+%s))' %(MEMORYOP, ANYOP)
MEMORYSRC = '(?:%s\s*,\s*)+%s(?:\s*,\s*%s)*' %(ANYOP, MEMORYOP, ANYOP)
MEMORYANY = '(?:%s\s*,\s*)*%s(?:\s*,\s*%s)*' %(ANYOP, MEMORYOP, ANYOP)
ATTSTAR = ''
GPR = '(?:rax|rcx|rdx|rbx|rdi|rsi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15|RAX|RCX|RDX|RBX|RDI|RSI|RBP|RSP|R8|R9|R10|R11|R12|R13|R14|R15)'

LFENCE = [
    '(?:%s%smov(?:[a-rt-z][a-z0-9]*)?\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%s(?:vpmask|vmask|mask|c|v|p|vp)mov[a-z0-9]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%spop[bswlqt]?\s+(?:%s|%s))' %(SEP, PFX, MEMORYOP, REG),
    '(?:%s%spopad?\s+%s\s*)' %(SEP, PFX, REG),
    '(?:%s%s(?:%s\s+)?xchg[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:%s\s+)?(?:x|p|vp|ph|h|pm|vpm|)add[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:%s\s+)?(?:p|vp|ph|h|)sub[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:%s\s+)?ad[co]x?[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:%s\s+)?sbb[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:%s\s+)?v?p?cmp(?:[a-rt-z][a-z0-9]*)?\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:%s\s+)?inc[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:%s\s+)?dec[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:%s\s+)?not[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:%s\s+)?neg[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:i|v|p|vp|)mul[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%s(?:i|v|p|vp|)div[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%spopcnt[a-z]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%scrc32[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%s(?:%s\s+)?v?p?and[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:%s\s+)?v?p?or[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%s(?:%s\s+)?v?p?xor[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%sv?p?test[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%ss[ah][lr][a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%ssar[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%s(?:vp|)ro(?:r|l)[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%src(?:r|l)[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%s(?:%s\s+)?bt[a-z]*\s+%s)' %(SEP, PFX, LOCK, MEMORYANY),
    '(?:%s%sbs[fr][a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%s(?:vp|)[lt]zcnt[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sblsi[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sblsmsk[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sblsr[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sbextr[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sbzhi[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%spdep[a-z]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%spext[a-z]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%s(?:%s\s+)?lods[a-z]*(?:\s+%s|\s*(?:#|$)))' %(SEP, PFX, REP, MEMORYSRC),
    '(?:%s%s(?:%s\s+)?scas[a-z]*(?:\s+%s|\s*(?:#|$)))' %(SEP, PFX, REP, MEMORYSRC),
    '(?:%s%s(?:%s\s+)?outs[a-z]*(?:\s+%s|\s*(?:#|$)))' %(SEP, PFX, REP, MEMORYSRC),
    '(?:%s%s(?:%s\s+)?cmps[a-z]*(?:\s+%s|\s*(?:#|$)))' %(SEP, PFX, REP, MEMORYSRC),
    '(?:%s%s(?:%s\s+)?movs[a-z]*(?:\s+%s|\s*(?:#|$)))' %(SEP, PFX, REP, MEMORYSRC),
    '(?:%s%slddqu\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%sv?pack[a-z]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%sv?p?unpck[a-z]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%sv?p?shuf[a-z0-9]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%sv?p?align[a-z]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%sv?pblend[a-z]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%svperm[a-z0-9]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%sv?p?insr[a-z]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%sv?insert[a-z0-9]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%sv?p?expand[a-z]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%svp?broadcast[a-z0-9]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%svp?gather[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?pavg[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?p?min[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?p?max[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?phminpos[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?pabs[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?psign[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?(?:m|db|)psad[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?psll[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?psrl[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?psra[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?pclmulqdq\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?aesdec(?:last)?\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?aesenc(?:last)?\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?aesimc\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?aeskeygenassist\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?sha(?:1|256)(?:nexte|rnds4|msg1|msg2)\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%sv?cvt[a-z0-9]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%sv?rcp(?:ss|ps)\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?u?comis[sd]\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?round[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?dpp[sd]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sv?r?sqrt[a-z0-9]*\s+%s)' %(SEP, PFX, MEMORYSRC),
    '(?:%s%sv?ldmxcsr\s+%s)' %(SEP, PFX, MEMORYOP),
    '(?:%s%sf?x?rstors?\s+%s)' %(SEP, PFX, MEMORYOP),
    '(?:%s%sl[gi]dt\s+%s)' %(SEP, PFX, MEMORYOP),
    '(?:%s%slmsw\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%svmptrld\s+%s)' %(SEP, PFX, MEMORYOP),
    '(?:%s%sf(?:b|i|)ld[a-z0-9]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sfi?add[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sfi?sub[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sfi?mul[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sfi?div[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sf(?:i|u|)com[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sleave[bswlqt]?)' %(SEP, PFX),
    '(?:%s%spopf[bswlqt]?)' %(SEP, PFX),
    '(?:%s%svfixupimm[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%svf[m|n]add[a-z0-9]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%svfpclass[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%svget[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%svpconflict[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%svpternlog[d|q]\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%svrange[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%svreduce[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%svrndscale[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%svscalef[a-z]*\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sxlat\s+%s)' %(SEP, PFX, MEMORYANY),
    '(?:%s%sxlatb?)' %(SEP, PFX),
]

RET = '(?:%s%sret[a-z]*(?:\s+%s)?(?:#|$))' %(SEP, PFX, IMMEDIATE)
MEM_INDBR = '(?:%s%s(?:call|jmp)[a-z]*\s+%s%s)' %(SEP, PFX, ATTSTAR, MEMORYOP)
REG_INDBR = '(?:%s%s(?:call|jmp)[a-z]*\s+%s)' %(SEP, PFX, GPR)

#
# File Operations - read/write
#
def read_file(sfile):
    f = open(sfile, 'r')
    lines = f.readlines()
    f.close()
    return lines

def write_file(tfile, lines):
    f = open(tfile, 'w')
    for line in lines:
        f.write(line)
    f.close()
    return

def check_code_line(line):
    line = line.strip()
    if line.startswith(';') or line.startswith('%') or line.startswith('['):
        return False
    
    return True

ASSEMBLERS = ['ml64', 'ml', 'nasm']
MITIGATIONS = ['NONE', 'CF', 'LOAD']

def insert_lfence(compiler, mitigation_level, infile, outfile):
    if compiler.startswith('ml'):
        PTR_KEYWORD = 'PTR'
    else: # compiler == 'nasm.exe'
        PTR_KEYWORD = ''

    pattern = '|'.join('(?:%s)' % l for l in LFENCE)
    lines = read_file(infile)
    outputs = lines
    for i in range(0, len(lines)):
        if lines[i].strip().startswith(';') or lines[i].strip().startswith('%') or lines[i].strip().startswith('['):
            continue
        if mitigation_level == 'LOAD':
            m = re.search(pattern, lines[i])
            if m:
                j = i
                while j > 0:
                    j = j + 1
                    if outputs[j].strip() != '' and not outputs[j].strip().startswith(';'):
                        break
                if not outputs[j].strip().startswith('lfence'):
                    load_mitigation = '    lfence\n'
                    outputs[i] = outputs[i] + load_mitigation
        if mitigation_level == 'CF':
            m = re.search(REG_INDBR, lines[i])
            if m:
                j = i
                while j > 0:
                    j = j - 1
                    if outputs[j].strip() != '' and not outputs[j].strip().startswith(';'):
                        break
                if not outputs[j].split('\n')[-2].strip().startswith('lfence'):
                    outputs[i] = '    lfence\n' + outputs[i]
        if mitigation_level != 'NONE':
            m = re.search(RET, lines[i])
            if m:
                ret_mitigation = '    shl QWORD %s [rsp], 0\n    lfence\n' %(PTR_KEYWORD)
                outputs[i] = ret_mitigation + outputs[i]
            m = re.search(MEM_INDBR, lines[i])
            if m:
                print ('Warning: indirect branch with memory operand, line %d' %(i))

    write_file(outfile, outputs)

def parse_options():
    options = []
    usage = "%(prog)s [options] [assembler arguments]"
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--assembler', type=str, help='specify assembler type: nasm|ml64|ml', required=True)
    parser.add_argument('--MITIGATION-CVE-2020-0551', type=str, dest='mitigation', default='NONE', help='specify CVE-2020-0551 mitigation level: NONE|LOAD|CF, [default: %(default)s]')
    (opts, args) = parser.parse_known_args()
    # check compiler
    if opts.assembler is None:
        print ('Error: assembler is not set')
        sys.exit(1)
    if not opts.assembler.lower() in ASSEMBLERS:
        print ('Error: assembler %s is not recogonized' %(opts.assembler))
        sys.exit(1)
    compiler = opts.assembler# + '.exe'
    # mitigation level
    if not opts.mitigation.upper() in MITIGATIONS:
        print ('Error: MITIGATION-CVE-2020-0551 %s is not recogonized' %(opts.mitigation))
        sys.exit(1)
    # process the arguments, add space and quote if needed
    for arg in args:
        if arg.startswith('/Ta') and len(arg) > 3:
            options.append('/Ta')
            arg = arg[3:]
        if arg.find(' ') > 0:
            arg = '\"' + arg + '\"'
        options.append(arg)
    return (compiler, opts.mitigation.upper(), options)


def get_mitigated_file(src):
    return src + '.mitigated'
def get_preprocess_file(src):
    return src + '.preprocess'

def get_src_index(options):
    src_index = -1
    for i in range(0,len(options)):
        if options[i].endswith('.asm'):
            if(src_index != -1):
                print ('source files conflict')
                sys.exit(-1)
            src_index = i
    if src_index == -1:
        print ('cannot find the source file')
        sys.exit(-1)
    return src_index

def get_dst_index(options):
    dst_index = -1
    for i in range(0,len(options)):
        if options[i] == '-o':
            if(dst_index != -1):
                print ('target files conflict')
                sys.exit(-1)
            dst_index = i+1
    if dst_index == -1:
        print ('cannot find the target file')
        sys.exit(-1)
    return dst_index

def get_preprocess_cmd(compiler, options, src_index):
    pre_file = get_preprocess_file(src_file)
    if compiler.startswith('ml'):
        pre_cmd = compiler + ' /EP ' + ' '.join(options) + ' > ' + pre_file
    else: # compiler == 'nasm.exe'
        ops = options
        dst_index = get_dst_index(options)
        tmp_file = ops[dst_index]
        ops[dst_index] = get_preprocess_file(src_file)
        pre_cmd = compiler + ' -E ' + ' '.join(ops)
        ops[dst_index] = tmp_file
    return pre_cmd

if __name__ == '__main__':
    (compiler, mitigation, options) = parse_options()
    ops = options

    if mitigation != 'NONE':
        src_index = get_src_index(options)
        src_file = options[src_index]

        # preprocess the source file
        pre_cmd = get_preprocess_cmd(compiler, options, src_index)
        errno = os.system(pre_cmd)
        if errno != 0:
            print ('preprocess the assembly failed, see %s for the preprocess output' %(get_preprocess_file(src_file)))
            sys.exit(errno)
        # insert lfence
        insert_lfence(compiler, mitigation, get_preprocess_file(src_file), get_mitigated_file(src_file))
        # compile use the mitigated file
        ops[src_index] = get_mitigated_file(src_file)
 
    as_cmd = compiler + ' ' + ' '.join(ops)
    errno = os.system(as_cmd)
    if errno != 0:
        print ('compile failed, file %s' %(get_mitigated_file(src_file)))
        sys.exit(errno)
    sys.exit(0)
