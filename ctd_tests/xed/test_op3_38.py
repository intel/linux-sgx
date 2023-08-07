import subprocess
import sys

OUR_KEYS = ['rm mod', 'size', 'modRM mod', 'modRM rm', 'imm4', 'fs', 'gs', 'operand size', 'imm1', 'sib base', 'sib index', 'sib scale']

XED_KEYS = {'MOD:': 2, ' RM:': 3, 'SIBBASE:': 9, 'SIBINDEX:': 10, 'SIBSCALE:': 11}

SZ_MAP = {'byte': 0, 'word': 1, 'dword': 2, 'qword': 4, 'xmmword': 5}

def run_ours(input):
    # run it
    ret = subprocess.run('$CTD_BIN/ctd_test {}'.format(input), shell= True, stdout=subprocess.PIPE)
    assert(ret.returncode == 0)
    result = {}
    #parse result
    stdout = ret.stdout.decode('utf-8')
    ls = stdout.splitlines()
    mod = ls[2].split(' ')[2]
    addr = ls[3].split(' ')[1]
    inst_len = ls[4].split(' ')[1]
    if addr.startswith('FSGS') or addr.startswith('GSFS'):
        addr = addr[4:]
    return (int(mod), addr, int(inst_len))


def parse_num(l, tar):
    idx = l.index(tar)
    tl = l[idx:]
    num = int(tl[tl.index(':') + 1: tl.index(',')])
    return num

def run_xed(input, mod, addr):
    # run it
    ret = subprocess.run('$XED_BIN/xed -64 -cet -mpx -v 5 -j -de {}'.format(input), shell= True, stdout=subprocess.PIPE)
    stdout = ret.stdout.decode("utf-8")
    if ret.returncode != 0:
        for l in stdout.splitlines():
            if 'ERROR: ' in l:
                return
        assert(mod == 0)
        return
    
    result = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0}
    # test if error

    ls = stdout.splitlines()
    passed = False
    inst_len = 0
    imm_len = 0
    for l in stdout.splitlines():
        if 'CATEGORY:   3DNOW' in l:
            return
        if 'ICLASS:     NOP' in l or 'ICLASS:     UD' in l or 'CATEGORY:   VTX' in l or 'ICLASS:     SMSW' in l:
            assert(mod == 0)
            return
        if 'IMM_WIDTH:' in l and 'POS_IMM:' in l:
            st_idx = l.find('IMM_WIDTH:')
            ed_idx = l[st_idx:].find(',')
            imm_len = int(int(l[st_idx+10: ed_idx + st_idx])/8)
        if 'Encodable!' in l:
            inst_len = int(len(l.split(' ')[1])/2)
        if 'dec_len=' in l:
            inst_len = int(l.split(' ')[4])
    l = ls[4]
    passed = addr in l
    # check memory access type
    if 'HAS_MODRM:1,' in l:
        for i in range(5, len(ls) - 1):
            if ls[i][0] in '0123456789':
                if 'MEM0' in ls[i] and '/EXPLICIT/' in ls[i]: 
                    if '/R/' in ls[i]:
                        assert(mod == 1 and passed and inlen == inst_len - imm_len)
                    elif '/RW/' in ls[i] or '/W/' in ls[i] or '/RCW/' in ls[i]:
                        if 'LOCK,' in l or l.startswith('XCHG'):
                            assert(mod == 1 and passed and inlen == inst_len - imm_len)
                        else:
                            assert(mod == 2 and passed and inlen == inst_len - imm_len)
    else:
        assert(mod == 0)


def test_2opcode(op):
    map = []
    for i in range(256):
        map.append(hex(i)[2:])
    map.append('')
    for i in range(0, 16):
        map[i] = '0' + map[i]
    map[0x38] = ''
    map[0x3a] = ''
    imm4 = 'deadbeef'
    gr1s=['', 'f0', 'f2', 'f3']
    gr2s=['', '2e', '36', '3e', '26', '64', '65']
    gr3s=['', '66']
    gr4s=['','67']
    rexs = ['', '40', '41', '42', '44', '47', '48', '4f']
    input = ''
    ans = []
    for rex in rexs:  
        for modrm in range(0, 257):
            ans.append( rex + '0f38' + op + map[modrm])
    for rex in rexs:
        for h in range(0, 4):
            for modrm in range(0, 8):
                t = modrm | (h<<6)
                for sib in range(0, 33):
                    ans.append( rex + '0f38' + op + map[t] + map[sib])
    return ans









if __name__ == '__main__':
    total = 0
    passed = 0
    imm4 = 'deadbeefdeadbeef'
    for op in range(0, 16):
        print('--------------------')
        op1 = int(sys.argv[1]) * 16 + op
        op1 = str(hex(op1))[2:]
        if len(op1)<2:
            op1 = '0'+op1
        for input in test_2opcode(op1):
            for prefix in ['', 'F0', 'F02E', 'F066', 'F03666', 'F02667','F26467', 'F22E66','F2366667','F326','F36466','F36567','F26566', 'F064','F06566']:
                total += 1
                temp = prefix + input+imm4
                temp=temp[:min(30, len(temp))]
                try:
                    mod, addr, inst_len = run_ours(temp)
                    run_xed(temp, mod, addr, inst_len)
                    passed += 1
                except Exception:
                    print(temp, passed, total, mod == 0)
    print(passed, total)
