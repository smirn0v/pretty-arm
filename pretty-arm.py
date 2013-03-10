#!/usr/bin/python

import json
import sys
import subprocess
import string
import struct
import traceback

def asm_for_file(executable):
    """
    returns array of dicts
    example:
    [ {
        line: 104, 
        full: "000035ce 6810 ldr r0, [r2, #0]", 
        address: 0x000035ce, 
        command: "ldr", 
        arguments: "r0, [r2, #0]"
        comments: ""
      }
    ]
    """
    asm = subprocess.check_output(["otool","-tvV","-arch","armv7",executable])
    asm_lines = asm.splitlines()

    result = []
    for idx,line in enumerate(asm_lines):
        elements = line.split('\t')
        asm_elements = {'line':idx,'full': line}
        if len(elements) >= 3:
            asm_elements['address'] = int(elements[0],16)
            asm_elements['command'] = elements[2]
        if len(elements) > 3:
            asm_elements['arguments'] = elements[3]
        if len(elements) > 4:
            asm_elements['comments'] = elements[4]
        result.append(asm_elements)
    return result

def section_desc_for_file(executable, section_name):
    """
    returns {vmaddr,size,fileoffset}
    """
    load_commands = subprocess.check_output(["otool","-l","-arch","armv7",executable])
    load_commands = load_commands.splitlines()

    selrefs_section_idx = (idx for idx,el in enumerate(load_commands) if el.endswith(section_name)).next()
    
    vmaddr_line = load_commands[selrefs_section_idx + 2]
    size_line   = load_commands[selrefs_section_idx + 3]
    file_offset_line = load_commands[selrefs_section_idx + 4]

    vmaddr_start = int(vmaddr_line.split(" ")[-1],16)
    size = int(size_line.split(" ")[-1],16)
    file_offset_start = int(file_offset_line.split(" ")[-1])

    return {'vmaddr':vmaddr_start,'size':size,'fileoffset':file_offset_start}

def objc_selrefs_for_file(executable):
    """
    returns {vmoffset: value}
    """
    section_desc = section_desc_for_file(executable,'__objc_selrefs')

    result = {}
    with open(executable,"rb") as f:
        f.seek(section_desc['fileoffset'])
        for i in xrange(section_desc['size']/4): #TODO: use align ?
           # arm is little endian, so '<'
           result[section_desc['vmaddr'] + i*4] = struct.unpack('<I',f.read(4))[0]

    return result

def objc_methname_for_file(executable):
    """
    returns {vmoffset: string}
    """

    section_desc = section_desc_for_file(executable,'__objc_methname')
    result = {}
    with open(executable,"rb") as f:
        f.seek(section_desc['fileoffset'])
        read_bytes = 0
        buffer = ''
        while read_bytes < section_desc['size']:
           chunk = f.read(4096) 
           read_bytes += len(chunk)
           buffer += chunk
           str_addr = section_desc['vmaddr']+read_bytes-len(buffer) 
           while '\x00' in buffer and str_addr < section_desc['vmaddr']+section_desc['size']:
               length = buffer.index('\x00')
               str = struct.unpack("%ds"%length,buffer[:length])[0]
               buffer = buffer[length+1:]
               result[str_addr] = str 
               str_addr+=length+1
    return result

def match_asm(asm,full_predicate):
    if len(full_predicate) == 0:
        raise Exception('Predicate must contain statements')
    if 'repeat' in full_predicate[0] or 'repeat' in full_predicate[-1]:
        raise Exception("Repeat predicate can't be first or last")
        
    """
    predicate is array of following dictionaries:
    {address:, command:, arguments:, repeat:}
    each argument is optional
    each argument is lambda taking one argument. except 'repeat', it takes number of lines that can match predicate.
    each lambda return 'true' if validation passed
    validation passed if each lambda returns 'true'
    """
    def match_line_to_predicate(asm_line,predicate):
        def match_key(asm_line,predicate,key):
            if key in predicate:
                if key not in asm_line or not predicate[key](asm_line[key]):
                    return False
            return True
        return match_key(asm_line,predicate,'address') and \
               match_key(asm_line,predicate,'command') and \
               match_key(asm_line,predicate,'arguments') and \
               match_key(asm_line,predicate,'comments')

    result = []

    for idx,asm_line in enumerate(asm):
        match = []
        matched = False
        original_idx = idx
        for predicate_index,predicate in enumerate(full_predicate):
            if idx >= len(asm):
                break
            repeat = 0
            if 'repeat' in predicate: repeat = predicate['repeat']
            if repeat == 0:
                if not match_line_to_predicate(asm[idx],predicate): 
                    break
                else: match.append(asm[idx])
                idx+=1
            else:
                local_match = []
                while (
                        idx+1 < len(asm) and
                        match_line_to_predicate(asm[idx],predicate) and
                        repeat > 0 and
                        not match_line_to_predicate(asm[idx],full_predicate[predicate_index+1])
                      ):
                    local_match.append(asm[idx])
                    repeat-=1
                    idx+=1
                match.append(local_match)
                if not match_line_to_predicate(asm[idx],full_predicate[predicate_index+1]):
                    break
            if predicate_index == len(full_predicate)-1:
                matched = True
        if matched: result.append(match)
    return result

def pc_address_from_line(asm_line):
    # http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0473c/Cacdbfji.html
    # in arm mode: pc = address of current + 8
    # in thumb mode:
    # * for b,bl,cbnz,cbz. pc = address of current + 4
    # * for others. pc = address of current + 4 with dropped LSB
    return (asm_line['address'] + 4) & ~1; #TODO: check if THUMB or ARM mode

def addr_from_movw_movt(movw_line,movt_line): 
    arguments = movw_line['arguments']
    ls_16 = int(arguments[string.find(arguments,",")+1:],16)
    arguments = movt_line['arguments']
    ms_16 = int(arguments[string.find(arguments,",")+1:],16)

    return (ls_16 & 0xffff) | (ms_16 << 16)

def pretty_msgSend_1(asm,selrefs,methnames):
    matches = []
    for reg_name in ["r0","r1","r2","r3","r4","r5","r6","r8"]:
        match = \
        match_asm(asm, [ 
                            {'command': lambda x: x == 'movw', 'arguments': lambda x: x.startswith(reg_name+",")},
                            {'repeat': 5, 'command':lambda x: x!='blx','arguments': lambda x: not x.startswith(reg_name)},
                            {'command': lambda x: x == 'movt', 'arguments': lambda x: x.startswith(reg_name+",")},
                            {'repeat': 5, 'command':lambda x: x!='blx','arguments': lambda x: not x.startswith(reg_name)},
                            {'command': lambda x: x == 'add', 'arguments': lambda x: x.startswith(reg_name+", pc")},
                            {'repeat': 5, 'command':lambda x: x!='blx','arguments': lambda x: not x.startswith(reg_name)},
                            {
                                'command': lambda x: x in ['ldr','ldr.w'], 
                                'arguments': lambda x: x in ["r1, [%s, #0]"%reg_name, "r1, [%s]"%reg_name]
                            },
                            {'repeat': 5,'arguments': lambda x: not x.startswith("r1")},
                            #TODO: manually extract objc_msgSend symbol from dyld info, instead of using
                            # otool comments ?
                            {'command': lambda x: x in ['blx','b.w'], 'comments': lambda x: x.endswith('_objc_msgSend') or x.endswith('_objc_msgSend$shim')}
                       ])
        matches.extend(match)
    for match in matches:
        try:
            addr = addr_from_movw_movt(match[0],match[2])
            addr += pc_address_from_line(match[4])
            match[-1]['full'] = match[-1]['full'] + ". -[%s]"%methnames[selrefs[addr]]
        except Exception as e:
            pass

def pretty_msgSend_2(asm,selrefs,methnames):
    matches = []
    for reg_name1 in ["r0","r1","r2","r3","r4","r5","r6","r8"]:
        for reg_name2 in ["r0","r1","r2","r3","r4","r5","r6","r8"]:
            if reg_name1 == reg_name2:
                continue
            match = \
            match_asm(asm, [ 
                                {'command': lambda x: x == 'movw', 'arguments': lambda x: x.startswith(reg_name1+",")},
                                {'repeat': 5, 'command':lambda x: x!='blx','arguments': lambda x: not x.startswith(reg_name1)},
                                {'command': lambda x: x == 'movt', 'arguments': lambda x: x.startswith(reg_name1+",")},
                                {'repeat': 5, 'command':lambda x: x!='blx','arguments': lambda x: not x.startswith(reg_name1)},
                                {'command': lambda x: x == 'add', 'arguments': lambda x: x.startswith(reg_name1+", pc")},
                                {'repeat': 5, 'command':lambda x: x!='blx','arguments': lambda x: not x.startswith(reg_name1)},
                                {
                                    'command': lambda x: x in ['ldr','ldr.w'], 
                                    'arguments': lambda x: x in ["%s, [%s, #0]"%(reg_name2,reg_name1), "%s, [%s]"%(reg_name2,reg_name1)]
                                },
                                {'repeat': 5,'arguments': lambda x: not x.startswith(reg_name2)},
                                {'command': lambda x: x == 'mov', 'arguments': lambda x: x == "r1, %s"%reg_name2},
                                #TODO: manually extract objc_msgSend symbol from dyld info, instead of using
                                # otool comments ?
                                {'command': lambda x: x in ['blx','b.w'], 'comments': lambda x: x.endswith('_objc_msgSend') or x.endswith('_objc_msgSend$shim')}
                           ])
            matches.extend(match)
    for match in matches:
        try:
            addr = addr_from_movw_movt(match[0],match[2])
            addr += pc_address_from_line(match[4])
            match[-1]['full'] = match[-1]['full'] + ". -[%s]"%methnames[selrefs[addr]]
        except Exception as e:
            pass

def pretty_method_call(asm,selrefs,methnames):
    pretty_msgSend_1(asm,selrefs,methnames)
    pretty_msgSend_2(asm,selrefs,methnames)

def main(executable):
    asm = asm_for_file(executable)
    selrefs = objc_selrefs_for_file(executable)
    methnames = objc_methname_for_file(executable)

    pretty_method_call(asm,selrefs,methnames)
        
    for line in asm:
        print line['full']

def usage():
    print "usage: {} <executable>".format(sys.argv[0])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
        sys.exit(1)
    main(sys.argv[1])
