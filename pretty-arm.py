#!/usr/bin/python

import sys
import subprocess

def asm_for_file(executable):
    """
    returns array of dicts
    [
        [address,command,arguments]
    ]
    example:
    [{line: 104, full: "000035ce            6810        ldr     r0, [r2, #0]", address:0x000035ce,command:"ldr",arguments:"r0, [r2, #0]"}]
    """
    asm = subprocess.check_output(["otool","-tvV","-arch","armv7",executable])
    asm_lines = asm.splitlines()[2:]

    result = []
    for idx,line in enumerate(asm_lines):
        elements = line.split('\t')
        asm_elements = {'line':idx,'full': line}
        if len(elements) >= 3:
            asm_elements['address'] = int(elements[0],16)
            asm_elements['command'] = elements[2]
        if len(elements) > 3:
            asm_elements['arguments'] = elements[3]
        result.append(asm_elements)
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
               match_key(asm_line,predicate,'arguments')

    result = []

    for idx,asm_line in enumerate(asm):
        match = []
        matched = False
        for predicate_index,predicate in enumerate(full_predicate):
            if idx >= len(asm):
                break
            repeat = 0
            if 'repeat' in predicate: repeat = predicate['repeat']
            if repeat == 0:
                if not match_line_to_predicate(asm[idx],predicate): break
                else: match.append(asm[idx])
                idx+=1
            else:
                local_match = []
                while match_line_to_predicate(asm[idx],predicate) and repeat>0 and \
                      not match_line_to_predicate(asm[idx],full_predicate[predicate_index+1]):
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

def main(executable):
    asm = asm_for_file(executable)
    result = \
    match_asm(asm, [ 
                        {'command': lambda x: x == 'movw', 'arguments': lambda x: x.startswith("r0,")},
                        {'repeat': 20},
                        {'command': lambda x: x == 'movt', 'arguments': lambda x: x.startswith("r0,")},
                        {'repeat': 50},
                        {'command': lambda x: x == 'add', 'arguments': lambda x: x.startswith("r0, pc")},
                        {'repeat': 50},
                        {'command': lambda x: x == 'ldr', 'arguments': lambda x: x == "r1, [r0, #0]"},
                        {'repeat': 20},
                        {'command': lambda x: x == 'blx'}
                   ])
    for match in result:
        match[0]['full'] = match[0]['full'] + " !!! MATCHED !!!"
    for line in asm:
        print line['full']
    

def usage():
    print "usage: {} <executable>".format(sys.argv[0])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
        sys.exit(1)
    main(sys.argv[1])
