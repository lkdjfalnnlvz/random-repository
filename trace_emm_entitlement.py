"""Trace SVM entitlement handler (event_num=6) with a captured EMM as input.

Emulate ac_svm_event_entitlement's setup:
  * event param buffer @ 0x6066C:
      +0  Parameter_ID magic 0x06000000 (BE)   ← event_num=6 in high byte
      +4  reserved 0
      +8  tuner_id  (BE)
      +12 service_id (BE)
      +16 BufferAddr (SVM address of EMM body, BE)
      +20 BufferLen  (BE)
  * PC = 0x280 (SetEventHandler-registered dispatcher)
  * dword_18070C copies to SVM_HANDLE+132 (=event handler PC) — same 0x280

Instrument every Cipher / GetHash / MemCopy / SlotRead call to reveal KDF.
Halt on EPComplete or fault.
"""
from __future__ import annotations
import struct
import sys
from pathlib import Path
from svm_emu import DLX, ROM_PATH, STACK_TOP, MEM_SIZE, SYSCALL_TRAP, TRAP_ASSERT, DLXFault

EMM_FILE = Path(r"C:\Users\leemi\Documents\GitHub\exampletv\emm_capture.bin")

EVENT_PARAM = 0x6066C     # unk_6066C — from sub_5FEA4 (SetEventParamBuffer)
EVENT_HANDLER_PC = 0x280
BUF_ADDR = 0x100000       # arbitrary SVM address where we drop the EMM body
INSTR_LIMIT = 5_000_000


def parse_emm(bin_path: Path) -> list[dict]:
    """Split emm_capture.bin into sections; return list of parsed EMM dicts."""
    d = bin_path.read_bytes()
    out = []
    i = 0
    while i + 3 <= len(d):
        tid = d[i]
        slen = ((d[i+1] & 0x0F) << 8) | d[i+2]
        total = 3 + slen
        if i + total > len(d): break
        if tid == 0x83:
            body = d[i+3:i+total]
            if len(body) >= 20:
                data_id = int.from_bytes(body[8:10], 'big')
                out.append({
                    'pos': i, 'total': total, 'raw': d[i:i+total],
                    'body': body, 'data_id': data_id,
                })
        i += total
    return out


def find_subtype(sections, target_id):
    for s in sections:
        if s['data_id'] == target_id:
            return s
    return None


def emulate_emm(section, trap_limit=200) -> dict:
    """Run SVM entitlement handler with `section` as the EMM data.
    Returns a trace log of interesting syscall invocations."""
    svm = DLX(ROM_PATH.read_bytes())
    svm.install_default_syscalls()
    svm.max_instrs = INSTR_LIMIT

    # ---- setup event param buffer ----
    body = section['body']
    svm.mem[BUF_ADDR:BUF_ADDR+len(body)] = body

    svm.w32(EVENT_PARAM + 0,  0x06000000)   # Parameter_ID magic (event_num=6)
    svm.w32(EVENT_PARAM + 4,  0)
    svm.w32(EVENT_PARAM + 8,  1)            # tuner_id
    svm.w32(EVENT_PARAM + 12, 713)          # service_id (channel we changed to)
    svm.w32(EVENT_PARAM + 16, BUF_ADDR)     # SVM address of EMM body
    svm.w32(EVENT_PARAM + 20, len(body))    # BufferLen

    # ---- install logging syscalls ----
    trace = []
    trap_count = {'total': 0}

    def hex_bytes(a, n):
        return bytes(svm.mem[a:a+n]).hex() if a and 0 < n < 4096 else '(none)'

    def log_cipher(vm):
        fp = svm.R(30)
        out_p     = svm.r32(fp + 0);  out_len_p = svm.r32(fp + 4)
        in_p      = svm.r32(fp + 8);  in_len    = svm.r32(fp + 12)
        key_p     = svm.r32(fp + 16); key_len   = svm.r32(fp + 20)
        iv_p      = svm.r32(fp + 24); iv_len    = svm.r32(fp + 28)
        alg       = svm.r32(fp + 32)
        entry = {
            'op': 'Cipher',
            'pc': svm.pc, 'instr': svm.instr_count,
            'alg': f'0x{alg:08x}',
            'family': (alg >> 24) & 0xff,
            'mode':   (alg >> 16) & 0xff,
            'dir':    (alg >> 8) & 0xff,
            'pad':     alg & 0xff,
            'key': hex_bytes(key_p, key_len),
            'iv':  hex_bytes(iv_p, iv_len),
            'in':  hex_bytes(in_p, min(in_len, 64)),
            'in_len': in_len,
        }
        trace.append(entry)
        print(f"[{svm.instr_count:7d}] Cipher alg={entry['alg']} (fam={entry['family']} mode={entry['mode']} "
              f"dir={entry['dir']} pad={entry['pad']}) key_len={key_len} iv_len={iv_len} in_len={in_len}")
        print(f"          key = {entry['key']}")
        print(f"          iv  = {entry['iv']}")
        print(f"          in  = {entry['in']}")
        svm.sys_cipher()   # actually perform decrypt (fills out buffer)
        entry['out'] = hex_bytes(out_p, min(in_len, 64))
        print(f"          out = {entry['out']}")

    def log_gethash(vm):
        fp = svm.R(30)
        md_p = svm.r32(fp);  src_p = svm.r32(fp + 4)
        n    = svm.r32(fp + 8);  alg = svm.r32(fp + 12)
        entry = {
            'op': 'GetHash',
            'pc': svm.pc, 'instr': svm.instr_count,
            'alg': alg,  # 0=MD5, 1=SHA1, 2..5=SHA-*
            'src': hex_bytes(src_p, min(n, 64)),
            'src_len': n,
        }
        svm.sys_gethash()
        entry['md'] = hex_bytes(md_p, {0:16, 1:20, 2:28, 3:32, 4:48, 5:64}.get(alg, 20))
        trace.append(entry)
        print(f"[{svm.instr_count:7d}] GetHash alg={alg} src_len={n}")
        print(f"          src = {entry['src']}")
        print(f"          md  = {entry['md']}")

    def log_slotread(vm):
        fp = svm.R(30)
        off = svm.r32(fp); buf = svm.r32(fp + 4); n = svm.r32(fp + 8)
        entry = {'op': 'SlotRead', 'pc': svm.pc, 'offset': off, 'len': n}
        trace.append(entry)
        print(f"[{svm.instr_count:7d}] SlotRead off=0x{off:x} len={n} → buf=0x{buf:x} (STUB)")
        # STUB: no real PA data, return zeros — but log the offset
        svm.mem[buf:buf+n] = b'\x00' * n
        svm.setR(1, 0)

    def epcomplete(vm):
        entry = {'op': 'EPComplete', 'pc': svm.pc, 'r1': svm.R(1)}
        trace.append(entry)
        print(f"[{svm.instr_count:7d}] EPComplete r1=0x{svm.R(1):x}  ← HALT")
        svm.setR(1, 0)
        svm.halted = True

    def epsetevent_dummy(vm):
        # SetEventHandler / SetEventParamBuffer — no-op for our trace
        svm.setR(1, 0)

    def svmspec_stub(vm):
        # Return spec version = 7 (per sub_54AE8 check)
        fp = svm.R(30)
        which = svm.r32(fp);  out1_p = svm.r32(fp + 4);  out2_p = svm.r32(fp + 8)
        if which == 1 and out1_p:
            svm.w32(out1_p, 7)
        svm.setR(1, 0)

    svm.syscalls[SYSCALL_TRAP["Cipher"]]   = log_cipher
    svm.syscalls[SYSCALL_TRAP["GetHash"]]  = log_gethash
    svm.syscalls[SYSCALL_TRAP["EPComplete"]] = epcomplete
    svm.syscalls[SYSCALL_TRAP["SetEventHandler"]]     = epsetevent_dummy
    svm.syscalls[SYSCALL_TRAP["SetEventParamBuffer"]] = epsetevent_dummy
    svm.syscalls[SYSCALL_TRAP["SVMSpec"]]  = svmspec_stub
    # Also add real trap IDs per firmware (analyze re-derived) in case svm_emu.py's base is off
    svm.syscalls[0x1001] = epsetevent_dummy   # SetEventHandler (real)
    svm.syscalls[0x1002] = epsetevent_dummy   # SetEventParamBuffer (real)
    svm.syscalls[0x1007] = epcomplete         # EPComplete (real)
    svm.syscalls[0x100D] = log_cipher         # Cipher (real)
    svm.syscalls[0x100C] = log_gethash        # GetHash (real)
    svm.syscalls[0x1013] = svmspec_stub       # SVMSpec (real)
    svm.syscalls[0x102B] = log_slotread       # SlotRead (real)

    def catchall(trap_id):
        def stub(vm):
            trace.append({'op': f'trap_{trap_id:#x}', 'pc': svm.pc})
            print(f"[{svm.instr_count:7d}] unhandled trap 0x{trap_id:x} @ pc=0x{svm.pc:x} — returning 0")
            svm.setR(1, 0)
        return stub

    # Blanket stub for unknown traps so we can see the full flow
    for tid in range(0x1000, 0x1040):
        if tid not in svm.syscalls:
            svm.syscalls[tid] = catchall(tid)

    # ---- initial state ----
    svm.setR(29, STACK_TOP)
    svm.setR(31, 0)          # sentinel return: pc becomes 0 → halt
    svm.pc = EVENT_HANDLER_PC

    # ---- run ----
    try:
        svm.run()
    except DLXFault as e:
        print(f"\n[!] DLX fault: {e}")
        print(f"    pc={svm.pc:#x} instr_count={svm.instr_count}")
    except Exception as e:
        print(f"\n[!] Exception: {e}")

    return {'trace': trace, 'instr_count': svm.instr_count, 'pc_final': svm.pc}


def main():
    print("[*] parsing emm_capture.bin ...")
    sections = parse_emm(EMM_FILE)
    print(f"[*] {len(sections)} sections total\n")

    # Pick the smallest of each subtype (fastest to trace)
    from collections import defaultdict
    by_id = defaultdict(list)
    for s in sections:
        by_id[s['data_id']].append(s)

    # Try 0x1A1 BG first (most common)
    for target in [0x1A1, 0x102, 0x101, 0x181]:
        if target not in by_id:
            continue
        picks = sorted(by_id[target], key=lambda s: s['total'])
        s = picks[0]
        print("="*72)
        print(f"=== data_id 0x{target:03x}   section total={s['total']}B  body={len(s['body'])}B")
        print("="*72)
        result = emulate_emm(s)
        print(f"\n[*] halted @ pc=0x{result['pc_final']:x} after {result['instr_count']} instrs")
        print(f"[*] {sum(1 for t in result['trace'] if t['op']=='Cipher')} Cipher calls, "
              f"{sum(1 for t in result['trace'] if t['op']=='GetHash')} GetHash calls\n")
        # Only one subtype for now to keep output readable
        break


if __name__ == "__main__":
    main()
