"""DLX SVM emulator for svm_bytecode.bin.

Full 58-opcode ISA (0x00..0x39) per svm_isa_ref.html.
32-bit BE, fixed 4-byte encoding, 32 GP regs.

Register conventions:
  r0    = zero (writes discarded)
  r1    = return value
  r29   = SP (stack pointer)
  r30   = FP (frame pointer)
  r31   = LR (return address)

Args are passed via stack: caller stores arg[i] at (i*4)(r29) before jal.
Callee reads them via (i*4)(r30) after prologue `add r30,r0,r29`.

SYSCALL trap numbering (derived from svm_load_event_syscall()):
  trap_id = 0x1002 + slot, slot ∈ 0..47
  Additionally 0x8001 = assert/panic.
See SYSCALLS dict below for the full slot→name table.
"""

from __future__ import annotations
import struct
from pathlib import Path


ROM_PATH = Path(r"firm"
                r"\extracted_20260719_203153\vendor_extracted\vendor\lib\mediacas\svm_bytecode.bin")

MEM_SIZE   = 0x200000        # 2 MiB total emulator address space
STACK_TOP  = 0x1FF000        # SP starts here (grows down)
ARG_BUF    = 0x1F0000        # scratch buffers for hosted-caller args

M32        = 0xFFFFFFFF


# SYSCALL slot table — derived from svm_load_event_syscall() in libktcasplugin.so.
# trap_id = 0x1002 + slot.  Two data points confirm the linear map:
#   slot 2 (MemCopy)  → 0x1004  (observed: sub_B64 executes `trap 0x1004`)
#   slot 11 (Cipher)  → 0x100D  (svm_isa_ref.html §06)
SYSCALLS = [
    "SetEventHandler",     # 0x1002
    "SetEventParamBuffer", # 0x1003
    "MemCopy",             # 0x1004
    "MemSet",              # 0x1005
    "BlockXor",            # 0x1006
    "EPComplete",          # 0x1007
    "GetCATCount",         # 0x1008
    "GetCATSize",          # 0x1009
    "ReadCAT",             # 0x100A
    "Random",              # 0x100B
    "GetHash",             # 0x100C
    "Cipher",              # 0x100D  ★ AES / DES etc. (analyze.txt §2)
    "GenSignature",        # 0x100E
    "VerifySignature",     # 0x100F
    "PKEncryption",        # 0x1010
    "PKDecryption",        # 0x1011
    "GetPublicKey",        # 0x1012
    "SVMSpec",             # 0x1013
    "GetTime",             # 0x1014
    "MapContentBuffer",    # 0x1015
    "SetDescrambleKey",    # 0x1016
    "SocketOpen",          # 0x1017
    "SocketClose",         # 0x1018
    "SocketRead",          # 0x1019
    "SocketWrite",         # 0x101A
    "CreateThread",        # 0x101B
    "ExitThread",          # 0x101C
    "MutexLock",           # 0x101D
    "MutexUnlock",         # 0x101E
    "SetLastError",        # 0x101F
    "GetMAC",              # 0x1020
    "GetUID",              # 0x1021
    "SetKeyPair",          # 0x1022
    "GetSocketOpt",        # 0x1023
    "SetSocketOpt",        # 0x1024
    "Select",              # 0x1025
    "GetHostByName",       # 0x1026
    "SlotOpen",            # 0x1027
    "SlotRead",            # 0x1028
    "SlotWrite",           # 0x1029
    "SlotClose",           # 0x102A
    "Sleep",               # 0x102B
    "MutexTryLock",        # 0x102C
    "RemoveKeyID",         # 0x102D
    "PutLog",              # 0x102E
    "MemComp",             # 0x102F
    "SetCASFilter",        # 0x1030
    "CASNotify",           # 0x1031
]
TRAP_BASE = 0x1002
TRAP_ASSERT = 0x8001

# reverse: name -> trap#
SYSCALL_TRAP = {n: TRAP_BASE + i for i, n in enumerate(SYSCALLS)}


def sxt(val: int, bits: int) -> int:
    m = 1 << (bits - 1)
    return (val & (m - 1)) - (val & m)


def s32(v: int) -> int:
    return sxt(v & M32, 32)


def u32(v: int) -> int:
    return v & M32


class DLXFault(Exception):
    pass


class DLX:
    def __init__(self, rom: bytes):
        assert len(rom) == 0xC3680, f"rom size {len(rom):#x} != 0xC3680"
        self.mem = bytearray(MEM_SIZE)
        self.mem[0:len(rom)] = rom
        self.regs = [0] * 32
        self.pc = 0
        self.halted = False
        self.trace = False
        self.instr_count = 0
        self.max_instrs = 10_000_000

        # PC -> Python hook to execute in place of native DLX code
        self.hooks: dict[int, callable] = {}
        # trap# -> Python syscall handler
        self.syscalls: dict[int, callable] = {}

    # ---------------- memory ----------------
    def r32(self, a: int) -> int:
        return struct.unpack_from(">I", self.mem, a & M32)[0]

    def w32(self, a: int, v: int) -> None:
        struct.pack_into(">I", self.mem, a & M32, v & M32)

    def r16u(self, a: int) -> int:
        return struct.unpack_from(">H", self.mem, a & M32)[0]

    def r16s(self, a: int) -> int:
        return sxt(self.r16u(a), 16)

    def w16(self, a: int, v: int) -> None:
        struct.pack_into(">H", self.mem, a & M32, v & 0xFFFF)

    def r8u(self, a: int) -> int:
        return self.mem[a & M32]

    def r8s(self, a: int) -> int:
        v = self.mem[a & M32]
        return v - 256 if v & 0x80 else v

    def w8(self, a: int, v: int) -> None:
        self.mem[a & M32] = v & 0xFF

    # ---------------- registers ----------------
    def R(self, i: int) -> int:
        return self.regs[i] & M32 if i else 0

    def setR(self, i: int, v: int) -> None:
        if i:
            self.regs[i] = v & M32

    # ---------------- hosted memcpy / memset (legacy PC hooks) ----------------
    def hook_memcpy(self):
        sp = self.R(29)
        dst = self.r32(sp);  src = self.r32(sp + 4);  n = self.r32(sp + 8)
        self.mem[dst:dst + n] = self.mem[src:src + n]
        self.setR(1, 0)
        self.pc = self.R(31)

    def hook_memset(self):
        sp = self.R(29)
        dst = self.r32(sp);  val = self.r32(sp + 4) & 0xFF;  n = self.r32(sp + 8)
        for i in range(n):
            self.mem[dst + i] = val
        self.setR(1, 0)
        self.pc = self.R(31)

    # ---------------- SYSCALL trap handlers ----------------
    # Each handler:
    #   - reads args from the stack at [r29+0], [r29+4], ...
    #     (caller allocated these slots before `trap`; the trap wrapper
    #      function's own frame is on top, so args are actually at
    #      [r30+0], [r30+4], ... just like a regular DLX call)
    #   - writes return value into r1
    #   - does NOT touch PC (the trap opcode itself already advanced PC)
    #
    # Since the trap is invoked from inside a thin wrapper function
    # (e.g. sub_B64 = memcpy) which set up r30 = r29 before the trap,
    # the args are at r30+0, r30+4, r30+8 ...
    def sys_memcpy(self):
        fp = self.R(30)
        dst = self.r32(fp);  src = self.r32(fp + 4);  n = self.r32(fp + 8)
        self.mem[dst:dst + n] = self.mem[src:src + n]
        self.setR(1, 0)

    def sys_memset(self):
        fp = self.R(30)
        dst = self.r32(fp);  val = self.r32(fp + 4) & 0xFF;  n = self.r32(fp + 8)
        for i in range(n):
            self.mem[dst + i] = val
        self.setR(1, 0)

    def sys_memcomp(self):
        fp = self.R(30)
        a = self.r32(fp);  b = self.r32(fp + 4);  n = self.r32(fp + 8)
        rv = 0
        for i in range(n):
            d = self.mem[a + i] - self.mem[b + i]
            if d:
                rv = 1 if d > 0 else 0xFFFFFFFF
                break
        self.setR(1, rv)

    def sys_blockxor(self):
        # SYSCALL_BlockXor(dst, src, len) — dst ^= src, byte-wise
        fp = self.R(30)
        dst = self.r32(fp);  src = self.r32(fp + 4);  n = self.r32(fp + 8)
        for i in range(n):
            self.mem[dst + i] ^= self.mem[src + i]
        self.setR(1, 0)

    def sys_gethash(self):
        # SYSCALL_GetHash(md_out, src, src_len, alg)
        # alg values (mapped to what SVM callers use):
        #   0 = MD5    (16B output)
        #   1 = SHA-1  (20B output)
        #   2 = SHA-224, 3 = SHA-256, 4 = SHA-384, 5 = SHA-512 (per GP TEE)
        import hashlib
        fp = self.R(30)
        md_out = self.r32(fp);  src = self.r32(fp + 4)
        n      = self.r32(fp + 8);  alg = self.r32(fp + 12)
        data = bytes(self.mem[src:src + n])
        if   alg == 0: d = hashlib.md5(data).digest()
        elif alg == 1: d = hashlib.sha1(data).digest()
        elif alg == 2: d = hashlib.sha224(data).digest()
        elif alg == 3: d = hashlib.sha256(data).digest()
        elif alg == 4: d = hashlib.sha384(data).digest()
        elif alg == 5: d = hashlib.sha512(data).digest()
        else:
            raise DLXFault(f"sys_gethash: unsupported alg {alg}")
        self.mem[md_out:md_out + len(d)] = d
        self.setR(1, 0)

    def sys_casnotify(self):
        # SYSCALL_CASNotify(event_id, ...) — best-effort stub for offline use
        self.setR(1, 0)

    def sys_putlog_silent(self):
        # PutLog stub that does nothing (avoids trace-only output flooding)
        self.setR(1, 0)

    def sys_setlasterror(self):
        # SYSCALL_SetLastError(code) — record but don't fail
        self.setR(1, 0)

    def sys_cipher(self):
        # SYSCALL_Cipher(out, outLen, in, inLen, key, keyLen, iv, ivLen, alg)
        # alg packed per analyze.txt §3:
        #   HIBYTE=cipher family (3=AES-128), BYTE1=mode (0=ECB,1=CBC,2=OFB),
        #   BYTE2=direction (0=Enc,1=Dec), LOBYTE=padding (0=block,1=PKCS,2=truncate)
        from Crypto.Cipher import AES, DES, DES3
        fp = self.R(30)
        out_p   = self.r32(fp + 0);   out_len_p = self.r32(fp + 4)
        in_p    = self.r32(fp + 8);   in_len    = self.r32(fp + 12)
        key_p   = self.r32(fp + 16);  key_len   = self.r32(fp + 20)
        iv_p    = self.r32(fp + 24);  iv_len    = self.r32(fp + 28)
        alg     = self.r32(fp + 32)

        family = (alg >> 24) & 0xFF
        mode_b = (alg >> 16) & 0xFF
        direction = (alg >> 8) & 0xFF
        pad     = alg & 0xFF

        ct = bytes(self.mem[in_p:in_p + in_len])
        key = bytes(self.mem[key_p:key_p + key_len])
        iv  = bytes(self.mem[iv_p:iv_p + iv_len]) if iv_p and iv_len else b""

        if family == 3:  # AES-128
            if   mode_b == 0: cipher = AES.new(key, AES.MODE_ECB)
            elif mode_b == 1: cipher = AES.new(key, AES.MODE_CBC, iv)
            elif mode_b == 2: cipher = AES.new(key, AES.MODE_OFB, iv)
            else: raise DLXFault(f"unsupported AES mode {mode_b}")
        elif family == 0:  # DES
            if   mode_b == 0: cipher = DES.new(key, DES.MODE_ECB)
            elif mode_b == 1: cipher = DES.new(key, DES.MODE_CBC, iv)
            else: raise DLXFault(f"unsupported DES mode {mode_b}")
        elif family in (1, 2):  # DES-EDE / DES-EDE3
            if   mode_b == 0: cipher = DES3.new(key, DES3.MODE_ECB)
            elif mode_b == 1: cipher = DES3.new(key, DES3.MODE_CBC, iv)
            else: raise DLXFault(f"unsupported DES3 mode {mode_b}")
        else:
            raise DLXFault(f"cipher family {family} not implemented")

        pt = cipher.decrypt(ct) if direction == 1 else cipher.encrypt(ct)

        # padding=1 PKCS7 strip on decrypt
        if direction == 1 and pad == 1 and pt:
            n = pt[-1]
            if 1 <= n <= 16 and pt[-n:] == bytes([n]) * n:
                pt = pt[:-n]

        self.mem[out_p:out_p + len(pt)] = pt
        if out_len_p:
            self.w32(out_len_p, len(pt))
        self.setR(1, 0)

    def sys_random(self):
        # SYSCALL_Random(out, len) — fills buffer with random bytes
        import os
        fp = self.R(30)
        out_p = self.r32(fp);  n = self.r32(fp + 4)
        self.mem[out_p:out_p + n] = os.urandom(n)
        self.setR(1, 0)

    def sys_gettime(self):
        # SYSCALL_GetTime(out_ts32)
        import time
        fp = self.R(30)
        out_p = self.r32(fp)
        self.w32(out_p, int(time.time()))
        self.setR(1, 0)

    def sys_putlog(self):
        # SYSCALL_PutLog(fmt, ...) — best-effort dump
        fp = self.R(30)
        fmt_p = self.r32(fp)
        s = bytearray()
        while self.mem[fmt_p] and len(s) < 256:
            s.append(self.mem[fmt_p]); fmt_p += 1
        if self.trace:
            try: print("  [SVM log]", s.decode(errors='replace'))
            except Exception: pass
        self.setR(1, 0)

    def sys_assert(self):
        raise DLXFault(f"svm_trap_sys_8001 (assert/panic) hit @ pc={self.pc:#x}")

    def install_default_syscalls(self):
        """Wire up the trap handlers we've implemented."""
        n2t = SYSCALL_TRAP
        self.syscalls[n2t["MemCopy"]]  = lambda vm: vm.sys_memcpy()
        self.syscalls[n2t["MemSet"]]   = lambda vm: vm.sys_memset()
        self.syscalls[n2t["MemComp"]]  = lambda vm: vm.sys_memcomp()
        self.syscalls[n2t["BlockXor"]] = lambda vm: vm.sys_blockxor()
        self.syscalls[n2t["GetHash"]]  = lambda vm: vm.sys_gethash()
        self.syscalls[n2t["Cipher"]]   = lambda vm: vm.sys_cipher()
        self.syscalls[n2t["Random"]]   = lambda vm: vm.sys_random()
        self.syscalls[n2t["GetTime"]]  = lambda vm: vm.sys_gettime()
        self.syscalls[n2t["PutLog"]]   = lambda vm: vm.sys_putlog()
        self.syscalls[n2t["CASNotify"]]    = lambda vm: vm.sys_casnotify()
        self.syscalls[n2t["SetLastError"]] = lambda vm: vm.sys_setlasterror()
        self.syscalls[TRAP_ASSERT]     = lambda vm: vm.sys_assert()

    # ---------------- fetch / decode / execute ----------------
    def step(self):
        # sentinel: r31=0 return → halt
        if self.pc == 0:
            self.halted = True
            return

        # native hook?
        if self.pc in self.hooks:
            self.hooks[self.pc]()
            return

        self.instr_count += 1
        if self.instr_count > self.max_instrs:
            raise DLXFault(f"runaway execution @ pc={self.pc:#x}")

        ins   = self.r32(self.pc)
        op    = (ins >> 26) & 0x3F
        rd    = (ins >> 21) & 0x1F
        rs1   = (ins >> 16) & 0x1F
        rs2   = (ins >> 11) & 0x1F
        imm16 = ins & 0xFFFF
        simm  = sxt(imm16, 16)
        shamt = ins & 0x1F
        imm26 = sxt(ins & 0x03FFFFFF, 26)

        pc0 = self.pc
        pc_next = pc0 + 4

        # convenience
        A = self.R(rs1); B = self.R(rs2); D = self.R(rd)

        if op == 0x00:                            # nop
            pass
        elif op == 0x01: self.setR(rd, A + B)              # add
        elif op == 0x02: self.setR(rd, A + simm)           # addi
        elif op == 0x03: self.setR(rd, A + imm16)          # addui
        elif op == 0x04: self.setR(rd, A - B)              # sub
        elif op == 0x05: self.setR(rd, A - simm)           # subi
        elif op == 0x06: self.setR(rd, A - imm16)          # subui
        elif op == 0x07:                                   # div signed
            b = s32(B)
            self.setR(rd, 0 if b == 0 else int(s32(A) / b))
        elif op == 0x08:                                   # divu unsigned
            self.setR(rd, 0 if B == 0 else A // B)
        elif op == 0x09: self.setR(rd, A * B)              # mul

        elif op == 0x0A: self.setR(rd, A << (B & 0x1F))    # sll
        elif op == 0x0B: self.setR(rd, A << shamt)         # slli
        elif op == 0x0C: self.setR(rd, A >> (B & 0x1F))    # srl (logical)
        elif op == 0x0D: self.setR(rd, A >> shamt)         # srli (logical)
        elif op == 0x0E:                                   # sra (arithmetic)
            self.setR(rd, (s32(A) >> (B & 0x1F)) & M32)
        elif op == 0x0F:                                   # srai
            self.setR(rd, (s32(A) >> shamt) & M32)

        elif op == 0x10: self.setR(rd, A & B)              # and
        elif op == 0x11: self.setR(rd, A & imm16)          # andi (I-u)
        elif op == 0x12: self.setR(rd, A | B)              # or
        elif op == 0x13: self.setR(rd, A | imm16)          # ori
        elif op == 0x14: self.setR(rd, A ^ B)              # xor
        elif op == 0x15: self.setR(rd, A ^ imm16)          # xori

        # set-compares (all produce 0 or 1)
        elif op == 0x16: self.setR(rd, 1 if s32(A) <  s32(B) else 0)  # slt
        elif op == 0x17: self.setR(rd, 1 if A       <  B       else 0)  # sltu
        elif op == 0x18: self.setR(rd, 1 if s32(A) <  simm    else 0)  # slti
        elif op == 0x19: self.setR(rd, 1 if A       <  imm16   else 0)  # sltui
        elif op == 0x1A: self.setR(rd, 1 if s32(A) >  s32(B) else 0)  # sgt
        elif op == 0x1B: self.setR(rd, 1 if A       >  B       else 0)  # sgtu
        elif op == 0x1C: self.setR(rd, 1 if s32(A) >  simm    else 0)  # sgti
        elif op == 0x1D: self.setR(rd, 1 if A       >  imm16   else 0)  # sgtui
        elif op == 0x1E: self.setR(rd, 1 if s32(A) <= s32(B) else 0)  # sle
        elif op == 0x1F: self.setR(rd, 1 if A       <= B       else 0)  # sleu
        elif op == 0x20: self.setR(rd, 1 if s32(A) <= simm    else 0)  # slei
        elif op == 0x21: self.setR(rd, 1 if A       <= imm16   else 0)  # sleui
        elif op == 0x22: self.setR(rd, 1 if s32(A) >= s32(B) else 0)  # sge
        elif op == 0x23: self.setR(rd, 1 if A       >= B       else 0)  # sgeu
        elif op == 0x24: self.setR(rd, 1 if s32(A) >= simm    else 0)  # sgei
        elif op == 0x25: self.setR(rd, 1 if A       >= imm16   else 0)  # sgeui
        elif op == 0x26: self.setR(rd, 1 if A ==     B         else 0)  # seq
        elif op == 0x27: self.setR(rd, 1 if s32(A) == simm    else 0)  # seqi
        elif op == 0x28: self.setR(rd, 1 if A !=     B         else 0)  # sne
        elif op == 0x29: self.setR(rd, 1 if s32(A) != simm    else 0)  # snei

        # branch / jump
        elif op == 0x2A:                                   # beqz rs1, imm16
            if A == 0: pc_next = pc0 + 4 + simm
        elif op == 0x2B:                                   # bnez rs1, imm16
            if A != 0: pc_next = pc0 + 4 + simm
        elif op == 0x2C:                                   # j imm26
            pc_next = pc0 + 4 + imm26
        elif op == 0x2D:                                   # jr rs1
            pc_next = A                                    # rs1 was read as A
        elif op == 0x2E:                                   # jal imm26
            self.setR(31, pc0 + 4)
            pc_next = pc0 + 4 + imm26
        elif op == 0x2F:                                   # jalr rs1
            self.setR(31, pc0 + 4)
            pc_next = A

        # memory (base = rs1, offset = sx(imm16))
        elif op == 0x30: self.setR(rd, self.r8s(A + simm) & M32)   # lb  (sx byte)
        elif op == 0x31: self.setR(rd, self.r8u(A + simm))          # lbu (zx byte)
        elif op == 0x32: self.setR(rd, self.r16s(A + simm) & M32)   # lh
        elif op == 0x33: self.setR(rd, self.r16u(A + simm))          # lhu
        elif op == 0x34: self.setR(rd, self.r32(A + simm))           # lw
        elif op == 0x35: self.setR(rd, (imm16 & 0xFFFF) << 16)       # lhi
        elif op == 0x36: self.w8( A + simm, D)                       # sb
        elif op == 0x37: self.w16(A + simm, D)                       # sh
        elif op == 0x38: self.w32(A + simm, D)                       # sw

        elif op == 0x39:                                    # trap imm26
            handler = self.syscalls.get(imm26)
            if handler is None:
                raise DLXFault(f"unhandled trap #{imm26:#x} @ pc={pc0:#x}")
            handler(self)

        else:
            raise DLXFault(f"invalid opcode 0x{op:02x} @ pc={pc0:#x} ins=0x{ins:08x}")

        if self.trace:
            print(f"  pc={pc0:08x} ins={ins:08x} op={op:02x} → next={pc_next & M32:08x}"
                  f"  r1={self.R(1):08x} r29={self.R(29):08x} r30={self.R(30):08x} r31={self.R(31):08x}")

        self.pc = pc_next & M32

    def run(self):
        self.halted = False
        while not self.halted:
            self.step()

    def call(self, target: int, args: tuple[int, ...] = ()):
        """Simulate calling `target(args)`. Returns r1."""
        n_slots = max(len(args), 4)                          # reserve at least 4 slots
        self.setR(29, (self.R(29) - n_slots * 4) & M32)
        for i, a in enumerate(args):
            self.w32(self.R(29) + i * 4, a)
        self.setR(31, 0)                                      # sentinel
        self.pc = target
        self.instr_count = 0
        self.run()
        self.setR(29, (self.R(29) + n_slots * 4) & M32)
        return self.R(1)


# ---------------- phase 1 smoke test ----------------
def phase1_smoke(mode: str = "trap"):
    """
    mode='trap'  : real syscall path — trap 0x1004 handled by sys_memcpy,
                   trap 0x1005 by sys_memset. sub_B64/sub_D2C execute their
                   DLX wrapper (which is basically `trap; jr r31`).
    mode='hook'  : PC hooks intercept sub_B64/sub_D2C directly, native DLX
                   never sees the trap.
    """
    svm = DLX(ROM_PATH.read_bytes())
    if mode == "hook":
        svm.hooks[0xB64] = svm.hook_memcpy
        svm.hooks[0xD2C] = svm.hook_memset
    elif mode == "trap":
        svm.install_default_syscalls()
    else:
        raise ValueError(mode)
    svm.setR(29, STACK_TOP)

    dst = ARG_BUF
    svm.call(0x144D4, args=(dst,))

    out = bytes(svm.mem[dst:dst + 16])
    expected = bytes.fromhex("D48EEA666E09F5A05CBAC2F8FBD47EE0")
    print(f"mode      = {mode}")
    print(f"out       = {out.hex()}")
    print(f"expected  = {expected.hex()}")
    print(f"instrs    = {svm.instr_count}")
    ok = (out == expected)
    print("PASS" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    phase1_smoke(mode="trap")
    phase1_smoke(mode="hook")
