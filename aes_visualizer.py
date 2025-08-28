# aes_verbose_demo.py
# AES-128 educational simulator: very detailed, binary-level log + human explanations.
# Requires: pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import string

# ---------- AES S-Box (standard) ----------
SBOX = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

# ---------- Utilities ----------
def byte_to_bin(b): return format(b, '08b')
def is_printable(b): return chr(b) in string.printable and b >= 32 and b < 127

def pretty_matrix(state):
    # state: 16-byte list (column-major). Return 4x4 rows of tuples (hex, bin, char)
    rows = []
    for r in range(4):
        row = []
        for c in range(4):
            idx = r + 4*c  # column-major mapping
            b = state[idx]
            row.append((f"{b:02X}", byte_to_bin(b), chr(b) if is_printable(b) else '.'))
        rows.append(row)
    return rows

def print_matrix_readable(state, logger, title="State"):
    rows = pretty_matrix(state)
    logger.log(f"\n{title}: (format: HEX | bin | char)\n")
    for r in range(4):
        line = " | ".join(f"{h} {binv} {ch}" for (h,binv,ch) in rows[r])
        logger.log(line)
    logger.log("")  # blank

# ---------- GF(2^8) multiply helpers with detailed trace ----------
def xtime_detail(a):
    """Return (result, explanation_string) for multiply-by-2 (×2)"""
    b = a << 1
    carry = (a & 0x80) != 0
    b &= 0xFF
    explain = f"{a:02X} ({byte_to_bin(a)}) << 1 => {b:02X} ({byte_to_bin(b)})"
    if carry:
        b ^= 0x1B
        explain += f"  carry=1 → XOR 0x1B -> {b:02X} ({byte_to_bin(b)})"
    else:
        explain += "  carry=0 → no reduction"
    return b, explain

def mul_detail(a, factor):
    """Return (value, explanation) computing a*factor where factor is 1,2,3"""
    if factor == 1:
        return a, f"{a:02X} (×1 = same)"
    if factor == 2:
        val, expl = xtime_detail(a)
        return val, f"2×{a:02X}: {expl}"
    if factor == 3:
        val2, expl2 = xtime_detail(a)
        val3 = val2 ^ a
        expl = f"3×{a:02X} = (2×{a:02X}) XOR {a:02X}\n  (2× part) {expl2}\n  XOR: {val2:02X} ({byte_to_bin(val2)}) XOR {a:02X} ({byte_to_bin(a)}) = {val3:02X} ({byte_to_bin(val3)})"
        return val3, expl
    raise ValueError("Only 1,2,3 supported in AES MixColumns")

# ---------- Key schedule (AES-128) ----------
def rot_word(w): return w[1:]+w[:1]
def sub_word(w): return [SBOX[b] for b in w]

def expand_key(key16):
    assert len(key16) == 16
    w = [list(key16[4*i:4*i+4]) for i in range(4)]
    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i//4]
        w.append([ (w[i-4][j] ^ temp[j]) & 0xFF for j in range(4) ])
    # produce round keys as 16-byte lists (0..10)
    rks = []
    for r in range(11):
        words = w[4*r:4*(r+1)]
        rk = []
        for word in words:
            rk.extend(word)
        rks.append(rk)
    return rks

# ---------- Logger ----------
class Logger:
    def __init__(self, filename="aes_verbose_log.txt"):
        self.f = open(filename, "w", encoding="utf-8")
    def log(self, s=""):
        print(s)
        self.f.write(s+"\n")
    def close(self):
        self.f.close()

# ---------- AES verbose demo ----------
def aes_verbose_demo(plaintext, key):
    # prep
    logger = Logger()
    logger.log("AES-128 VERBOSE SIMULATOR\n")
    logger.log("Short guide: each block prints HEX | binary | printable-char (.) if non-printable)")
    logger.log("MixColumns calculations show binary steps for ×2 and ×3 and final XOR chain.\n")

    pt = pad(plaintext.encode('utf-8'), 16)  # one block
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    state = list(pt[:16])

    logger.log(f"Plaintext: '{plaintext}'")
    logger.log(f"Key: '{key}'\n")
    print_matrix_readable(state, logger, "Initial State (before any key)")

    # key schedule
    rks = expand_key(key.encode('utf-8'))
    for i, rk in enumerate(rks):
        logger.log(f"RoundKey {i}: " + " ".join(f"{b:02X}" for b in rk))

    # Initial AddRoundKey (Round 0)
    logger.log("\n=== Initial AddRoundKey (Round 0) ===")
    rk0 = rks[0]
    logger.log("RoundKey 0 matrix (HEX):")
    print_matrix_readable(rk0, logger, "RoundKey 0 (as matrix)")
    # show XOR for each byte
    logger.log("XOR each state byte with corresponding roundkey byte (binary shown):")
    for i, (s,k) in enumerate(zip(state, rk0)):
        logger.log(f"  pos[{i}] {s:02X} ({byte_to_bin(s)}) XOR {k:02X} ({byte_to_bin(k)}) = {(s^k):02X} ({byte_to_bin(s^k)})")
    state = [s ^ k for s,k in zip(state, rk0)]
    print_matrix_readable(state, logger, "State after AddRoundKey (Round 0)")

    # Rounds 1..10
    for rnd in range(1, 11):
        logger.log(f"\n\n########## ROUND {rnd} ##########")
        # SubBytes
        logger.log("\n-- SubBytes (bytewise S-Box substitution) --")
        new_state = []
        for idx, b in enumerate(state):
            after = SBOX[b]
            logger.log(f" pos[{idx}] : {b:02X} ({byte_to_bin(b)})  ->  {after:02X} ({byte_to_bin(after)})    (S-box)")
            new_state.append(after)
        state = new_state
        print_matrix_readable(state, logger, f"State after SubBytes (Round {rnd})")

        # ShiftRows
        logger.log("\n-- ShiftRows (row-wise left rotate) --")
        # form column-major list into matrix rows (r0..r3)
        rows = pretty_matrix(state)  # each row is list of (hex,bin,char)
        # But pretty_matrix returns tuples; reconstruct raw bytes for shifting
        matrix_bytes = [ [ int(rows[r][c][0], 16) for c in range(4) ] for r in range(4) ]
        for r in range(1,4):
            before = [byte_to_bin(x) for x in matrix_bytes[r]]
            # perform left rotate by r
            matrix_bytes[r] = matrix_bytes[r][r:] + matrix_bytes[r][:r]
            after = [byte_to_bin(x) for x in matrix_bytes[r]]
            logger.log(f" Row {r}: {before}  ->  {after}")
        # flatten back to column-major state representation
        state = []
        for c in range(4):
            for r in range(4):
                state.append(matrix_bytes[r][c])
        print_matrix_readable(state, logger, f"State after ShiftRows (Round {rnd})")

        # MixColumns (skip in final round)
        if rnd != 10:
            logger.log("\n-- MixColumns (column mixing in GF(2^8)) --")
            mixed = [0]*16
            for c in range(4):
                # extract column (a0,a1,a2,a3) in column-major indices
                a0 = state[0 + 4*c]
                a1 = state[1 + 4*c]
                a2 = state[2 + 4*c]
                a3 = state[3 + 4*c]
                logger.log(f"\n Column {c} input: {[f'{x:02X}' for x in (a0,a1,a2,a3)]}")
                # compute with details
                v2_a0, expl2_a0 = mul_detail(a0,2)
                v3_a1, expl3_a1 = mul_detail(a1,3)
                # show steps for c0
                logger.log(f"  -> computing c0 = (2·a0) ⊕ (3·a1) ⊕ a2 ⊕ a3")
                logger.log(f"     2·a0 detail: {expl2_a0}")
                logger.log(f"     3·a1 detail: {expl3_a1}")
                logger.log(f"     a2 = {a2:02X} ({byte_to_bin(a2)}), a3 = {a3:02X} ({byte_to_bin(a3)})")
                c0 = (v2_a0 ^ v3_a1 ^ a2 ^ a3) & 0xFF
                logger.log(f"     XOR chain: {v2_a0:02X} ^ {v3_a1:02X} ^ {a2:02X} ^ {a3:02X} = {c0:02X} ({byte_to_bin(c0)})")

                # c1
                v2_a1, expl2_a1 = mul_detail(a1,2)
                v3_a2, expl3_a2 = mul_detail(a2,3)
                logger.log(f"  -> computing c1 = a0 ⊕ (2·a1) ⊕ (3·a2) ⊕ a3")
                logger.log(f"     2·a1 detail: {expl2_a1}")
                logger.log(f"     3·a2 detail: {expl3_a2}")
                c1 = (a0 ^ v2_a1 ^ v3_a2 ^ a3) & 0xFF
                logger.log(f"     XOR chain: {a0:02X} ^ {v2_a1:02X} ^ {v3_a2:02X} ^ {a3:02X} = {c1:02X} ({byte_to_bin(c1)})")

                # c2
                v2_a2, expl2_a2 = mul_detail(a2,2)
                v3_a3, expl3_a3 = mul_detail(a3,3)
                logger.log(f"  -> computing c2 = a0 ⊕ a1 ⊕ (2·a2) ⊕ (3·a3)")
                logger.log(f"     2·a2 detail: {expl2_a2}")
                logger.log(f"     3·a3 detail: {expl3_a3}")
                c2 = (a0 ^ a1 ^ v2_a2 ^ v3_a3) & 0xFF
                logger.log(f"     XOR chain: {a0:02X} ^ {a1:02X} ^ {v2_a2:02X} ^ {v3_a3:02X} = {c2:02X} ({byte_to_bin(c2)})")

                # c3
                v3_a0, expl3_a0 = mul_detail(a0,3)
                v2_a3, expl2_a3 = mul_detail(a3,2)
                logger.log(f"  -> computing c3 = (3·a0) ⊕ a1 ⊕ a2 ⊕ (2·a3)")
                logger.log(f"     3·a0 detail: {expl3_a0}")
                logger.log(f"     2·a3 detail: {expl2_a3}")
                c3 = (v3_a0 ^ a1 ^ a2 ^ v2_a3) & 0xFF
                logger.log(f"     XOR chain: {v3_a0:02X} ^ {a1:02X} ^ {a2:02X} ^ {v2_a3:02X} = {c3:02X} ({byte_to_bin(c3)})")

                # place results in mixed state (column-major)
                mixed[0 + 4*c] = c0
                mixed[1 + 4*c] = c1
                mixed[2 + 4*c] = c2
                mixed[3 + 4*c] = c3

            state = mixed
            print_matrix_readable(state, logger, f"State after MixColumns (Round {rnd})")

        # AddRoundKey using round key rks[rnd]
        logger.log("\n-- AddRoundKey (XOR with round key) --")
        rk = rks[rnd]
        print_matrix_readable(rk, logger, f"RoundKey {rnd} (as matrix)")
        logger.log("Bytewise XOR (state ^ roundkey):")
        for i, (s,k) in enumerate(zip(state, rk)):
            logger.log(f" pos[{i}] : {s:02X} ({byte_to_bin(s)}) XOR {k:02X} ({byte_to_bin(k)}) = {(s^k):02X} ({byte_to_bin(s^k)})")
        state = [s ^ k for s,k in zip(state, rk)]
        print_matrix_readable(state, logger, f"State after AddRoundKey (Round {rnd})")

    # final ciphertext (validate with library)
    ct = cipher.encrypt(pt)
    logger.log("\n=== Final Result ===")
    logger.log("Ciphertext (hex): " + ct.hex())
    logger.close()
    return ct

if __name__ == "__main__":
    # Example: exactly 16 bytes plaintext and key
    PLAINTEXT = "HELLO WORLD 1234"
    KEY = "Thats my Kung Fu"
    aes_verbose_demo(PLAINTEXT, KEY)
