#!/usr/bin/env python3
"""
AES-CBC validation tool for telemt middle proxy logs with support for noop padding.

Parses log lines containing:
  - "ME diag: derived keys and handshake plaintext" (provides write_key, write_iv, hs_plain)
  - "ME diag: handshake ciphertext" (provides hs_cipher)

For each pair it:
  - Decrypts the ciphertext using the provided key and IV.
  - Compares the beginning of the decrypted data with hs_plain.
  - Attempts to identify the actual padding scheme (PKCS#7, zero padding, noop padding).
  - Re-encrypts with different paddings and reports mismatches block by block.
  - Accumulates statistics for final summary.
"""

import sys
import re
from collections import defaultdict
from Crypto.Cipher import AES

# Constants
NOOP_FRAME = bytes([0x04, 0x00, 0x00, 0x00])   # noop frame used for padding

def hex_str_to_bytes(hex_str):
    """Convert a hex string like 'aa bb cc' to bytes."""
    return bytes.fromhex(hex_str.replace(' ', ''))

def parse_params(line):
    """Extract key=value pairs where value is a space-separated hex string."""
    pattern = r'(\w+)=((?:[0-9a-f]{2} )*[0-9a-f]{2})'
    return {key: val for key, val in re.findall(pattern, line)}

def pkcs7_pad(data, block_size=16):
    """Apply PKCS#7 padding to the given data."""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def zero_pad(data, block_size=16):
    """Pad with zeros to the next block boundary."""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == block_size:
        return data  # already full blocks, no zero padding needed
    return data + bytes(pad_len)

def noop_pad(data):
    """
    Pad with minimal number of noop frames (b'\\x04\\x00\\x00\\x00')
    to reach a multiple of 16 bytes.
    """
    block_size = 16
    frame_len = len(NOOP_FRAME)  # 4
    remainder = len(data) % block_size
    if remainder == 0:
        return data  # no padding needed
    # We need to add k frames such that (len(data) + k*frame_len) % block_size == 0
    # => k*frame_len ≡ -remainder (mod block_size)
    # Since frame_len=4 and block_size=16, we need k*4 ≡ (16-remainder) mod 16
    # k must be an integer in {1,2,3} (because 4*4=16 ≡0 mod16, so k=4 gives remainder 0, but then total increase=16,
    # but if remainder==0 we already handled; if remainder!=0, k=4 gives (len+16)%16 == remainder, not 0,
    # so k=4 doesn't solve unless remainder=0. Actually 4*4=16 ≡0, so k=4 gives (len+16)%16 = remainder, so still not 0.
    # The equation is k*4 ≡ (16-remainder) mod 16. Let r=16-remainder (1..15). Then k ≡ r*inv(4) mod 4? Since mod 16,
    # 4 has no inverse modulo 16 because gcd(4,16)=4. So solutions exist only if r is multiple of 4.
    # Therefore remainder must be 4,8,12 (so that r = 12,8,4). This matches the idea that noop padding is only added
    # when the plaintext length mod 16 is 4,8,12. In our logs it's always 44 mod16=12, so r=4, so k=1 works.
    # For safety, we compute k as (block_size - remainder) // frame_len, but this only works if that value is integer.
    need = block_size - remainder
    if need % frame_len != 0:
        # This shouldn't happen by protocol, but if it does, fall back to adding full blocks of noop until multiple.
        # We'll add ceil(need/frame_len) frames.
        k = (need + frame_len - 1) // frame_len
    else:
        k = need // frame_len
    return data + NOOP_FRAME * k

def unpad_pkcs7(data):
    """Remove PKCS#7 padding (assumes correct padding)."""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data  # not valid PKCS#7, return as is
    # Check that all padding bytes are equal to pad_len
    if all(b == pad_len for b in data[-pad_len:]):
        return data[:-pad_len]
    return data

def is_noop_padded(decrypted, plain_log):
    """
    Check if the extra bytes after plain_log in decrypted consist of one or more NOOP_FRAMEs.
    Returns True if they do, False otherwise.
    """
    extra = decrypted[len(plain_log):]
    if len(extra) == 0:
        return False
    # Split into chunks of 4
    if len(extra) % 4 != 0:
        return False
    for i in range(0, len(extra), 4):
        if extra[i:i+4] != NOOP_FRAME:
            return False
    return True

def main():
    derived_list = []   # entries from "derived keys and handshake plaintext"
    cipher_list = []    # entries from "handshake ciphertext"

    for line in sys.stdin:
        if 'ME diag: derived keys and handshake plaintext' in line:
            params = parse_params(line)
            if all(k in params for k in ('write_key', 'write_iv', 'hs_plain')):
                derived_list.append(params)
        elif 'ME diag: handshake ciphertext' in line:
            params = parse_params(line)
            if 'hs_cipher' in params:
                cipher_list.append(params)

    # Warn about count mismatch but process as many pairs as possible
    n_pairs = min(len(derived_list), len(cipher_list))
    if len(derived_list) != len(cipher_list):
        print(f"\n[WARN] Number of derived entries ({len(derived_list)}) "
              f"differs from cipher entries ({len(cipher_list)}). "
              f"Processing first {n_pairs} pairs.\n")

    # Statistics accumulators
    stats = {
        'total': n_pairs,
        'key_length_ok': 0,
        'iv_length_ok': 0,
        'cipher_aligned': 0,
        'decryption_match_start': 0,      # first bytes equal hs_plain
        'pkcs7_after_unpad_matches': 0,   # after removing PKCS7, equals hs_plain
        'extra_bytes_all_zero': 0,         # extra bytes after hs_plain are zero
        'extra_bytes_noop': 0,             # extra bytes are noop frames
        'pkcs7_encrypt_ok': 0,             # re-encryption with PKCS7 matches ciphertext
        'zero_encrypt_ok': 0,               # re-encryption with zero padding matches
        'noop_encrypt_ok': 0,                # re-encryption with noop padding matches
        'no_padding_encrypt_ok': 0,         # only if plaintext multiple of 16 and matches
        'no_padding_applicable': 0,         # number of tests where plaintext len %16 ==0
    }

    detailed_results = []  # store per-test summary for final heuristic

    for idx, (der, ciph) in enumerate(zip(derived_list[:n_pairs], cipher_list[:n_pairs]), 1):
        print(f"\n{'='*60}")
        print(f"Test #{idx}")
        print(f"{'='*60}")

        # Local stats for this test
        test_stats = defaultdict(bool)

        try:
            key = hex_str_to_bytes(der['write_key'])
            iv = hex_str_to_bytes(der['write_iv'])
            plain_log = hex_str_to_bytes(der['hs_plain'])
            ciphertext = hex_str_to_bytes(ciph['hs_cipher'])

            # Basic sanity checks
            print(f"[INFO] Key length       : {len(key)} bytes (expected 32)")
            print(f"[INFO] IV length        : {len(iv)} bytes (expected 16)")
            print(f"[INFO] hs_plain length  : {len(plain_log)} bytes")
            print(f"[INFO] hs_cipher length : {len(ciphertext)} bytes")

            if len(key) == 32:
                stats['key_length_ok'] += 1
                test_stats['key_ok'] = True
            else:
                print("[WARN] Key length is not 32 bytes – AES-256 requires 32-byte key.")

            if len(iv) == 16:
                stats['iv_length_ok'] += 1
                test_stats['iv_ok'] = True
            else:
                print("[WARN] IV length is not 16 bytes – AES-CBC requires 16-byte IV.")

            if len(ciphertext) % 16 == 0:
                stats['cipher_aligned'] += 1
                test_stats['cipher_aligned'] = True
            else:
                print("[ERROR] Ciphertext length is not a multiple of 16 – invalid AES-CBC block alignment.")
                # Skip further processing for this test
                detailed_results.append(test_stats)
                continue

            # --- Decryption test ---
            cipher_dec = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher_dec.decrypt(ciphertext)
            print(f"[INFO] Decrypted ({len(decrypted)} bytes): {decrypted.hex()}")

            # Compare beginning with hs_plain
            match_len = min(len(plain_log), len(decrypted))
            if decrypted[:match_len] == plain_log[:match_len]:
                print(f"[OK] First {match_len} bytes match hs_plain.")
                stats['decryption_match_start'] += 1
                test_stats['decrypt_start_ok'] = True
            else:
                print(f"[FAIL] First bytes do NOT match hs_plain.")
                for i in range(match_len):
                    if decrypted[i] != plain_log[i]:
                        print(f"       First mismatch at byte {i}: hs_plain={plain_log[i]:02x}, decrypted={decrypted[i]:02x}")
                        break
                test_stats['decrypt_start_ok'] = False

            # --- Try to identify actual padding ---
            # Remove possible PKCS#7 padding from decrypted data
            decrypted_unpadded = unpad_pkcs7(decrypted)
            if decrypted_unpadded != decrypted:
                print(f"[INFO] After removing PKCS#7 padding: {len(decrypted_unpadded)} bytes left.")
                if decrypted_unpadded == plain_log:
                    print("[OK] Decrypted data with PKCS#7 removed exactly matches hs_plain.")
                    stats['pkcs7_after_unpad_matches'] += 1
                    test_stats['pkcs7_unpad_matches'] = True
                else:
                    print("[INFO] Decrypted (PKCS#7 removed) does NOT match hs_plain.")
                    test_stats['pkcs7_unpad_matches'] = False
            else:
                print("[INFO] No valid PKCS#7 padding detected in decrypted data.")
                test_stats['pkcs7_unpad_matches'] = False

            # Check if the extra bytes after hs_plain in decrypted are all zero (zero padding)
            extra = decrypted[len(plain_log):]
            if extra and all(b == 0 for b in extra):
                print("[INFO] Extra bytes after hs_plain are all zeros – likely zero padding.")
                stats['extra_bytes_all_zero'] += 1
                test_stats['extra_zero'] = True
            else:
                test_stats['extra_zero'] = False

            # Check for noop padding in extra bytes
            if is_noop_padded(decrypted, plain_log):
                print(f"[OK] Extra bytes after hs_plain consist of noop frames ({NOOP_FRAME.hex()}).")
                stats['extra_bytes_noop'] += 1
                test_stats['extra_noop'] = True
            else:
                test_stats['extra_noop'] = False
                if extra:
                    print(f"[INFO] Extra bytes after hs_plain (hex): {extra.hex()}")

            # --- Re-encryption tests ---
            # PKCS#7
            padded_pkcs7 = pkcs7_pad(plain_log)
            cipher_enc = AES.new(key, AES.MODE_CBC, iv)
            computed_pkcs7 = cipher_enc.encrypt(padded_pkcs7)
            if computed_pkcs7 == ciphertext:
                print("[OK] PKCS#7 padding produces the expected ciphertext.")
                stats['pkcs7_encrypt_ok'] += 1
                test_stats['pkcs7_enc_ok'] = True
            else:
                print("[FAIL] PKCS#7 padding does NOT match the ciphertext.")
                test_stats['pkcs7_enc_ok'] = False
                # Show block where first difference occurs
                block_size = 16
                for blk in range(len(ciphertext)//block_size):
                    start = blk*block_size
                    exp = ciphertext[start:start+block_size]
                    comp = computed_pkcs7[start:start+block_size]
                    if exp != comp:
                        print(f"       First difference in block {blk}:")
                        print(f"         expected : {exp.hex()}")
                        print(f"         computed : {comp.hex()}")
                        break

            # Zero padding
            padded_zero = zero_pad(plain_log)
            # Ensure multiple of 16
            if len(padded_zero) % 16 != 0:
                padded_zero += bytes(16 - (len(padded_zero)%16))
            cipher_enc_zero = AES.new(key, AES.MODE_CBC, iv)
            computed_zero = cipher_enc_zero.encrypt(padded_zero)
            if computed_zero == ciphertext:
                print("[OK] Zero padding produces the expected ciphertext.")
                stats['zero_encrypt_ok'] += 1
                test_stats['zero_enc_ok'] = True
            else:
                print("[INFO] Zero padding does NOT match (expected, unless log used PKCS#7).")
                test_stats['zero_enc_ok'] = False

            # Noop padding
            padded_noop = noop_pad(plain_log)
            # Ensure multiple of 16 (noop_pad already returns multiple of 16)
            cipher_enc_noop = AES.new(key, AES.MODE_CBC, iv)
            computed_noop = cipher_enc_noop.encrypt(padded_noop)
            if computed_noop == ciphertext:
                print("[OK] Noop padding produces the expected ciphertext.")
                stats['noop_encrypt_ok'] += 1
                test_stats['noop_enc_ok'] = True
            else:
                print("[FAIL] Noop padding does NOT match the ciphertext.")
                test_stats['noop_enc_ok'] = False
                # Show block difference if needed
                for blk in range(len(ciphertext)//16):
                    start = blk*16
                    if computed_noop[start:start+16] != ciphertext[start:start+16]:
                        print(f"       First difference in block {blk}:")
                        print(f"         expected : {ciphertext[start:start+16].hex()}")
                        print(f"         computed : {computed_noop[start:start+16].hex()}")
                        break

            # No padding (only possible if plaintext is already multiple of 16)
            if len(plain_log) % 16 == 0:
                stats['no_padding_applicable'] += 1
                cipher_enc_nopad = AES.new(key, AES.MODE_CBC, iv)
                computed_nopad = cipher_enc_nopad.encrypt(plain_log)
                if computed_nopad == ciphertext:
                    print("[OK] No padding (plaintext multiple of 16) matches.")
                    stats['no_padding_encrypt_ok'] += 1
                    test_stats['no_pad_enc_ok'] = True
                else:
                    print("[INFO] No padding does NOT match.")
                    test_stats['no_pad_enc_ok'] = False
            else:
                print("[INFO] Skipping no‑padding test because plaintext length is not a multiple of 16.")

        except Exception as e:
            print(f"[EXCEPTION] {e}")
            test_stats['exception'] = True

        detailed_results.append(test_stats)

    # --- Final statistics and heuristic summary ---
    print("\n" + "="*60)
    print("STATISTICS SUMMARY")
    print("="*60)
    print(f"Total tests processed          : {stats['total']}")
    print(f"Key length OK (32)              : {stats['key_length_ok']}/{stats['total']}")
    print(f"IV length OK (16)                : {stats['iv_length_ok']}/{stats['total']}")
    print(f"Ciphertext 16-byte aligned       : {stats['cipher_aligned']}/{stats['total']}")
    print(f"Decryption starts with hs_plain  : {stats['decryption_match_start']}/{stats['total']}")
    print(f"After PKCS#7 removal matches     : {stats['pkcs7_after_unpad_matches']}/{stats['total']}")
    print(f"Extra bytes after hs_plain are 0 : {stats['extra_bytes_all_zero']}/{stats['total']}")
    print(f"Extra bytes are noop frames       : {stats['extra_bytes_noop']}/{stats['total']}")
    print(f"PKCS#7 re-encryption OK           : {stats['pkcs7_encrypt_ok']}/{stats['total']}")
    print(f"Zero padding re-encryption OK     : {stats['zero_encrypt_ok']}/{stats['total']}")
    print(f"Noop padding re-encryption OK     : {stats['noop_encrypt_ok']}/{stats['total']}")
    if stats['no_padding_applicable'] > 0:
        print(f"No-padding applicable tests      : {stats['no_padding_applicable']}")
        print(f"No-padding re-encryption OK       : {stats['no_padding_encrypt_ok']}/{stats['no_padding_applicable']}")

    # Heuristic: determine most likely padding
    print("\n" + "="*60)
    print("HEURISTIC CONCLUSION")
    print("="*60)

    if stats['decryption_match_start'] == stats['total']:
        print("✓ All tests: first bytes of decrypted data match hs_plain → keys and IV are correct.")
    else:
        print("✗ Some tests: first bytes mismatch → possible key/IV issues or corrupted ciphertext.")

    # Guess padding based on re-encryption success and extra bytes
    candidates = []
    if stats['pkcs7_encrypt_ok'] == stats['total']:
        candidates.append("PKCS#7")
    if stats['zero_encrypt_ok'] == stats['total']:
        candidates.append("zero padding")
    if stats['noop_encrypt_ok'] == stats['total']:
        candidates.append("noop padding")
    if stats['no_padding_applicable'] == stats['total'] and stats['no_padding_encrypt_ok'] == stats['total']:
        candidates.append("no padding")

    if len(candidates) == 1:
        print(f"✓ All tests consistent with padding scheme: {candidates[0]}.")
    elif len(candidates) > 1:
        print(f"⚠ Multiple padding schemes succeed in all tests: {', '.join(candidates)}. This is unusual.")
    else:
        # No scheme succeeded in all tests – look at ratios
        print("Mixed padding results:")
        total = stats['total']
        pkcs7_ratio = stats['pkcs7_encrypt_ok'] / total if total else 0
        zero_ratio = stats['zero_encrypt_ok'] / total if total else 0
        noop_ratio = stats['noop_encrypt_ok'] / total if total else 0
        print(f"  PKCS#7 success = {stats['pkcs7_encrypt_ok']}/{total} ({pkcs7_ratio*100:.1f}%)")
        print(f"  Zero success   = {stats['zero_encrypt_ok']}/{total} ({zero_ratio*100:.1f}%)")
        print(f"  Noop success   = {stats['noop_encrypt_ok']}/{total} ({noop_ratio*100:.1f}%)")

        if noop_ratio > max(pkcs7_ratio, zero_ratio):
            print("→ Noop padding is most frequent. Check if extra bytes are indeed noop frames.")
        elif pkcs7_ratio > zero_ratio:
            print("→ PKCS#7 is most frequent, but fails in some tests.")
        elif zero_ratio > pkcs7_ratio:
            print("→ Zero padding is most frequent, but fails in some tests.")
        else:
            print("→ No clear winner; possibly a different padding scheme or random data.")

    # Additional heuristics based on extra bytes
    if stats['extra_bytes_noop'] == stats['total']:
        print("✓ All tests: extra bytes after hs_plain are noop frames → strongly indicates noop padding.")
    if stats['extra_bytes_all_zero'] == stats['total']:
        print("✓ All tests: extra bytes are zeros → suggests zero padding.")

    # Final health check
    if (stats['decryption_match_start'] == stats['total'] and
        (stats['pkcs7_encrypt_ok'] == stats['total'] or
         stats['zero_encrypt_ok'] == stats['total'] or
         stats['noop_encrypt_ok'] == stats['total'] or
         stats['no_padding_encrypt_ok'] == stats['no_padding_applicable'] == stats['total'])):
        print("\n✅ OVERALL: All tests consistent. The encryption parameters and padding are correct.")
    else:
        print("\n⚠️ OVERALL: Inconsistencies detected. Review the detailed output for failing tests.")

if __name__ == '__main__':
    main()
