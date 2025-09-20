#!/usr/bin/env python3
# hp_smartmemory_ident.py
# Identify HP SmartMemory P/N from (serial,hpt) using a registry of family constants.
# Learn new families from two samples + known PN.
# NEW: compute HPT from (serial, part-number), now with support for even B coefficients.

import json, argparse, os, sys

MOD = 1 << 32
u32 = lambda x: x & 0xFFFFFFFF

REG_PATH_DEFAULT = "hp_families.json"

def inv_mod_pow2(a: int, k: int) -> int:
    """
    Computes modular inverse of a for modulus 2^k, where a is odd.
    """
    if k == 0:
        return 0
    m = 1 << k
    x = a
    # Number of iterations for 2-adic Newton-Raphson method is ceil(log2(k)).
    # 5 is enough for k<=32, 6 is enough for k<=64.
    num_iterations = 5 if k <= 32 else 6
    for _ in range(num_iterations):
        x = (x * (2 - a * x)) & (m - 1)
    return x

def load_registry(path: str):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)

def save_registry(path: str, reg: dict):
    with open(path, "w") as f:
        json.dump(reg, f, indent=2, sort_keys=True)

def parse_int(x: str) -> int:
    x = x.strip().lower()
    if x.startswith("0x"):
        return int(x, 16)
    return int(x)

def digits_to_u32_pn(pn_str: str) -> int:
    d = "".join(ch for ch in pn_str if ch.isdigit())
    if not d:
        raise ValueError("Part number must contain digits")
    return int(d) & 0xFFFFFFFF

def format_hp_pn(p_u32: int) -> str:
    dec = f"{p_u32:d}"
    return f"{dec[:-3]}-{dec[-3:]}" if len(dec) > 3 else dec

def learn_family_from_two(s1, h1, s2, h2):
    dS = u32(s1 - s2)
    dH = u32(h1 - h2)
    A  = dH
    B  = u32(-dS)
    K  = u32(A*s1 + B*h1)
    
    # Verification check
    K2 = u32(A*s2 + B*h2)
    if K != K2:
        sys.stderr.write(
            f"[WARN] Inconsistent data: K derived from sample 1 (0x{K:08X}) does not match K from sample 2 (0x{K2:08X}).\n"
            "       The learned family constants may be incorrect for this memory.\n"
        )
        
    return A, B, K

# ---------- Commands ----------

def cmd_identify(args):
    reg = load_registry(args.registry)
    serial = parse_int(args.serial) & 0xFFFFFFFF
    hpt    = parse_int(args.hpt) & 0xFFFFFFFF

    matches = []
    for key_p, fam in reg.items():
        A_str = fam.get("A")
        B_str = fam.get("B")
        K_str = fam.get("K")
        if not all([A_str, B_str, K_str]):
            continue # Skip families without A, B, K constants

        A = int(A_str, 16)
        B = int(B_str, 16)
        K = int(K_str, 16)
        if u32(A*serial + B*hpt) == K:
            pn_u32 = int(key_p, 16)
            matches.append((pn_u32, fam))

    if not matches:
        print("No match in registry. You need to learn this family (see 'learn').")
        return 1

    for pn_u32, fam in matches:
        pn_str = fam.get("name") or format_hp_pn(pn_u32)
        print(f"Match: HP P/N {pn_str}  (P=0x{pn_u32:08X})")
        if fam.get("equivalents"):
            print(f"  Vendor equivalents: {', '.join(fam['equivalents'])}")

    return 0


def cmd_learn(args):
    # Need two samples of the same (unknown) HP P/N + the actual PN once
    s1 = parse_int(args.serial1) & 0xFFFFFFFF
    h1 = parse_int(args.hpt1)    & 0xFFFFFFFF
    s2 = parse_int(args.serial2) & 0xFFFFFFFF
    h2 = parse_int(args.hpt2)    & 0xFFFFFFFF
    pn_u32 = digits_to_u32_pn(args.part_number)

    A, B, K = learn_family_from_two(s1, h1, s2, h2)

    invB_str = ""
    if (B & 1) == 0:
        print("Warning: derived B is even. The 'hpt' command will show multiple possible solutions.")
    else:
        invB = inv_mod_pow2(B, 32)
        invB_str = f"  (inv=0x{invB:08X})"


    # Store
    reg = load_registry(args.registry)
    key = f"0x{pn_u32:08X}"
    reg[key] = {
        "name": args.part_number,
        "A": f"0x{A:08X}",
        "B": f"0x{B:08X}",
        "K": f"0x{K:08X}"
    }
    save_registry(args.registry, reg)

    print("Learned family constants:")
    print(f"  PN       : {args.part_number} (P=0x{pn_u32:08X})")
    print(f"  A        : 0x{A:08X}")
    print(f"  B        : 0x{B:08X}{invB_str}")
    print(f"  K (magic): 0x{K:08X}")
    print(f"Saved to   : {args.registry}")
    return 0

def cmd_hpt(args):
    """
    Compute HPT from (serial, part-number) using the registry family constants.
    Solves B*hpt = K - A*serial (mod 2^32) for hpt.
    """
    reg = load_registry(args.registry)
    serial = parse_int(args.serial) & 0xFFFFFFFF
    pn_u32 = digits_to_u32_pn(args.part_number)
    key = f"0x{pn_u32:08X}"

    fam = reg.get(key)
    if fam is None:
        print(f"No family constants for PN {args.part_number} (P=0x{pn_u32:08X}). "
              f"Learn it first with 'learn'.")
        return 1

    A = int(fam["A"], 16)
    B = int(fam["B"], 16)
    K = int(fam["K"], 16)
    
    val = u32(K - u32(A * serial))

    print(f"HP P/N : {fam.get('name') or format_hp_pn(pn_u32)} (P=0x{pn_u32:08X})")
    print(f"Serial: 0x{serial:08X} ({serial})")

    if (B & 1) != 0: # B is odd, standard modular inverse
        invB = inv_mod_pow2(B, 32)
        hpt = u32(val * invB)
        print(f"HPT   : 0x{hpt:08X} ({hpt})")
    else: # B is even, solve linear congruence
        g = B & -B # gcd(B, 2**32) is the largest power of 2 that divides B
        if g == 0:
            print("Error: B is zero in registry, cannot compute HPT.", file=sys.stderr)
            return 2
        
        if val % g != 0:
            print(f"Error: (K - A*serial) is not divisible by gcd(B, 2^32), no solution for HPT.", file=sys.stderr)
            return 2
        
        # We have g solutions. We'll find the smallest positive one and then the others.
        B_prime = B // g
        val_prime = val // g
        k = g.bit_length() - 1
        mod_k = 32 - k
        
        inv_B_prime = inv_mod_pow2(B_prime, mod_k)
        hpt0 = (val_prime * inv_B_prime) & ((1 << mod_k) - 1)
        
        print(f"Found {g} possible HPT solutions:")
        
        step = (1 << 32) // g
        for i in range(g):
            hpt_i = u32(hpt0 + i * step)
            print(f"  - 0x{hpt_i:08X} ({hpt_i})")

    return 0

def cmd_lookup(args):
    """Looks up an HP or vendor part number."""
    reg = load_registry(args.registry)
    
    # Create a reverse map from vendor P/N to HP P/N info
    reverse_map = {}
    for hp_pn_key, fam in reg.items():
        for eq_pn in fam.get("equivalents", []):
            reverse_map[eq_pn] = fam

    # Check if the input is an HP part number
    try:
        pn_u32 = digits_to_u32_pn(args.part_number)
        key = f"0x{pn_u32:08X}"
        if key in reg:
            fam = reg[key]
            print(f"HP P/N: {fam.get('name', args.part_number)}")
            if fam.get("equivalents"):
                print("Known vendor part numbers:")
                for eq in fam["equivalents"]:
                    print(f"- {eq}")
            else:
                print("No known vendor equivalents.")
            return 0
    except ValueError:
        pass # Not a digit-based part number

    # Check if the input is a vendor part number
    if args.part_number in reverse_map:
        fam = reverse_map[args.part_number]
        print(f"Vendor P/N: {args.part_number}")
        print(f"Maps to HP P/N: {fam.get('name')}")
        return 0
        
    print(f"Part number '{args.part_number}' not found in registry.")
    return 1

def cmd_add_equivalent(args):
    """Adds a vendor equivalent part number to an HP family."""
    reg = load_registry(args.registry)
    pn_u32 = digits_to_u32_pn(args.part_number)
    key = f"0x{pn_u32:08X}"
    
    if key not in reg:
        reg[key] = {"name": args.part_number, "equivalents": []}
        
    if "equivalents" not in reg[key]:
        reg[key]["equivalents"] = []
        
    if args.equivalent_pn not in reg[key]["equivalents"]:
        reg[key]["equivalents"].append(args.equivalent_pn)
        save_registry(args.registry, reg)
        print(f"Added '{args.equivalent_pn}' as an equivalent for HP P/N {args.part_number}.")
    else:
        print("Equivalent part number already exists.")
        
    return 0

# ---------- Main ----------

def main():
    ap = argparse.ArgumentParser(
        description="Identify/learn HP SmartMemory families, or compute HPT from (serial, PN)."
    )
    ap.add_argument("--registry", default=REG_PATH_DEFAULT,
                    help=f"JSON registry path (default: {REG_PATH_DEFAULT})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_id = sub.add_parser("identify", help="Identify HP P/N from one (serial,hpt) using registry.")
    p_id.add_argument("--serial", required=True, help="e.g. 0x4132E061 or 1094997473")
    p_id.add_argument("--hpt",    required=True, help="e.g. 0xFCD7E032 or 4240061234")
    p_id.set_defaults(func=cmd_identify)

    p_learn = sub.add_parser("learn", help="Learn a family's constants from two samples + known HP P/N.")
    p_learn.add_argument("--serial1", required=True)
    p_learn.add_argument("--hpt1",    required=True)
    p_learn.add_argument("--serial2", required=True)
    p_learn.add_argument("--hpt2",    required=True)
    p_learn.add_argument("--part-number", required=True, help="e.g. 712383-081")
    p_learn.set_defaults(func=cmd_learn)

    p_hpt = sub.add_parser("hpt", help="Compute HPT from (serial, part-number) using registry.")
    p_hpt.add_argument("--serial", required=True, help="e.g. 0x4132E061 or 1094997473")
    p_hpt.add_argument("--part-number", required=True, help="e.g. 712383-081 or 712383081")
    p_hpt.set_defaults(func=cmd_hpt)

    p_lookup = sub.add_parser("lookup", help="Look up an HP or vendor part number.")
    p_lookup.add_argument("part_number", help="HP or vendor part number to look up.")
    p_lookup.set_defaults(func=cmd_lookup)

    p_add_equiv = sub.add_parser("add-equivalent", help="Add a vendor equivalent to an HP P/N.")
    p_add_equiv.add_argument("--part-number", required=True, help="HP P/N, e.g. 647648-071")
    p_add_equiv.add_argument("--equivalent-pn", required=True, help="Vendor P/N, e.g. M393B5270DH0-CK0")
    p_add_equiv.set_defaults(func=cmd_add_equivalent)


    args = ap.parse_args()
    raise SystemExit(args.func(args))

if __name__ == "__main__":
    main()