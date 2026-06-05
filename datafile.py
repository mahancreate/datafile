#!/usr/bin/env python3
"""
DataFile 0.1.0
File encryption CLI — AES-256-GCM + Argon2id
"""

import os
import sys
import argparse
from pathlib import Path

try:
    from argon2.low_level import hash_secret_raw, Type
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Missing dependencies. Run: pip install argon2-cffi cryptography")
    sys.exit(1)

# Platform raw-input support
if sys.platform == "win32":
    import msvcrt
    _WINDOWS = True
else:
    import termios, tty
    _WINDOWS = False

VERSION = "0.1.0"
MAGIC = b"DATAFILE"          # 8-byte magic header
FORMAT_VER = b"\x01"         # 1-byte format version
SALT_LEN = 32
NONCE_LEN = 12

# Argon2id params per accuracy level
ACCURACY_PARAMS = {
    "B": {"time_cost": 8,  "memory_cost": 262144, "parallelism": 4},  # Best
    "G": {"time_cost": 4,  "memory_cost": 131072, "parallelism": 2},  # Good
    "M": {"time_cost": 2,  "memory_cost": 65536,  "parallelism": 2},  # Medium
    "L": {"time_cost": 1,  "memory_cost": 16384,  "parallelism": 1},  # Low
}

ACCURACY_LABELS = {
    "B": "Best (slowest)",
    "G": "Good (slow)",
    "M": "Medium (fast)",
    "L": "Low (very fast)",
}


def derive_key(password: str, salt: bytes, params: dict) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=32,
        type=Type.ID,
    )


def encrypt_file(input_path: Path, output_name: str, password: str, accuracy: str):
    params = ACCURACY_PARAMS[accuracy]
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)

    print(f"\n  Deriving key [{ACCURACY_LABELS[accuracy]}]...", end=" ", flush=True)
    key = derive_key(password, salt, params)
    print("done")

    plaintext = input_path.read_bytes()

    # Encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Pack accuracy level as 1 byte
    acc_byte = accuracy.encode("ascii")

    # File layout:
    # [MAGIC 8][VER 1][ACC 1][SALT 32][NONCE 12][CIPHERTEXT+TAG]
    output_path = input_path.parent / f"{output_name}.datafile"
    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(FORMAT_VER)
        f.write(acc_byte)
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    size_kb = output_path.stat().st_size / 1024
    print(f"\n  Done! Your file is now unusable without a password.")
    print(f"  Saved as: {output_path.name}  ({size_kb:.1f} KB)")


def decrypt_file(input_path: Path, password: str):
    data = input_path.read_bytes()

    # Validate magic
    if data[:8] != MAGIC:
        print("Error: not a valid .datafile")
        sys.exit(1)

    fmt_ver = data[8:9]
    accuracy = data[9:10].decode("ascii")
    salt = data[10:10 + SALT_LEN]
    nonce = data[10 + SALT_LEN:10 + SALT_LEN + NONCE_LEN]
    ciphertext = data[10 + SALT_LEN + NONCE_LEN:]

    params = ACCURACY_PARAMS[accuracy]
    print(f"\n  Deriving key [{ACCURACY_LABELS[accuracy]}]...", end=" ", flush=True)
    key = derive_key(password, salt, params)
    print("done")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        print("\n  Wrong password or corrupted file.")
        sys.exit(1)

    # Strip .datafile, restore original
    stem = input_path.stem
    output_path = input_path.parent / stem
    if output_path.exists():
        output_path = input_path.parent / f"{stem}.decrypted"

    output_path.write_bytes(plaintext)
    print(f"\n  Decrypted successfully.")
    print(f"  Saved as: {output_path.name}")


def password_strength(pw: str) -> tuple[int, str]:
    score = 0
    if len(pw) >= 8:  score += 1
    if len(pw) >= 14: score += 1
    has_lower  = any(c.islower() for c in pw)
    has_upper  = any(c.isupper() for c in pw)
    has_digit  = any(c.isdigit() for c in pw)
    has_symbol = any(not c.isalnum() for c in pw)
    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    if variety >= 3: score += 1
    if variety == 4: score += 1
    score = min(score, 4)
    labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
    return score, labels[score]


def render_meter(pw: str) -> str:
    score, label = password_strength(pw)
    filled = "◉" * score
    empty  = "○" * (4 - score)
    colors = ["\033[91m", "\033[91m", "\033[93m", "\033[92m", "\033[92m"]
    reset  = "\033[0m"
    c      = colors[score]
    return f"  Strength:  {c}{filled}{empty}{reset}  {c}{label}{reset}"


def _read_char() -> str:
    """Read one raw character from stdin, cross-platform."""
    if _WINDOWS:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):  return "\n"
        if ch == "\x03":         return "\x03"
        if ch in ("\x00", "\xe0"):
            msvcrt.getwch()      # swallow second byte of special keys
            return ""
        return ch
    else:
        return sys.stdin.read(1)


def read_password_live(prompt: str, confirm: bool = False) -> str:
    """
    Read a password character-by-character, updating the strength meter
    live on the line below as the user types. Cross-platform (Win/Unix).
    """
    HIDE  = "\033[?25l"
    SHOW  = "\033[?25h"
    UP    = "\033[1A"
    CLEAR = "\033[2K\r"

    pw = ""

    sys.stdout.write(f"  {prompt} \n")
    sys.stdout.write(render_meter("") + "\n")
    sys.stdout.flush()

    if _WINDOWS:
        ctx = None
    else:
        fd  = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        ctx = (fd, old)

    try:
        if not _WINDOWS:
            tty.setraw(ctx[0])
        sys.stdout.write(HIDE)
        sys.stdout.flush()

        while True:
            ch = _read_char()

            if ch == "\n":                      # Enter
                break
            elif ch in ("\x7f", "\x08"):       # Backspace
                if pw:
                    pw = pw[:-1]
            elif ch == "\x03":                  # Ctrl-C
                sys.stdout.write(SHOW + "\n")
                sys.stdout.flush()
                raise KeyboardInterrupt
            elif ch and ch >= " ":               # printable
                pw += ch
            else:
                continue

            dots = "*" * len(pw)
            sys.stdout.write(UP + UP)
            sys.stdout.write(CLEAR + f"  {prompt} {dots}\n")
            if not confirm:
                sys.stdout.write(CLEAR + render_meter(pw) + "\n")
            else:
                sys.stdout.write(CLEAR + "\n")
            sys.stdout.flush()

    finally:
        if not _WINDOWS and ctx:
            termios.tcsetattr(ctx[0], termios.TCSADRAIN, ctx[1])
        sys.stdout.write(SHOW)
        sys.stdout.flush()

    return pw


def prompt_accuracy() -> str:
    options = {
        "B": "Best (slowest)",
        "G": "Good (slow)",
        "M": "Medium (fast)",
        "L": "Low (very fast)",
    }
    print("  Accuracy:")
    for k, v in options.items():
        print(f"    [{k}] {v}")
    while True:
        choice = input("  Choose [B/G/M/L]: ").strip().upper()
        if choice in options:
            return choice
        print("  Invalid choice. Enter B, G, M, or L.")



def bundle_file(input_path: Path, output_name: str, password: str, accuracy: str):
    """Encrypt and embed into a self-decrypting .py bundle."""
    import base64, textwrap

    params = ACCURACY_PARAMS[accuracy]
    salt   = os.urandom(32)
    nonce  = os.urandom(12)

    print(f"\n  Deriving key [{ACCURACY_LABELS[accuracy]}]...", end=" ", flush=True)
    key = derive_key(password, salt, params)
    print("done")

    plaintext  = input_path.read_bytes()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    payload_b64 = base64.b64encode(salt + nonce + ciphertext).decode("ascii")

    # Build bundle using string concatenation — no .format() so no brace-escaping issues
    lines = [
        "#!/usr/bin/env python3",
        "# DataFile self-decrypting bundle",
        f"# Generated by DataFile {VERSION}",
        f"# Original file: {input_path.name}",
        "import sys, base64, os",
        "",
        "try:",
        "    from argon2.low_level import hash_secret_raw, Type",
        "    from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
        "except ImportError:",
        '    print("Missing dependencies. Run: pip install argon2-cffi cryptography")',
        "    sys.exit(1)",
        "",
        'if sys.platform == "win32":',
        "    import msvcrt",
        "    _WINDOWS = True",
        "else:",
        "    import termios, tty",
        "    _WINDOWS = False",
        "",
        f'PAYLOAD   = base64.b64decode("{payload_b64}")',
        "SALT      = PAYLOAD[0:32]",
        "NONCE     = PAYLOAD[32:44]",
        "CIPHER    = PAYLOAD[44:]",
        f'ACC       = "{accuracy}"',
        f'ORIG_NAME = "{input_path.name}"',
        "",
        "PARAMS = {",
        '    "B": {"time_cost": 8,  "memory_cost": 262144, "parallelism": 4},',
        '    "G": {"time_cost": 4,  "memory_cost": 131072, "parallelism": 2},',
        '    "M": {"time_cost": 2,  "memory_cost": 65536,  "parallelism": 2},',
        '    "L": {"time_cost": 1,  "memory_cost": 16384,  "parallelism": 1},',
        "}",
        "LABELS = {",
        '    "B": "Best (slowest)", "G": "Good (slow)",',
        '    "M": "Medium (fast)",  "L": "Low (very fast)",',
        "}",
        "",
        "def _read_char():",
        "    if _WINDOWS:",
        "        ch = msvcrt.getwch()",
        r'        if ch in ("\r", "\n"): return "\n"',
        r'        if ch == "\x03":       return "\x03"',
        r'        if ch in ("\x00", "\xe0"):',
        "            msvcrt.getwch()",
        '            return ""',
        "        return ch",
        "    else:",
        "        return sys.stdin.read(1)",
        "",
        "def read_pw(prompt):",
        r'    HIDE = "\033[?25l"; SHOW = "\033[?25h"',
        '    pw = ""',
        '    sys.stdout.write(f"  {prompt} "); sys.stdout.flush()',
        "    if not _WINDOWS:",
        "        fd = sys.stdin.fileno(); old = termios.tcgetattr(fd)",
        "    try:",
        "        if not _WINDOWS: tty.setraw(sys.stdin.fileno())",
        "        sys.stdout.write(HIDE); sys.stdout.flush()",
        "        while True:",
        "            ch = _read_char()",
        r'            if ch == "\n": break',
        r'            elif ch in ("\x7f", "\x08"):',
        "                if pw: pw = pw[:-1]",
        r'            elif ch == "\x03":',
        r'                sys.stdout.write(SHOW + "\n"); sys.stdout.flush()',
        "                raise KeyboardInterrupt",
        '            elif ch and ch >= " ": pw += ch',
        "    finally:",
        "        if not _WINDOWS: termios.tcsetattr(fd, termios.TCSADRAIN, old)",
        "        sys.stdout.write(SHOW); sys.stdout.flush()",
        "    return pw",
        "",
        f'print("\\nDataFile Bundle — {input_path.name}")',
        'print("  Requires: argon2-cffi, cryptography\\n")',
        "",
        "p = PARAMS[ACC]",
        "while True:",
        "    pw = read_pw('Password:')",
        "    print()",
        '    print(f"  Deriving key [{LABELS[ACC]}]...", end=" ", flush=True)',
        "    key = hash_secret_raw(",
        "        secret=pw.encode(), salt=SALT,",
        "        time_cost=p['time_cost'], memory_cost=p['memory_cost'],",
        "        parallelism=p['parallelism'], hash_len=32, type=Type.ID,",
        "    )",
        "    print('done')",
        "    try:",
        "        plain = AESGCM(key).decrypt(NONCE, CIPHER, None)",
        "        break",
        "    except Exception:",
        r'        print("  Wrong password. Try again.\n")',
        "",
        "out = ORIG_NAME",
        "if os.path.exists(out): out = ORIG_NAME + '.decrypted'",
        "open(out, 'wb').write(plain)",
        r'print(f"\n  Decrypted: {out}")',
        "",
        "try:",
        "    main() if '__main__' == __name__ else None",
        "except: pass",
    ]

    script = "\n".join(lines) + "\n"

    out_path = input_path.parent / f"{output_name}.py"
    out_path.write_text(script, encoding="utf-8")
    size_kb = out_path.stat().st_size / 1024
    print(f"\n  Bundle ready! Run  python {out_path.name}  to decrypt.")
    print(f"  Saved as: {out_path.name}  ({size_kb:.1f} KB)")


def main():
    parser = argparse.ArgumentParser(
        prog="datafile",
        description=f"DataFile {VERSION} — encrypt/decrypt files with AES-256-GCM",
        add_help=True,
    )
    parser.add_argument("file", help="File to encrypt or decrypt")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt a .datafile")
    parser.add_argument("-p", "--password", help="Password (omit for prompt)")
    parser.add_argument(
        "-a", "--accuracy",
        choices=["B", "G", "M", "L"],
        help="KDF accuracy: B=Best G=Good M=Medium L=Low",
    )
    parser.add_argument("-n", "--name", help="Output name stem (encrypt only)")
    parser.add_argument("-bd", "--bundle", action="store_true", help="Bundle as self-decrypting .py file")
    parser.add_argument("-v", "--version", action="version", version=f"DataFile {VERSION}")

    args = parser.parse_args()

    print(f"\ndatafile {VERSION}")

    input_path = Path(args.file)
    if not input_path.exists():
        print(f"Error: file not found: {input_path}")
        sys.exit(1)

    if args.decrypt:
        # --- DECRYPT ---
        if not str(input_path).endswith(".datafile"):
            print("Warning: file does not have .datafile extension")
        if args.password:
            password = args.password
        else:
            password = read_password_live("Password:", confirm=True)
            print()
        decrypt_file(input_path, password)

    else:
        # --- ENCRYPT ---
        default_name = input_path.stem
        if args.name:
            output_name = args.name
        else:
            prompted = input(f"  Encrypted name [{default_name}]: ").strip()
            output_name = prompted if prompted else default_name

        password = args.password
        if not password:
            while True:
                pw1 = read_password_live("Set password:")
                print()
                pw2 = read_password_live("Confirm password:", confirm=True)
                print()
                if pw1 == pw2:
                    password = pw1
                    break
                print("  Passwords don't match. Try again.\n")

        if not password:
            print("Error: password cannot be empty.")
            sys.exit(1)

        accuracy = args.accuracy
        if not accuracy:
            accuracy = prompt_accuracy()

        if args.bundle:
            bundle_file(input_path, output_name, password, accuracy)
        else:
            encrypt_file(input_path, output_name, password, accuracy)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Cancelled.")
        sys.exit(0)