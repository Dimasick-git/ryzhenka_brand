import re
def scan_section_for_strings(file_path, min_length=4):
    """Scan binary file for readable ASCII strings (min_length chars)"""
    with open(file_path, "rb") as f:
        data = f.read()
    # ASCII strings
    ascii_strings = re.findall(rb'([ -~]{%d,})' % min_length, data)
    # UTF-16LE strings
    utf16_strings = re.findall(rb'((?:[ -~]\x00){%d,})' % min_length, data)
    # Decode and deduplicate
    result = set()
    for s in ascii_strings:
        try:
            result.add(s.decode('ascii'))
        except:
            pass
    for s in utf16_strings:
        try:
            result.add(s.decode('utf-16-le'))
        except:
            pass
    return sorted(result)
import struct
import sys
import os
HEADER_SIZE = 0x100
ENTRY_BASE = 0x10
ENTRY_SIZE = 0x10
NUM_ENTRIES = 6
SECTION_NAMES = ["text", "rodata", "data", "bss", "s5", "s6"]


def read_u32le(b, off):
    return struct.unpack_from("<I", b, off)[0]


def unpack_kip(kip_path, out_dir):
    if not os.path.isfile(kip_path):
        print("ERROR: file not found:", kip_path)
        return 2

    with open(kip_path, "rb") as f:
        data = f.read()

    if len(data) < HEADER_SIZE or data[0:4] != b'KIP1':
        print("ERROR: Not a KIP1 file or file too small.")
        return 3

    os.makedirs(out_dir, exist_ok=True)

    header = data[:HEADER_SIZE]
    open(os.path.join(out_dir, "header.bin"), "wb").write(header)
    print("[OK] header.bin written")

    file_len = len(data)
    print(f"[INFO] file length: {file_len} bytes")

    sections_data = []
    for i in range(NUM_ENTRIES):
        entry_off = ENTRY_BASE + i * ENTRY_SIZE
        off = read_u32le(header, entry_off)
        size = read_u32le(header, entry_off + 4)
        dst = read_u32le(header, entry_off + 8)
        comp = read_u32le(header, entry_off + 12)
        name = SECTION_NAMES[i] if i < len(SECTION_NAMES) else f"sec{i}"
        print(
    f"[ENTRY {i}] {name}: offset=0x{
        off:X} ({off}), size={size}, dst=0x{
            dst:X}, comp={comp}")
        if size == 0:
            continue
        if off + size > file_len:
            print(
    f"  WARNING: declared region out-of-bounds (off+size > file_len) — skipping.")
            continue
        out_path = os.path.join(out_dir, f"{name}.bin")
        with open(out_path, "wb") as wf:
            wf.write(data[off:off + size])
        sections_data.append((name, out_path, data[off:off + size]))
        print(f"  -> wrote {out_path}")

    print("[DONE] unpack complete")
    return sections_data


def modify_section(file_path, search_str, replace_str):
    """Replace search_str with replace_str in a binary file"""
    with open(file_path, "rb") as f:
        data = f.read()

    found = False
    # Try utf-8
    search_bytes = search_str.encode('utf-8')
    replace_bytes = replace_str.encode('utf-8')
    if search_bytes in data:
        print(f"[utf-8] Found '{search_str}' in {file_path}. Replacing...")
        data = data.replace(search_bytes, replace_bytes)
        found = True

    # Try utf-16-le
    search_bytes_utf16 = search_str.encode('utf-16-le')
    replace_bytes_utf16 = replace_str.encode('utf-16-le')
    if search_bytes_utf16 in data:
        print(f"[utf-16-le] Found '{search_str}' in {file_path}. Replacing...")
        data = data.replace(search_bytes_utf16, replace_bytes_utf16)
        found = True

    # Try hex string (if search_str is hex like '556c74726120322e36205231')
    try:
        if all(c in '0123456789abcdefABCDEF' for c in search_str.replace(' ', '')) and len(search_str.replace(' ', '')) % 2 == 0:
            search_bytes_hex = bytes.fromhex(search_str.replace(' ', ''))
            replace_bytes_hex = bytes.fromhex(replace_str.replace(' ', '')) if all(c in '0123456789abcdefABCDEF' for c in replace_str.replace(' ', '')) and len(replace_str.replace(' ', '')) % 2 == 0 else replace_str.encode('utf-8')
            if search_bytes_hex in data:
                print(f"[hex] Found hex pattern in {file_path}. Replacing...")
                data = data.replace(search_bytes_hex, replace_bytes_hex)
                found = True
    except Exception as e:
        print(f"[hex] Error parsing hex: {e}")

    if found:
        with open(file_path, "wb") as f:
            f.write(data)
        print(f"'{search_str}' replaced with '{replace_str}' in {file_path}.")
    else:
        print(f"'{search_str}' not found in {file_path} (utf-8, utf-16-le, hex). No changes made.")


def pack_kip(in_dir, out_path):
    header_path = os.path.join(in_dir, "header.bin")
    if not os.path.isfile(header_path):
        print("ERROR: header.bin not found in", in_dir)
        return 1

    header = bytearray(open(header_path, "rb").read())
    if len(header) < HEADER_SIZE:
        header += b'\x00' * (HEADER_SIZE - len(header))

    sections_data = []
    cur_off = len(header)
    for i in range(NUM_ENTRIES):
        sec_name = SECTION_NAMES[i] if i < len(SECTION_NAMES) else f"sec{i}"
        sec_path = os.path.join(in_dir, f"{sec_name}.bin")
        if not os.path.isfile(sec_path):
            struct.pack_into(
    "<IIII",
    header,
    ENTRY_BASE +
    i *
    ENTRY_SIZE,
    0,
    0,
    0,
     0)
            continue
        blob = open(sec_path, "rb").read()
        size = len(blob)
        struct.pack_into(
    "<IIII",
    header,
    ENTRY_BASE +
    i *
    ENTRY_SIZE,
    cur_off,
    size,
    0,
     0)
        sections_data.append(blob)
        cur_off += size

    with open(out_path, "wb") as f:
        f.write(header)
        for b in sections_data:
            f.write(b)
    print("[DONE] packed to", out_path)


def main():
    if len(sys.argv) < 3:
        print("Usage: python kip_auto_patch.py loader.kip out_dir [search_string replace_string] | unpack")
        return 1

    kip_path = sys.argv[1]
    out_dir = sys.argv[2]

    # Если третий аргумент 'unpack', просто распаковать
    if len(sys.argv) == 3 or (len(sys.argv) == 4 and sys.argv[3].lower() == 'unpack'):
        print("[UNPACK MODE] Только распаковка секций без патча.")
        sections_data = unpack_kip(kip_path, out_dir)
        if sections_data:
            print("\n[INFO] Содержимое секций:")
            for name, path, data in sections_data:
                print(f"  {name}: {len(data)} байт, файл: {path}")
        return 0

    if len(sys.argv) < 5:
        print("Usage: python kip_auto_patch.py loader.kip out_dir search_string replace_string")
        return 1

    search_str = sys.argv[3]
    replace_str = sys.argv[4]
    try:
        if any(c in search_str for c in ['0x', '0X']):
            print("Warning: hexadecimal literals detected. Ensure these are correct.")
    except Exception as e:
        print(f"Error: {e}")
        return 1

    sections_data = unpack_kip(kip_path, out_dir)
    if sections_data:
        print("\n[SCAN] Поиск строк в секциях:")
        all_found_strings = set()
        for name, path, data in sections_data:
            found = scan_section_for_strings(path)
            if found:
                print(f"  {name}: {len(found)} строк найдено")
                for s in found:
                    print(f"    {s}")
                all_found_strings.update(found)
        print("\n[INFO] Всего уникальных строк:", len(all_found_strings))
        if search_str in all_found_strings:
            print(f"[PATCH] Строка '{search_str}' найдена, выполняю замену...")
            for name, path, data in sections_data:
                modify_section(path, search_str, replace_str)
            pack_kip(out_dir, kip_path.replace(".kip", "_modified.kip"))
        else:
            print(f"[WARN] Строка '{search_str}' не найдена среди извлечённых. Проверьте список выше и попробуйте ещё раз.")

if __name__ == "__main__":
    main()
