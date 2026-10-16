import datetime
import os
import re
import shutil
import struct
import sys
import zlib

# ==================== CONFIGURATIONS ====================
ZIP_FILE = r"C:\path\to\your\corrupt_file.zip"  # 27 GB zip ka exact path dalein
OUTPUT_EXTRACT_DIR = (
    r"C:\path\to\recovered_files"  # Extraction destination folder
)
REPORT_FILE = "zip_diagnostic_report.txt"  # Diagnostic report path
CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB fast scan buffer
REQUIRED_FREE_SPACE_GB = 20  # Minimum safe disk space
# ========================================================

LOCAL_HEADER_SIG = b"\x50\x4b\x03\x04"


def safe_win_path(path):
    """Windows 260 character MAX_PATH limit ko bypass karta hai."""
    abs_path = os.path.abspath(path)
    if os.name == "nt" and not abs_path.startswith("\\\\?\\"):
        return "\\\\?\\" + abs_path
    return abs_path


def check_disk_space(target_dir, required_gb):
    """Output drive ka free storage verify karta hai."""
    try:
        drive_path = os.path.splitdrive(os.path.abspath(target_dir))[0]
        if not drive_path:
            drive_path = "."
        _, _, free = shutil.disk_usage(drive_path)
        free_gb = free / (1024**3)
        if free_gb < required_gb:
            print(
                f"\n[WARNING] Output drive par sirf {free_gb:.2f} GB space free hai! (Recommended: {required_gb} GB)"
            )
            c = input("Space kam hai, kya fir bhi continue karna hai? (y/n): ")
            if c.lower() != "y":
                print("Exit kar rahe hain.")
                sys.exit(0)
    except Exception as e:
        print(f"[NOTE] Disk space verification bypass: {e}")


def parse_zip64_extra(extra_data):
    """Zip64 extra field (0x0001) se real 64-bit sizes parse karta hai."""
    offset = 0
    u_size, c_size = None, None
    while offset + 4 <= len(extra_data):
        header_id, data_size = struct.unpack(
            "<HH", extra_data[offset : offset + 4]
        )
        field_data = extra_data[offset + 4 : offset + 4 + data_size]
        if header_id == 0x0001:
            curr = 0
            if len(field_data) >= curr + 8:
                u_size = struct.unpack("<Q", field_data[curr : curr + 8])[0]
                curr += 8
            if len(field_data) >= curr + 8:
                c_size = struct.unpack("<Q", field_data[curr : curr + 8])[0]
                curr += 8
            return u_size, c_size
        offset += 4 + data_size
    return u_size, c_size


def build_tree_structure(paths):
    """Hierarchical folder dictionary build karta hai."""
    tree = {}
    for path in sorted(paths):
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        curr = tree
        for part in parts:
            if part not in curr:
                curr[part] = {}
            curr = curr[part]
    return tree


def render_tree(d, prefix="", is_last=True):
    """Tree ko readable ascii format me render karta hai."""
    lines = []
    items = list(d.keys())
    for index, item in enumerate(items):
        last = index == (len(items) - 1)
        connector = "└── " if last else "├── "
        lines.append(prefix + connector + item)
        new_prefix = prefix + ("    " if last else "│   ")
        if d[item]:
            lines.extend(render_tree(d[item], new_prefix, last))
    return lines


def process_stream_and_extract(
    f,
    data_offset,
    comp_method,
    comp_size,
    uncomp_size,
    flags,
    expected_crc,
    target_save_path,
):
    """Level-0 diagnostic, full decompression aur partial salvage execute karta hai."""
    has_data_descriptor = bool(flags & 0x0008)
    read_len = (
        comp_size
        if (comp_size > 0 and comp_size != 0xFFFFFFFF)
        else 80 * 1024 * 1024
    )

    f.seek(data_offset)
    raw_data = f.read(read_len)

    if not raw_data:
        return (
            "FATAL_TRUNCATED",
            "Zero bytes readable at offset (Hard physical cutoff).",
            False,
            "N/A",
        )

    # 1. Method 0: Stored (Uncompressed)
    if comp_method == 0:
        actual_len = (
            uncomp_size
            if (uncomp_size > 0 and uncomp_size != 0xFFFFFFFF)
            else len(raw_data)
        )
        out_bytes = raw_data[:actual_len]

        has_pdf_magic = b"%PDF-" in out_bytes[:1024]
        has_eof = b"%%EOF" in out_bytes[-1024:]
        calc_crc = zlib.crc32(out_bytes) & 0xFFFFFFFF

        crc_ok = (
            (expected_crc == 0)
            or has_data_descriptor
            or (calc_crc == expected_crc)
        )

        final_path = safe_win_path(target_save_path)
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        with open(final_path, "wb") as out_f:
            out_f.write(out_bytes)

        status = "HEALTHY_STORED" if crc_ok else "STORED_CRC_MISMATCH"
        detail = f"Written {len(out_bytes)} bytes. Magic: {'%PDF- OK' if has_pdf_magic else 'None'} | EOF: {'%%EOF OK' if has_eof else 'Missing EOF'}"
        return status, detail, True, final_path

    # 2. Method 8: Deflated
    elif comp_method == 8:
        decompressor = zlib.decompressobj(-15)
        try:
            decompressed = decompressor.decompress(raw_data)
            calc_crc = zlib.crc32(decompressed) & 0xFFFFFFFF
            has_pdf_magic = b"%PDF-" in decompressed[:1024]
            has_eof = b"%%EOF" in decompressed[-1024:]

            crc_ok = (
                (expected_crc == 0)
                or has_data_descriptor
                or (calc_crc == expected_crc)
            )

            final_path = safe_win_path(target_save_path)
            os.makedirs(os.path.dirname(final_path), exist_ok=True)
            with open(final_path, "wb") as out_f:
                out_f.write(decompressed)

            status = "HEALTHY" if crc_ok else "CRC_MISMATCH_SAVED"
            detail = f"Decompressed {len(decompressed)} bytes. Magic: {'%PDF- OK' if has_pdf_magic else 'None'} | EOF: {'%%EOF OK' if has_eof else 'Missing EOF'}"
            return status, detail, True, final_path

        except zlib.error as ze:
            # Partial Stream Salvage
            salvage_buf = bytearray()
            salvage_d = zlib.decompressobj(-15)
            for i in range(0, len(raw_data), 4096):
                try:
                    chunk = salvage_d.decompress(raw_data[i : i + 4096])
                    salvage_buf.extend(chunk)
                except zlib.error:
                    break

            if len(salvage_buf) > 1024:
                partial_path = safe_win_path(target_save_path + ".partial.pdf")
                os.makedirs(os.path.dirname(partial_path), exist_ok=True)
                with open(partial_path, "wb") as out_f:
                    out_f.write(salvage_buf)
                has_pdf_magic = b"%PDF-" in salvage_buf[:1024]
                return (
                    "PARTIAL_SALVAGED",
                    f"Zlib crashed ({ze}) but salvaged {len(salvage_buf)} bytes. Magic: {'%PDF- OK' if has_pdf_magic else 'None'}",
                    True,
                    partial_path,
                )

            return (
                "CORRUPT_DEFLATE_STREAM",
                f"ZLIB Decode Failed: {str(ze)}. Offset unrecoverable.",
                False,
                "N/A",
            )

    return (
        "UNSUPPORTED_METHOD",
        f"Method {comp_method} not supported.",
        False,
        "N/A",
    )


def write_diagnostic_report(
    total_size, matched_paths, diagnostics_log, recovered_count
):
    """Saara audit record text report file me log karta hai."""
    with open(REPORT_FILE, "w", encoding="utf-8") as out:
        out.write("=" * 80 + "\n")
        out.write("ZIP ARCHIVE INTEGRITY & EXTRACTION AUDIT REPORT\n")
        out.write(f"Generated on   : {datetime.datetime.now()}\n")
        out.write(
            f"Archive        : {ZIP_FILE} ({total_size / (1024**3):.2f} GB)\n"
        )
        out.write("Target Pattern : '9' + 'important' combined\n")
        out.write("=" * 80 + "\n\n")

        out.write("SECTION 1: DISCOVERED DIRECTORY TREE\n")
        out.write("-" * 80 + "\n")
        if matched_paths:
            tree = build_tree_structure(matched_paths)
            for line in render_tree(tree):
                out.write(line + "\n")
        else:
            out.write("No matching files detected.\n")
        out.write("\n\n")

        out.write("SECTION 2: FILE-BY-FILE DIAGNOSTIC AUDIT & EXTRACTION STATE\n")
        out.write("-" * 80 + "\n")
        for item in diagnostics_log:
            out.write(f"FILE: {item['file']}\n")
            out.write(
                f"  ├─ Header Offset   : {item['header_offset']} (0x{item['header_offset']:X})\n"
            )
            out.write(
                f"  ├─ Data Offset     : {item['data_offset']} (0x{item['data_offset']:X})\n"
            )
            out.write(
                f"  ├─ Method / Size   : Method {item['comp_method']} | Comp: {item['comp_size']} B | Uncomp: {item['uncomp_size']} B\n"
            )
            out.write(f"  ├─ Health Status   : [{item['status']}]\n")
            out.write(
                f"  ├─ Extracted       : {'YES -> ' + item['save_path'] if item['saved'] else 'NO (Unrecoverable)'}\n"
            )
            out.write(f"  └─ Technical Notes : {item['detail']}\n\n")

        out.write("=" * 80 + "\n")
        out.write(
            f"SUMMARY: Matched Files: {len(matched_paths)} | Successfully Recovered/Salvaged: {recovered_count}\n"
        )
        out.write("=" * 80 + "\n")


def main():
    if not os.path.exists(ZIP_FILE):
        print(f"Error: Archive nahi mila -> {ZIP_FILE}")
        return

    check_disk_space(OUTPUT_EXTRACT_DIR, REQUIRED_FREE_SPACE_GB)
    total_size = os.path.getsize(ZIP_FILE)

    print("=" * 75)
    print("      PHASE 1: SCANNING 27 GB ARCHIVE (DISCOVERY & TREE CREATION)")
    print("=" * 75)
    print(f"Archive        : {ZIP_FILE} ({total_size / (1024**3):.2f} GB)")
    print(
        "Match Criteria : '9' aur 'important' (Space/Underscore/Case-Insensitive)"
    )
    print("Status         : Parsing byte stream... Please wait.\n")

    current_offset = 0
    matched_records = []  # Stores header metadata for fast Phase 2 extraction

    try:
        with open(ZIP_FILE, "rb") as f:
            while current_offset < total_size:
                progress = (current_offset / total_size) * 100
                sys.stdout.write(
                    f"\rScanning Progress: {progress:.2f}% | Scanned: {current_offset / (1024**3):.2f} GB | Targets Found: {len(matched_records)}..."
                )
                sys.stdout.flush()

                try:
                    f.seek(current_offset)
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                except Exception as e:
                    current_offset += CHUNK_SIZE
                    continue

                sig_idx = 0
                while True:
                    sig_idx = chunk.find(LOCAL_HEADER_SIG, sig_idx)
                    if sig_idx == -1:
                        break

                    header_pos = current_offset + sig_idx

                    try:
                        f.seek(header_pos)
                        header = f.read(30)

                        if len(header) == 30:
                            (
                                sig,
                                ver,
                                flags,
                                method,
                                mtime,
                                mdate,
                                crc,
                                c_size,
                                u_size,
                                name_len,
                                extra_len,
                            ) = struct.unpack("<4sHHHHHIIIHH", header)

                            name_bytes = f.read(name_len)
                            try:
                                filename = name_bytes.decode(
                                    "utf-8", errors="ignore"
                                )
                            except Exception:
                                filename = str(name_bytes)

                            extra_bytes = (
                                f.read(extra_len) if extra_len > 0 else b""
                            )

                            # Zip64 check
                            if (
                                c_size == 0xFFFFFFFF or u_size == 0xFFFFFFFF
                            ) and extra_bytes:
                                z64_u, z64_c = parse_zip64_extra(extra_bytes)
                                if z64_u is not None:
                                    u_size = z64_u
                                if z64_c is not None:
                                    c_size = z64_c

                            # Targeted Match Rule
                            clean_name = filename.lower()
                            pattern_match = bool(
                                re.search(r"9[\s_\-\.]{0,5}important", clean_name)
                            )
                            loose_match = ("9" in clean_name) and (
                                "important" in clean_name
                            )

                            if (
                                filename
                                and (pattern_match or loose_match)
                                and not filename.endswith("/")
                            ):
                                data_offset = (
                                    header_pos + 30 + name_len + extra_len
                                )
                                matched_records.append({
                                    "filename": filename,
                                    "header_pos": header_pos,
                                    "data_offset": data_offset,
                                    "method": method,
                                    "c_size": c_size,
                                    "u_size": u_size,
                                    "flags": flags,
                                    "crc": crc,
                                })
                    except Exception:
                        pass

                    sig_idx += 4

                current_offset += CHUNK_SIZE - 4096

    except KeyboardInterrupt:
        print("\n\n[PAUSED] Scan early interrupt by user.")

    print("\n\n" + "=" * 75)
    print(
        f"PHASE 1 COMPLETE: Total {len(matched_records)} matching target files discovered!"
    )
    print("=" * 75)

    if not matched_records:
        print(
            "Koi bhi matching file nahi mili jisme '9' aur 'important' ho. Process aborted."
        )
        return

    # Render Found Directory Tree
    all_paths = [rec["filename"] for rec in matched_records]
    tree = build_tree_structure(all_paths)
    print("\n--- FOUND DIRECTORY & FILE TREE ---")
    for line in render_tree(tree):
        print(line)
    print("-----------------------------------\n")

    # Permission Prompt
    print(
        f"Upar dikhayi gayi saari {len(matched_records)} files ko extract karne ke liye tayyar hain."
    )
    confirm = (
        input("Kya aap in sabhi files ko extract karna chahte hain? (y/n): ")
        .strip()
        .lower()
    )

    if confirm != "y":
        print(
            "\n[ABORTED] Extraction permission deny ki gayi. Files extract nahi hui."
        )
        return

    # PHASE 2: EXTRACTION
    print("\n" + "=" * 75)
    print("      PHASE 2: AUTO-EXTRACTION & GROUND-LEVEL INTEGRITY AUDIT")
    print("=" * 75)

    diagnostics_log = []
    recovered_count = 0

    with open(ZIP_FILE, "rb") as f:
        for idx, rec in enumerate(matched_records, 1):
            filename = rec["filename"]
            clean_subpath = filename.replace("\\", "/").lstrip("/")
            target_save_path = os.path.join(OUTPUT_EXTRACT_DIR, clean_subpath)

            print(f"[{idx}/{len(matched_records)}] Processing: {filename}")

            status, detail, saved, actual_saved_path = (
                process_stream_and_extract(
                    f,
                    rec["data_offset"],
                    rec["method"],
                    rec["c_size"],
                    rec["u_size"],
                    rec["flags"],
                    rec["crc"],
                    target_save_path,
                )
            )

            if saved:
                recovered_count += 1
                print(f"  └─ SUCCESS: Extracted to -> {actual_saved_path}")
            else:
                print(f"  └─ FAILED: [{status}] -> {detail}")

            diagnostics_log.append({
                "file": filename,
                "header_offset": rec["header_pos"],
                "data_offset": rec["data_offset"],
                "comp_method": rec["method"],
                "comp_size": rec["c_size"],
                "uncomp_size": rec["u_size"],
                "expected_crc": hex(rec["crc"]),
                "status": status,
                "saved": saved,
                "save_path": actual_saved_path,
                "detail": detail,
            })

    write_diagnostic_report(
        total_size, all_paths, diagnostics_log, recovered_count
    )

    print("\n" + "=" * 75)
    print(
        f"EXTRACTION COMPLETED: {recovered_count}/{len(matched_records)} files safely recovered!"
    )
    print(f"Target Folder  : {OUTPUT_EXTRACT_DIR}")
    print(f"Detailed Audit : {REPORT_FILE}")
    print("=" * 75)


if __name__ == "__main__":
    main()
