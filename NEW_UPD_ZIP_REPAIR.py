import datetime
import io
import os
import re
import shutil
import struct
import sys
import zlib
from PIL import Image

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
JPEG_SOI = b"\xff\xd8\xff"
JPEG_EOI = b"\xff\xd9"


def safe_win_path(path):
    abs_path = os.path.abspath(path)
    if os.name == "nt" and not abs_path.startswith("\\\\?\\"):
        return "\\\\?\\" + abs_path
    return abs_path


def check_disk_space(target_dir, required_gb):
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


def build_pure_image_pdf(jpeg_bytes):
    try:
        img = Image.open(io.BytesIO(jpeg_bytes))
        width, height = img.size
    except Exception:
        width, height = 595, 842

    img_len = len(jpeg_bytes)
    pdf_parts = []
    pdf_parts.append(b"%PDF-1.4\n")

    o1_offset = len(b"".join(pdf_parts))
    pdf_parts.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

    o2_offset = len(b"".join(pdf_parts))
    pdf_parts.append(
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    )

    o3_offset = len(b"".join(pdf_parts))
    page_obj = f"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>\nendobj\n"
    pdf_parts.append(page_obj.encode("ascii"))

    o4_offset = len(b"".join(pdf_parts))
    img_header = f"4 0 obj\n<< /Type /XObject /Subtype /Image /Width {width} /Height {height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length {img_len} >>\nstream\n".encode(
        "ascii"
    )
    pdf_parts.append(img_header)
    pdf_parts.append(jpeg_bytes)
    pdf_parts.append(b"\nendstream\nendobj\n")

    stream_content = f"q\n{width} 0 0 {height} 0 0 cm\n/Im0 Do\nQ\n".encode(
        "ascii"
    )
    o5_offset = len(b"".join(pdf_parts))
    pdf_parts.append(
        f"5 0 obj\n<< /Length {len(stream_content)} >>\nstream\n".encode(
            "ascii"
        )
    )
    pdf_parts.append(stream_content)
    pdf_parts.append(b"endstream\nendobj\n")

    xref_offset = len(b"".join(pdf_parts))
    xref = (
        f"xref\n0 6\n"
        f"0000000000 65535 f \n"
        f"{o1_offset:010d} 00000 n \n"
        f"{o2_offset:010d} 00000 n \n"
        f"{o3_offset:010d} 00000 n \n"
        f"{o4_offset:010d} 00000 n \n"
        f"{o5_offset:010d} 00000 n \n"
        f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
    )
    pdf_parts.append(xref.encode("ascii"))
    return b"".join(pdf_parts)


def deep_complex_salvage(raw_compressed):
    out_buf = bytearray()
    ptr = 0
    raw_len = len(raw_compressed)
    d = zlib.decompressobj(-15)
    step = 2048

    while ptr < raw_len:
        try:
            chunk = d.decompress(raw_compressed[ptr : ptr + step])
            if chunk:
                out_buf.extend(chunk)
            ptr += step
        except zlib.error:
            ptr += 1
            d = zlib.decompressobj(-15)

    try:
        tail = d.flush()
        if tail:
            out_buf.extend(tail)
    except Exception:
        pass

    decompressed_data = bytes(out_buf)
    search_space = decompressed_data + raw_compressed

    soi_idx = search_space.find(JPEG_SOI)
    if soi_idx != -1:
        eoi_idx = search_space.rfind(JPEG_EOI)
        if eoi_idx != -1 and eoi_idx > soi_idx:
            jpeg_candidate = search_space[soi_idx : eoi_idx + 2]
        else:
            jpeg_candidate = search_space[soi_idx:]

        if len(jpeg_candidate) > 20000:
            return build_pure_image_pdf(jpeg_candidate), "SYNTHESIZED_IMAGE_PDF"

    if b"%PDF-" in decompressed_data[:2048]:
        fixed = bytearray(decompressed_data)
        if not fixed.endswith(b"%%EOF") and b"%%EOF" not in fixed[-1024:]:
            fixed.extend(
                b"\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n0\n%%EOF\n"
            )
        return bytes(fixed), "HEALED_PARTIAL_PDF"

    return decompressed_data, "RAW_SALVAGED"


def process_stream_and_extract(
    f,
    data_offset,
    comp_method,
    comp_size,
    uncomp_size,
    flags,
    expected_crc,
    target_save_path,
    next_header_offset,
):
    has_data_descriptor = bool(flags & 0x0008)

    if comp_size > 0 and comp_size != 0xFFFFFFFF:
        read_len = comp_size
    elif next_header_offset and next_header_offset > data_offset:
        read_len = next_header_offset - data_offset
    else:
        read_len = 80 * 1024 * 1024

    f.seek(data_offset)
    raw_data = f.read(read_len)

    if not raw_data:
        return (
            "FATAL_TRUNCATED",
            "Zero bytes readable at offset (Hard physical cutoff).",
            False,
            "N/A",
        )

    if comp_method == 0:
        actual_len = (
            uncomp_size
            if (uncomp_size > 0 and uncomp_size != 0xFFFFFFFF)
            else len(raw_data)
        )
        out_bytes = raw_data[:actual_len]
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
        detail = f"Written {len(out_bytes)} bytes."
        return status, detail, True, final_path

    elif comp_method == 8:
        try:
            decompressed = zlib.decompress(raw_data, -15)
            calc_crc = zlib.crc32(decompressed) & 0xFFFFFFFF
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
            detail = f"Decompressed clean {len(decompressed)} bytes."
            return status, detail, True, final_path

        except zlib.error as ze:
            repaired_bytes, repair_mode = deep_complex_salvage(raw_data)

            if len(repaired_bytes) > 1024:
                final_path = safe_win_path(target_save_path)
                os.makedirs(os.path.dirname(final_path), exist_ok=True)
                with open(final_path, "wb") as out_f:
                    out_f.write(repaired_bytes)

                return (
                    f"REPAIRED_{repair_mode}",
                    f"Recovered {len(repaired_bytes)} bytes via sliding window decompression.",
                    True,
                    final_path,
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

        out.write(
            "SECTION 2: FILE-BY-FILE DIAGNOSTIC AUDIT & EXTRACTION STATE\n"
        )
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
    total_size_gb = total_size / (1024**3)

    print("=" * 75)
    print("      PHASE 1: SCANNING 27 GB ARCHIVE (DISCOVERY & TREE CREATION)")
    print("=" * 75)
    print(f"Archive        : {ZIP_FILE} ({total_size_gb:.2f} GB)")
    print("Status         : Parsing byte stream... Please wait.\n")

    current_offset = 0
    matched_records = []

    try:
        with open(ZIP_FILE, "rb") as f:
            while current_offset < total_size:
                progress = (current_offset / total_size) * 100
                scanned_gb = current_offset / (1024**3)

                # Real-time scan statistics display
                sys.stdout.write(
                    f"\r[SCANNING] {progress:5.2f}% | Scanned: {scanned_gb:5.2f}/{total_size_gb:.2f} GB | Targets Found: {len(matched_records):<5}"
                )
                sys.stdout.flush()

                try:
                    f.seek(current_offset)
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                except Exception:
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

                            if (
                                c_size == 0xFFFFFFFF or u_size == 0xFFFFFFFF
                            ) and extra_bytes:
                                z64_u, z64_c = parse_zip64_extra(extra_bytes)
                                if z64_u is not None:
                                    u_size = z64_u
                                if z64_c is not None:
                                    c_size = z64_c

                            clean_name = filename.lower()
                            pattern_match = bool(
                                re.search(
                                    r"9[\s_\-\.]{0,5}important", clean_name
                                )
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
                                # Jaise hi target mile, console par update
                                sys.stdout.write(
                                    f"\n   [+] Found #{len(matched_records)}: {filename}\n"
                                )
                                sys.stdout.flush()

                    except Exception:
                        pass

                    sig_idx += 4

                current_offset += CHUNK_SIZE - 4096

    except KeyboardInterrupt:
        print("\n\n[PAUSED] Scan early interrupt by user.")

    total_found = len(matched_records)
    print("\n\n" + "=" * 75)
    print(f"PHASE 1 COMPLETE: Total Found Target Files = {total_found}")
    print("=" * 75)

    if total_found == 0:
        print("Koi bhi matching file nahi mili. Process aborted.")
        return

    # Accurate boundaries ke liye sort karein
    matched_records.sort(key=lambda x: x["header_pos"])

    all_paths = [rec["filename"] for rec in matched_records]
    tree = build_tree_structure(all_paths)
    print("\n--- FOUND DIRECTORY & FILE TREE ---")
    for line in render_tree(tree):
        print(line)
    print(f"-----------------------------------\nTotal Files in Tree: {total_found}\n")

    confirm = (
        input(f"Kya aap in sabhi {total_found} files ko deep-repair extract karna chahte hain? (y/n): ")
        .strip()
        .lower()
    )
    if confirm != "y":
        print("\n[ABORTED] Process cancel kiya gaya.")
        return

    # PHASE 2: DEEP REPAIR EXTRACTION
    print("\n" + "=" * 75)
    print("      PHASE 2: AUTO-EXTRACTION & DEEP REPAIR EXECUTION")
    print("=" * 75)

    diagnostics_log = []
    recovered_count = 0
    repaired_count = 0
    failed_count = 0

    with open(ZIP_FILE, "rb") as f:
        for idx, rec in enumerate(matched_records):
            filename = rec["filename"]
            next_offset = (
                matched_records[idx + 1]["header_pos"]
                if (idx + 1) < total_found
                else None
            )

            clean_subpath = filename.replace("\\", "/").lstrip("/")
            clean_subpath = clean_subpath.replace(".partial", "")
            if not clean_subpath.lower().endswith(".pdf"):
                clean_subpath += ".pdf"

            target_save_path = os.path.join(OUTPUT_EXTRACT_DIR, clean_subpath)

            print(
                f"\n[{idx+1}/{total_found}] Processing ({((idx+1)/total_found)*100:.1f}%): {filename}"
            )

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
                    next_offset,
                )
            )

            if saved:
                recovered_count += 1
                if "REPAIRED" in status:
                    repaired_count += 1
                    print(f"  └─ [REPAIRED OK] Status: {status}")
                else:
                    print(f"  └─ [HEALTHY EXTRACT] Status: {status}")
                print(f"  └─ Saved Path: {actual_saved_path}")
            else:
                failed_count += 1
                print(f"  └─ [FAILED] Status: {status} | Detail: {detail}")

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
    print("EXTRACTION SUMMARY:")
    print(f"  ├─ Total Files Discovered : {total_found}")
    print(f"  ├─ Clean Extracted        : {recovered_count - repaired_count}")
    print(f"  ├─ Deep-Repaired / Salvaged: {repaired_count}")
    print(f"  ├─ Total Recovered Saved  : {recovered_count}/{total_found}")
    print(f"  └─ Failed / Destroyed     : {failed_count}")
    print(f"\nTarget Folder  : {OUTPUT_EXTRACT_DIR}")
    print(f"Detailed Audit : {REPORT_FILE}")
    print("=" * 75)


if __name__ == "__main__":
    main()
