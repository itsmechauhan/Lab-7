import os
import sys

# ==================== CONFIGURATIONS ====================
ZIP_FILE = r"C:\path\to\your\corrupt_file.zip"
CARVE_OUTPUT_DIR = r"C:\path\to\emergency_carved_pdfs"
CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB buffer
# ========================================================

PDF_START = b"%PDF-"
PDF_END = b"%%EOF"


def emergency_carve():
    if not os.path.exists(ZIP_FILE):
        print(f"Archive file nahi mili: {ZIP_FILE}")
        return

    os.makedirs(CARVE_OUTPUT_DIR, exist_ok=True)
    total_size = os.path.getsize(ZIP_FILE)

    print("=" * 70)
    print("      EMERGENCY RAW BYTE CARVER (ZERO HEADER DEPENDENCY)")
    print("=" * 70)
    print(f"Scanning 27 GB stream: {ZIP_FILE}\n")

    current_offset = 0
    pdf_count = 0
    leftover = b""

    with open(ZIP_FILE, "rb") as f:
        while current_offset < total_size:
            progress = (current_offset / total_size) * 100
            sys.stdout.write(
                f"\rCarving Progress: {progress:.2f}% | Extracted: {pdf_count} Raw PDFs..."
            )
            sys.stdout.flush()

            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            data = leftover + chunk
            idx = 0

            while True:
                start = data.find(PDF_START, idx)
                if start == -1:
                    break

                # Max 60 MB window limit per document
                end = data.find(PDF_END, start)
                if end != -1 and (end - start) < (60 * 1024 * 1024):
                    pdf_data = data[start : end + len(PDF_END)]
                    pdf_count += 1

                    out_path = os.path.join(
                        CARVE_OUTPUT_DIR, f"carved_doc_{pdf_count}.pdf"
                    )
                    with open(out_path, "wb") as out_f:
                        out_f.write(pdf_data)

                    idx = end + len(PDF_END)
                else:
                    idx = start + 5
                    break

            leftover = data[- (4 * 1024 * 1024) :]
            current_offset += CHUNK_SIZE

    print("\n\n" + "=" * 70)
    print(f"DONE: Total {pdf_count} uncompressed raw PDFs successfully carved!")
    print(f"Files saved in: {CARVE_OUTPUT_DIR}")
    print("=" * 70)


if __name__ == "__main__":
    emergency_carve()
