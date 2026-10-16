import os
import sys

# PyMuPDF library install karein: pip install pymupdf
try:
    import fitz
except ImportError:
    print(
        "PyMuPDF install nahi hai. Pehle CMD me chalayein: pip install pymupdf"
    )
    sys.exit(1)

# ==================== CONFIGURATION ====================
# Jahan aapne main script se files extract ki hain wo folder:
TARGET_DIR = r"C:\path\to\recovered_files"
# =======================================================


def auto_heal_pdfs():
    if not os.path.exists(TARGET_DIR):
        print(f"Directory nahi mili: {TARGET_DIR}")
        return

    print("=" * 70)
    print("      RECOVERED PDF AUTO-HEALING & SYNTAX REBUILD PIPELINE")
    print("=" * 70)
    print(f"Target Directory: {TARGET_DIR}\n")

    healed_count = 0
    already_clean = 0
    failed_count = 0

    # Recursive walk taaki subfolder structure intact rahe
    for root, _, files in os.walk(TARGET_DIR):
        for f in files:
            # Sirf PDFs aur partial salvage files target karein
            if (f.endswith(".pdf") or f.endswith(".partial.pdf")) and (
                not f.startswith("HEALED_")
            ):
                full_path = os.path.join(root, f)
                clean_name = f.replace(".partial.pdf", ".pdf")
                fixed_name = "HEALED_" + clean_name
                fixed_path = os.path.join(root, fixed_name)

                try:
                    # fitz corrupted xref table aur missing trailers ko memory me rebuild karta hai
                    doc = fitz.open(full_path)
                    pages = doc.page_count

                    if pages > 0:
                        # Re-synthesize syntax & clean stream
                        doc.save(
                            fixed_path,
                            garbage=4,  # Dead streams truncate karein
                            deflate=True,  # Healthy streams safely re-compress karein
                            clean=True,  # Corrupt PDF operators remove karein
                        )
                        print(
                            f"[HEALED] {f} -> {pages} readable pages recovered -> {fixed_name}"
                        )
                        healed_count += 1
                    else:
                        print(f"[EMPTY] {f} -> 0 readable pages.")
                        failed_count += 1
                    doc.close()

                except Exception as e:
                    print(f"[FAILED] {f} : {e}")
                    failed_count += 1

    print("\n" + "=" * 70)
    print(
        f"HEALING COMPLETE: {healed_count} PDFs restored with full page access!"
    )
    print(f"Failed / Unreadable: {failed_count}")
    print("=" * 70)


if __name__ == "__main__":
    auto_heal_pdfs()
