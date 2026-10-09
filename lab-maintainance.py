import os
import shutil
import sys
import ctypes
import csv
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def force_print(msg):
    """Ensure output is instantly flushed to the console."""
    print(msg)
    sys.stdout.flush()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def format_size(bytes_val):
    if bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.2f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.2f} MB"
    else:
        return f"{bytes_val / (1024 ** 3):.2f} GB"

def detect_target_drive():
    """Auto-detects the secondary storage drive with maximum available free space."""
    possible_drives = ['D:', 'E:', 'F:']
    best_drive = None
    max_free = 0
    for d in possible_drives:
        drive_path = d + "\\"
        if os.path.exists(drive_path):
            try:
                _, _, free = shutil.disk_usage(drive_path)
                if free > max_free:
                    max_free = free
                    best_drive = d
            except Exception:
                pass
    return best_drive if best_drive else 'D:'

TARGET_DRIVE = detect_target_drive()
DESTINATION_BASE = os.path.join(TARGET_DRIVE, "codefiles")
HEAVY_DESTINATION = os.path.join(TARGET_DRIVE, "codefiles", "Heavy_Media_And_Archives")
AUDIT_LOG_DIR = os.path.join(TARGET_DRIVE, "codefiles", "Audit_Logs")
LOG_CSV_PATH = os.path.join(AUDIT_LOG_DIR, f"migration_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")

CODE_EXTENSIONS = {
    '.c', '.cpp', '.h', '.hpp', '.py',
    '.html', '.htm', '.css', '.js', '.jsx', '.ts', '.tsx',
    '.java', '.kt', '.kts', '.cs', '.php', '.sql', '.r', '.dart',
    '.txt', '.docx', '.pdf', '.xlsx'
}

HEAVY_FILE_EXTS = {
    '.mp4', '.mkv', '.avi', '.mov', '.wmv',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.iso', '.img', '.vmdk',
    '.o', '.obj', '.pdb', '.tmp', '.log', '.layout', '.depend',
    '.torrent'
}

STRICT_EXCLUDE_PATHS = [
    r'c:\windows', r'c:\program files', r'c:\program files (x86)',
    r'c:\programdata', r'$recycle.bin', r'system volume information',
    r'c:\python', r'c:\mingw', r'c:\turboc', r'c:\tc', r'c:\jdk',
    r'node_modules', '.git', '__pycache__', 'venv', '.venv'
]

USERS_ROOT = r"C:\Users"
SYSTEM_USERS = {'all users', 'default', 'default user', 'public'}

def is_path_safe(full_path):
    lower_path = full_path.lower()
    for exc in STRICT_EXCLUDE_PATHS:
        if exc in lower_path:
            return False
    return True

def scan_single_user(user):
    """Scans a single user profile directory in parallel."""
    user_path = os.path.join(USERS_ROOT, user)
    local_codes = []
    local_heavies = []
    local_temps = []

    user_folders = [
        os.path.join(user_path, "Desktop"),
        os.path.join(user_path, "Documents"),
        os.path.join(user_path, "Downloads"),
        os.path.join(user_path, "OneDrive"),
        os.path.join(user_path, r"AppData\Roaming\Code\User\workspaceStorage"),
        os.path.join(user_path, r"AppData\Roaming\JetBrains"),
        os.path.join(user_path, r"AppData\Local\Programs")
    ]

    for folder in user_folders:
        if not os.path.exists(folder):
            continue
        try:
            for root, _, files in os.walk(folder):
                if not is_path_safe(root):
                    continue
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    if not is_path_safe(file_path):
                        continue
                    ext = os.path.splitext(file_name)[1].lower()
                    try:
                        sz = os.path.getsize(file_path)
                        rel_dir = os.path.relpath(root, user_path)
                        if ext in CODE_EXTENSIONS:
                            local_codes.append((user, file_path, rel_dir, file_name, sz))
                        elif ext in HEAVY_FILE_EXTS:
                            local_heavies.append((user, file_path, rel_dir, file_name, sz))
                    except Exception:
                        pass
        except Exception:
            pass

    # User temp & cache directories
    temp_folders = [
        os.path.join(user_path, r"AppData\Local\Temp"),
        os.path.join(user_path, r"AppData\Local\CrashDumps"),
        os.path.join(user_path, r"AppData\Local\Google\Chrome\User Data\Default\Cache"),
        os.path.join(user_path, r"AppData\Local\Microsoft\Edge\User Data\Default\Cache")
    ]

    for tf in temp_folders:
        if os.path.exists(tf):
            try:
                for root, _, files in os.walk(tf):
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        try:
                            sz = os.path.getsize(file_path)
                            local_temps.append((file_path, sz))
                        except Exception:
                            pass
            except Exception:
                pass

    return local_codes, local_heavies, local_temps

def display_file_table(file_list, title, is_code=True, preview_limit=30):
    total = len(file_list)
    if total == 0:
        return

    force_print("\n" + "=" * 80)
    force_print(f" DETAILS: {title} (Total: {total} items)")
    force_print("=" * 80)
    force_print(f"{'#':<5} | {'USER':<18} | {'SIZE':<10} | {'LOCATION'}")
    force_print("-" * 80)

    display_count = min(total, preview_limit)
    for i in range(display_count):
        if is_code:
            user, _, rel_dir, file_name, sz = file_list[i]
            force_print(f"{i+1:<5} | {user:<18} | {format_size(sz):<10} | {rel_dir}\\{file_name}")
        else:
            fp, sz = file_list[i]
            force_print(f"{i+1:<5} | {'TEMP_CACHE':<18} | {format_size(sz):<10} | {fp}")

    if total > preview_limit:
        force_print("-" * 80)
        show_all = input(f"--> Aur {total - preview_limit} items hain. Kya sabhi terminal par dekhna chahte hain? (y/n): ").strip().lower()
        if show_all == 'y':
            for i in range(preview_limit, total):
                if is_code:
                    user, _, rel_dir, file_name, sz = file_list[i]
                    force_print(f"{i+1:<5} | {user:<18} | {format_size(sz):<10} | {rel_dir}\\{file_name}")
                else:
                    fp, sz = file_list[i]
                    force_print(f"{i+1:<5} | {'TEMP_CACHE':<18} | {format_size(sz):<10} | {fp}")
    force_print("-" * 80)

def safe_transfer_files(file_list, dest_root, audit_writer, label="files"):
    """Copies, verifies, and deletes original to prevent data loss on locks."""
    os.makedirs(dest_root, exist_ok=True)
    moved_count = 0
    failed_count = 0

    force_print(f"\n[*] Transferring {label} to '{dest_root}'...")

    for user, src_path, rel_dir, file_name, size in file_list:
        target_dir = os.path.join(dest_root, user, rel_dir)
        os.makedirs(target_dir, exist_ok=True)
        dest_path = os.path.join(target_dir, file_name)

        # Handle duplicate filenames in same path
        base, ext = os.path.splitext(file_name)
        cnt = 1
        while os.path.exists(dest_path):
            dest_path = os.path.join(target_dir, f"{base}_{cnt}{ext}")
            cnt += 1

        try:
            shutil.copy2(src_path, dest_path)
            # Verify file size before deleting source
            if os.path.getsize(dest_path) == size:
                os.remove(src_path)
                moved_count += 1
                audit_writer.writerow([datetime.now().isoformat(), user, src_path, dest_path, size, "MOVED_SUCCESS"])
                force_print(f" [OK] {user} -> {rel_dir}\\{file_name}")
            else:
                failed_count += 1
                audit_writer.writerow([datetime.now().isoformat(), user, src_path, dest_path, size, "COPY_SIZE_MISMATCH"])
        except Exception as e:
            failed_count += 1
            audit_writer.writerow([datetime.now().isoformat(), user, src_path, "N/A", size, f"FAILED_LOCKED: {e}"])
            force_print(f" [LOCKED/SKIP] {src_path}")

    force_print(f"[+] Completed: {moved_count} {label} moved. ({failed_count} locked/skipped)")

def purge_deep_system():
    """Frees massive SSD space by clearing SoftwareDistribution, Temp, and disabling Hibernation."""
    force_print("\n[*] Purging Windows updates cache and disabling hibernation file...")
    cmds = [
        'powercfg -h off',
        'del /q/f/s "%systemroot%\\SoftwareDistribution\\Download\\*"',
        'del /q/f/s "%systemroot%\\Temp\\*"'
    ]
    for c in cmds:
        subprocess.run(c, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    force_print("[+] Deep system components clean completed.")

def main():
    force_print("=" * 80)
    force_print(f"   ENTERPRISE LAB RESCUE & MIGRATION TOOL (TARGET: {TARGET_DRIVE})")
    force_print("=" * 80)

    if not is_admin():
        force_print("[!] Warning: Run as Administrator to access system roots & all profiles!\n")

    # 1. Detect All Lab Users
    users = [u for u in os.listdir(USERS_ROOT) if os.path.isdir(os.path.join(USERS_ROOT, u)) and u.lower() not in SYSTEM_USERS]
    force_print(f"[*] Detected {len(users)} User Profiles under {USERS_ROOT}")

    # 2. Parallel Fast Scanning
    force_print("[*] Starting multi-threaded scan across all profiles...")
    coding_files, heavy_files, temp_files = [], [], []

    with ThreadPoolExecutor(max_workers=8) as executor:
        scan_results = executor.map(scan_single_user, users)
        for codes, heavies, temps in scan_results:
            coding_files.extend(codes)
            heavy_files.extend(heavies)
            temp_files.extend(temps)

    # Add Windows System Temp
    sys_temp = r"C:\Windows\Temp"
    if os.path.exists(sys_temp):
        for root, _, files in os.walk(sys_temp):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    temp_files.append((fp, os.path.getsize(fp)))
                except Exception:
                    pass

    # Storage calculations
    code_sz = sum(x[4] for x in coding_files)
    heavy_sz = sum(x[4] for x in heavy_files)
    temp_sz = sum(x[1] for x in temp_files)

    # 3. Summary Dashboard
    force_print("\n" + "=" * 80)
    force_print("                    STORAGE ESTIMATE BREAKDOWN")
    force_print("=" * 80)
    force_print(f" [ C: -> {TARGET_DRIVE} ] Student Code Files to Move   : {format_size(code_sz)} ({len(coding_files)} files)")
    force_print(f" [ C: -> {TARGET_DRIVE} ] Heavy Media / Archives to Move : {format_size(heavy_sz)} ({len(heavy_files)} files)")
    force_print(f" [ C: DRIVE RECLAIM ] Temp / Caches to Delete        : {format_size(temp_sz)} ({len(temp_files)} files)")
    force_print(f" [ AUDIT REPORT ] Will be saved to                   : {LOG_CSV_PATH}")
    force_print("=" * 80)

    # Ensure log directory exists
    os.makedirs(AUDIT_LOG_DIR, exist_ok=True)

    with open(LOG_CSV_PATH, mode='w', newline='', encoding='utf-8') as log_file:
        writer = csv.writer(log_file)
        writer.writerow(["Timestamp", "User", "SourcePath", "DestPath", "SizeBytes", "Status"])

        # --- SECTION 1: STUDENT CODE FILES ---
        if coding_files:
            display_file_table(coding_files, "STUDENT CODE FILES", is_code=True)
            choice_code = input(f"\nMove all {len(coding_files)} code files to '{DESTINATION_BASE}'? (y/n): ").strip().lower()
            if choice_code == 'y':
                safe_transfer_files(coding_files, DESTINATION_BASE, writer, label="coding files")
            else:
                force_print("[*] Code migration skipped.")
        else:
            force_print("\n[-] No student code files detected.")

        # --- SECTION 2: HEAVY MEDIA & ARCHIVES ---
        if heavy_files:
            display_file_table(heavy_files, "HEAVY MEDIA & ARCHIVES", is_code=True)
            force_print("\nAction choices for heavy files:")
            force_print(f" [m] Move to {HEAVY_DESTINATION}")
            force_print(" [d] Delete permanently from C: drive")
            force_print(" [s] Skip")

            choice_heavy = input("\nSelect action (m/d/s): ").strip().lower()
            if choice_heavy == 'm':
                safe_transfer_files(heavy_files, HEAVY_DESTINATION, writer, label="heavy files")
            elif choice_heavy == 'd':
                del_cnt = 0
                for user, fp, _, _, sz in heavy_files:
                    try:
                        os.remove(fp)
                        del_cnt += 1
                        writer.writerow([datetime.now().isoformat(), user, fp, "DELETED", sz, "PURGED_SUCCESS"])
                    except Exception as e:
                        writer.writerow([datetime.now().isoformat(), user, fp, "N/A", sz, f"DELETE_FAILED: {e}"])
                force_print(f"[+] Permanently deleted {del_cnt} heavy files.")
            else:
                force_print("[*] Heavy file action skipped.")
        else:
            force_print("\n[-] No heavy media/archive files detected.")

        # --- SECTION 3: DEEP TEMP & SYSTEM CLEANUP ---
        if temp_files:
            choice_temp = input(f"\nPurge ~{format_size(temp_sz)} of Temp Caches + Deep Windows Update bloat on C:? (y/n): ").strip().lower()
            if choice_temp == 'y':
                del_temp = 0
                for fp, sz in temp_files:
                    try:
                        os.remove(fp)
                        del_temp += 1
                    except Exception:
                        pass
                purge_deep_system()
                writer.writerow([datetime.now().isoformat(), "SYSTEM", "TempCaches_and_SoftwareDist", "PURGED", temp_sz, "PURGED_SUCCESS"])
                force_print(f"[+] Cleaned {del_temp} temporary files & freed Windows update caches!")
            else:
                force_print("[*] Temp cleanup skipped.")

    force_print(f"\n[✓] All Operations Completed! Audit report generated at: {LOG_CSV_PATH}")

if __name__ == "__main__":
    try:
        main()
    except Exception as fatal_err:
        print(f"[!] Fatal Execution Error: {fatal_err}")