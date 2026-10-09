import os
import shutil
import sys
import ctypes

def force_print(msg):
    """Ensure output is instantly flushed to the console."""
    print(msg)
    sys.stdout.flush()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# Target source code extensions
CODE_EXTENSIONS = {
    '.c', '.cpp', '.h', '.hpp', '.py',
    '.html', '.htm', '.css', '.js', '.jsx', '.ts', '.tsx',
    '.java', '.kt', '.kts', '.cs', '.php', '.sql', '.r', '.dart'
}

# Heavy media, archives, and build artifacts (EXCLUDES .exe and .msi)
HEAVY_FILE_EXTS = {
    '.mp4', '.mkv', '.avi', '.mov', '.wmv',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.iso', '.img', '.vmdk',
    '.o', '.obj', '.pdb', '.tmp', '.log',
    '.torrent'
}

STRICT_EXCLUDE_PATHS = [
    r'c:\program files',
    r'c:\program files (x86)',
    r'c:\programdata',
    r'$recycle.bin',
    r'system volume information',
    r'c:\python',
    r'c:\mingw',
    r'c:\turboc',
    r'c:\tc',
    r'c:\jdk',
    r'c:\java',
    r'c:\xampp',
    r'c:\wamp',
    r'appdata\local\programs\python',
    r'appdata\local\programs',
    r'appdata\roaming\python',
    r'appdata\local\pip',
    r'python3',
    r'\lib\test',
    r'\doc\html',
    r'site-packages',
    r'dist-packages',
    'node_modules',
    '.git',
    '__pycache__',
    'venv',
    '.venv',
    'windowsapps',
    'microsoft'
]

USERS_ROOT = r"C:\Users"
SYSTEM_USERS = {'all users', 'default', 'default user', 'public', 'administrator'}
DESTINATION_BASE = r"D:\codefiles"
HEAVY_DESTINATION = r"D:\codefiles\Heavy_Media_And_Archives"

def is_path_safe(full_path):
    lower_path = full_path.lower()
    for exclude_keyword in STRICT_EXCLUDE_PATHS:
        if exclude_keyword in lower_path:
            return False
    return True

def get_detected_users():
    """Detects and returns all non-system user accounts from C:\\Users."""
    if not os.path.exists(USERS_ROOT):
        return []
    
    valid_users = []
    try:
        all_entries = os.listdir(USERS_ROOT)
        for entry in all_entries:
            entry_path = os.path.join(USERS_ROOT, entry)
            if os.path.isdir(entry_path) and entry.lower() not in SYSTEM_USERS:
                valid_users.append(entry)
    except Exception as e:
        force_print(f"[!] Error reading user profiles: {e}")
    
    return valid_users

def scan_system(users):
    coding_files = []
    heavy_files = []
    temp_junk_files = []
    code_size_bytes = 0
    heavy_size_bytes = 0
    temp_size_bytes = 0

    if not users:
        force_print(f"[!] No valid user accounts detected under {USERS_ROOT}")
        return coding_files, code_size_bytes, heavy_files, heavy_size_bytes, temp_junk_files, temp_size_bytes

    force_print("\n[*] Starting file scan across user profiles...")

    for user in users:
        user_path = os.path.join(USERS_ROOT, user)
        force_print(f" -> Inspecting profile: {user}")

        user_folders = [
            os.path.join(user_path, "Desktop"),
            os.path.join(user_path, "Documents"),
            os.path.join(user_path, "Downloads"),
            os.path.join(user_path, "OneDrive"),
            os.path.join(user_path, r"AppData\Roaming\Code\User\workspaceStorage"),
            os.path.join(user_path, r"AppData\Roaming\JetBrains")
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

                        if ext in CODE_EXTENSIONS:
                            try:
                                f_size = os.path.getsize(file_path)
                                coding_files.append((user, file_path))
                                code_size_bytes += f_size
                            except Exception:
                                pass
                        elif ext in HEAVY_FILE_EXTS:
                            try:
                                f_size = os.path.getsize(file_path)
                                heavy_files.append((user, file_path))
                                heavy_size_bytes += f_size
                            except Exception:
                                pass
            except Exception as walk_err:
                force_print(f" [!] Error reading {folder}: {walk_err}")

        # User-specific Temp & Cache directories
        temp_cache_folders = [
            os.path.join(user_path, r"AppData\Local\Temp"),
            os.path.join(user_path, r"AppData\Local\CrashDumps"),
            os.path.join(user_path, r"AppData\Local\Google\Chrome\User Data\Default\Cache"),
            os.path.join(user_path, r"AppData\Local\Microsoft\Edge\User Data\Default\Cache")
        ]

        for temp_folder in temp_cache_folders:
            if os.path.exists(temp_folder):
                try:
                    for root, _, files in os.walk(temp_folder):
                        for file_name in files:
                            file_path = os.path.join(root, file_name)
                            try:
                                f_size = os.path.getsize(file_path)
                                temp_junk_files.append(file_path)
                                temp_size_bytes += f_size
                            except Exception:
                                pass
                except Exception:
                    pass

    # System-wide Temp & Prefetch Directories (Require Admin Privileges)
    system_temp_folders = [
        r"C:\Windows\Temp",
        r"C:\Windows\Prefetch"
    ]

    for sys_temp in system_temp_folders:
        if os.path.exists(sys_temp):
            try:
                for root, _, files in os.walk(sys_temp):
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        try:
                            f_size = os.path.getsize(file_path)
                            temp_junk_files.append(file_path)
                            temp_size_bytes += f_size
                        except Exception:
                            pass
            except Exception:
                pass

    return coding_files, code_size_bytes, heavy_files, heavy_size_bytes, temp_junk_files, temp_size_bytes

def move_files(file_list, destination_root, label="files"):
    os.makedirs(destination_root, exist_ok=True)
    moved_count = 0
    failed_count = 0

    force_print(f"\n[*] Transferring {label} to '{destination_root}'...")

    for user, src_path in file_list:
        try:
            target_user_dir = os.path.join(destination_root, user)
            os.makedirs(target_user_dir, exist_ok=True)

            file_name = os.path.basename(src_path)
            dest_path = os.path.join(target_user_dir, file_name)

            base, ext = os.path.splitext(file_name)
            counter = 1
            while os.path.exists(dest_path):
                dest_path = os.path.join(target_user_dir, f"{base}_{counter}{ext}")
                counter += 1

            shutil.move(src_path, dest_path)
            moved_count += 1
            force_print(f" [MOVED] {user} -> {file_name}")
        except Exception as e:
            failed_count += 1
            force_print(f" [FAILED] {src_path}: {e}")

    force_print(f"[+] Completed: {moved_count} {label} moved successfully. ({failed_count} skipped/locked)")

def purge_temp_files(temp_files):
    deleted_count = 0
    freed_bytes = 0
    force_print("\n[*] Purging temporary caches, crash dumps, system temp, and prefetch...")

    for file_path in temp_files:
        try:
            f_size = os.path.getsize(file_path)
            os.remove(file_path)
            deleted_count += 1
            freed_bytes += f_size
        except Exception:
            pass

    freed_gb = round(freed_bytes / (1024 ** 3), 2)
    force_print(f"[+] Deleted {deleted_count} temporary files.")
    force_print(f"[+] Reclaimed space on C: drive: ~{freed_gb} GB")

def main():
    force_print("=" * 70)
    force_print("      LAB STORAGE MAINTENANCE & CODE MIGRATION TOOL")
    force_print("=" * 70)

    if not is_admin():
        force_print("[!] Warning: Script is running without Administrator privileges.")
        force_print("[!] Run as Administrator to access C:\\Windows\\Temp and all profile directories.\n")

    # --- USER ACCOUNT DETECTION ---
    users = get_detected_users()
    force_print("\n" + "=" * 70)
    force_print(f"[*] Total User Accounts Detected: {len(users)}")
    force_print("=" * 70)
    
    if users:
        for idx, u in enumerate(users, start=1):
            force_print(f" {idx}. Username: {u}")
    else:
        force_print("[-] No active user profiles found.")

    # --- SYSTEM SCAN ---
    coding_files, code_size, heavy_files, heavy_size, temp_junk, temp_size = scan_system(users)

    # --- ESTIMATED STORAGE SUMMARY ---
    code_mb = round(code_size / (1024 ** 2), 2)
    heavy_gb = round(heavy_size / (1024 ** 3), 2)
    temp_gb = round(temp_size / (1024 ** 3), 2)

    force_print("\n" + "=" * 70)
    force_print("      STORAGE ESTIMATE SUMMARY (DRIVE-WISE)")
    force_print("=" * 70)
    force_print(f" [ DRIVE C: ] Space to be FREED by deleting Temp/Junk: ~{temp_gb} GB ({len(temp_junk)} files)")
    force_print(f" [ DRIVE C: -> D: ] Source Code data to be MOVED: ~{code_mb} MB ({len(coding_files)} files)")
    force_print(f" [ DRIVE C: -> D: ] Heavy Media/Archives data to be MOVED: ~{heavy_gb} GB ({len(heavy_files)} files)")
    force_print("=" * 70)

    # --- SOURCE CODE MIGRATION ---
    force_print("\n" + "-" * 70)
    force_print(f"1. SOURCE CODE FILES ({len(coding_files)} files, ~{code_mb} MB)")
    force_print("-" * 70)

    if coding_files:
        choice_code = input(f"Move all {len(coding_files)} source code files (~{code_mb} MB) to 'D:\\codefiles'? (y/n): ").strip().lower()
        if choice_code == 'y':
            move_files(coding_files, DESTINATION_BASE, label="code files")
        else:
            force_print("[*] Code migration skipped.")
    else:
        force_print("[-] No source code files detected.")

    # --- HEAVY MEDIA & ARCHIVES MIGRATION ---
    force_print("\n" + "-" * 70)
    force_print(f"2. HEAVY MEDIA & ARCHIVES ({len(heavy_files)} files, ~{heavy_gb} GB)")
    force_print("-" * 70)

    if heavy_files:
        force_print("Action choices for heavy files:")
        force_print(" [m] Move to D:\\codefiles\\Heavy_Media_And_Archives")
        force_print(" [d] Delete permanently from C: drive")
        force_print(" [s] Skip")
        
        choice_heavy = input("\nSelect action (m/d/s): ").strip().lower()
        
        if choice_heavy == 'm':
            move_files(heavy_files, HEAVY_DESTINATION, label="heavy files")
        elif choice_heavy == 'd':
            deleted = 0
            for _, fp in heavy_files:
                try:
                    os.remove(fp)
                    deleted += 1
                except Exception:
                    pass
            force_print(f"[+] Deleted {deleted} heavy files.")
        else:
            force_print("[*] Heavy file action skipped.")
    else:
        force_print("[-] No heavy files detected.")

    # --- TEMP & CACHE PURGE ---
    force_print("\n" + "-" * 70)
    force_print(f"3. TEMPORARY JUNK & CACHES ({len(temp_junk)} files, ~{temp_gb} GB)")
    force_print("-" * 70)

    if temp_junk:
        choice_temp = input(f"Purge ~{temp_gb} GB of temporary system cache files from C: drive? (y/n): ").strip().lower()
        if choice_temp == 'y':
            purge_temp_files(temp_junk)
        else:
            force_print("[*] Temp cleanup skipped.")
    else:
        force_print("[-] No temporary cache files found.")

    force_print("\n[✓] System scan and maintenance complete.")

if __name__ == "__main__":
    try:
        main()
    except Exception as fatal_err:
        print(f"[!] Fatal Execution Error: {fatal_err}")