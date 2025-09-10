import os
import hashlib
import shutil
import time
import math
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# --- Config ---
MALWARE_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR test
    "5d41402abc4b2a76b9719d911017c592",  # Dummy
}

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".scr", ".cmd", ".js", ".vbs"}
QUARANTINE_DIR = Path.cwd() / "quarantine"
QUARANTINE_DIR.mkdir(exist_ok=True)

# --- Detection Logic ---
def get_md5(file_path):
    try:
        h = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def is_suspicious_file(file_path):
    ext = Path(file_path).suffix.lower()
    return ext in SUSPICIOUS_EXTENSIONS

def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        entropy = 0
        for count in byte_counts:
            if count == 0:
                continue
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy
    except Exception:
        return 0

def quarantine_file(file_path):
    base = os.path.basename(file_path)
    dest = QUARANTINE_DIR / f"{int(time.time())}_{base}"
    try:
        shutil.move(file_path, dest)
        return f"[ACTION] Quarantined: {dest}"
    except Exception as e:
        return f"[ERROR] Failed to quarantine: {e}"

def clean_file(file_path):
    ext = Path(file_path).suffix.lower()
    entropy = calculate_entropy(file_path)
    file_hash = get_md5(file_path)

    try:
        if file_hash in MALWARE_HASHES:
            os.remove(file_path)
            return f"[CLEANED] Known malware removed: {file_path}"

        if ext in {".bat", ".vbs", ".js"} and entropy > 7.5:
            os.remove(file_path)
            return f"[CLEANED] Suspicious script deleted: {file_path}"

        if ext in {".exe", ".dll"} and entropy > 7.8:
            os.remove(file_path)
            return f"[CLEANED] Packed binary removed: {file_path}"

        return f"[SKIPPED] File looks safe: {file_path}"
    except Exception:
        q = quarantine_file(file_path)
        return f"[FAILED DELETE] Quarantined instead: {file_path}\n{q}"

def scan_file(file_path):
    file_hash = get_md5(file_path)
    if not file_hash:
        return f"[ERROR] Could not read: {file_path}"

    if file_hash in MALWARE_HASHES:
        result = f"[ALERT] Known malware: {os.path.basename(file_path)}"
        clean_result = clean_file(file_path)
        return f"{result}\n{clean_result}"

    if is_suspicious_file(file_path):
        entropy = calculate_entropy(file_path)
        if entropy > 7.5:
            result = f"[WARNING] Packed/Encrypted file: {os.path.basename(file_path)} (entropy={entropy:.2f})"
            clean_result = clean_file(file_path)
            return f"{result}\n{clean_result}"
        else:
            return f"[NOTICE] Suspicious file: {os.path.basename(file_path)} (entropy={entropy:.2f})"

    return f"[OK] File is clean: {os.path.basename(file_path)}"

def scan_directory(folder, output_widget, settings):
    folder = Path(folder).resolve()
    output_widget.insert(tk.END, f"[INFO] Scanning: {folder}\n\n")
    for root, _, files in os.walk(folder):
        for file in files:
            full_path = os.path.join(root, file)
            if not settings["show_hidden"].get() and os.path.basename(full_path).startswith("."):
                continue
            result = scan_file(full_path)
            output_widget.insert(tk.END, result + "\n")
            output_widget.see(tk.END)

def scan_all_drives(output_widget, settings):
    drives = [f"{d}:/" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:/")]
    output_widget.insert(tk.END, "[INFO] Starting full system scan...\n\n")
    for drive in drives:
        scan_directory(drive, output_widget, settings)

# --- GUI Setup ---
def launch_app():
    root = tk.Tk()
    root.title("Malvinse by F(ox)Safety")
    root.geometry("800x550")
    root.resizable(False, False)

    settings = {
        "auto_scan": tk.BooleanVar(master=root, value=False),
        "show_hidden": tk.BooleanVar(master=root, value=False),
    }

    style = ttk.Style()
    style.configure("TNotebook.Tab", font=("Arial", 11, "bold"))

    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill="both")

    # --- Home Tab ---
    home_tab = ttk.Frame(notebook)
    notebook.add(home_tab, text="Home")

    tk.Label(home_tab, text="Welcome to Malvinse by F(ox)Safety", font=("Arial", 16)).pack(pady=20)
    tk.Label(home_tab, text="Version 1.1 • Real Cleaning • No pip required", font=("Arial", 10)).pack()

    # --- Scanner Tab ---
    scan_tab = ttk.Frame(notebook)
    notebook.add(scan_tab, text="Scanner")

    scan_output = tk.Text(scan_tab, wrap=tk.WORD, font=("Courier", 10))
    scan_output.pack(expand=True, fill="both", padx=10, pady=10)

    def choose_and_scan_folder():
        folder = filedialog.askdirectory()
        if folder:
            scan_output.delete("1.0", tk.END)
            scan_directory(folder, scan_output, settings)

    def choose_and_scan_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            scan_output.insert(tk.END, f"[INFO] Scanning file: {file_path}\n")
            result = scan_file(file_path)
            scan_output.insert(tk.END, result + "\n")
            scan_output.see(tk.END)

    tk.Button(scan_tab, text="Scan Folder", command=choose_and_scan_folder, font=("Arial", 12)).pack(pady=5)
    tk.Button(scan_tab, text="Scan Specific File", command=choose_and_scan_file, font=("Arial", 12)).pack(pady=5)

    # --- Quarantine Tab ---
    quarantine_tab = ttk.Frame(notebook)
    notebook.add(quarantine_tab, text="Quarantine")

    tk.Label(quarantine_tab, text="Quarantined Files:", font=("Arial", 12)).pack(pady=5)
    q_list = tk.Listbox(quarantine_tab, font=("Courier", 10))
    q_list.pack(expand=True, fill="both", padx=10, pady=10)

    def refresh_quarantine():
        q_list.delete(0, tk.END)
        for file in QUARANTINE_DIR.glob("*"):
            q_list.insert(tk.END, file.name)

    tk.Button(quarantine_tab, text="Refresh List", command=refresh_quarantine).pack(pady=5)

    # --- Settings Tab ---
    settings_tab = ttk.Frame(notebook)
    notebook.add(settings_tab, text="Settings")

    tk.Label(settings_tab, text="App Settings", font=("Arial", 14)).pack(pady=10)

    tk.Checkbutton(settings_tab, text="Auto Scan on Launch", variable=settings["auto_scan"]).pack(anchor="w", padx=20)
    tk.Checkbutton(settings_tab, text="Show Hidden Files", variable=settings["show_hidden"]).pack(anchor="w", padx=20)

    def clean_system():
        scan_output.delete("1.0", tk.END)
        scan_all_drives(scan_output, settings)

    tk.Button(settings_tab, text="Clean System", command=clean_system, font=("Arial", 12), bg="#d9534f", fg="white").pack(pady=20)

import requests

VIRUSTOTAL_API_KEY = "9714b22b1ccc56c2d0f86b443f6953f32a120fa7714803186df860c3442089e3"

def check_virustotal(file_path):
    file_hash = get_md5(file_path)
    if not file_hash:
        return "Error reading file"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        response = requests.get(url, headers=headers) # type: ignore
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            positives = stats.get("malicious", 0)
            if positives > 0:
                return f"[VT] Malware detected by {positives} engines"
            else:
                return "[VT] File is clean"
        elif response.status_code == 404:
            return "[VT] File not found in VirusTotal"
        else:
            return f"[VT] Error: {response.status_code}"
    except Exception as e:
        return f"[VT] API error: {e}"

import webbrowser

def open_privacy_policy(product_name):
    query = f"{product_name} privacy policy site:obsproject.com"
    search_url = f"https://www.google.com/search?q={query}"
    webbrowser.open(search_url)
    return f"[INFO] Searching privacy policy for: {product_name}"

    # --- Auto Scan if enabled ---
    if settings["auto_scan"].get():
        scan_all_drives(scan_output, settings)

    root.mainloop()

import os
import hashlib
import shutil
import time
import math
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# --- Config ---
MALWARE_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR test
    "5d41402abc4b2a76b9719d911017c592",  # Dummy
}

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".scr", ".cmd", ".js", ".vbs"}
QUARANTINE_DIR = Path.cwd() / "quarantine"
QUARANTINE_DIR.mkdir(exist_ok=True)

# --- Detection Logic ---
def get_md5(file_path):
    try:
        h = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def is_suspicious_file(file_path):
    ext = Path(file_path).suffix.lower()
    return ext in SUSPICIOUS_EXTENSIONS

def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        entropy = 0
        for count in byte_counts:
            if count == 0:
                continue
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy
    except Exception:
        return 0

def quarantine_file(file_path):
    base = os.path.basename(file_path)
    dest = QUARANTINE_DIR / f"{int(time.time())}_{base}"
    try:
        shutil.move(file_path, dest)
        return f"[ACTION] Quarantined: {dest}"
    except Exception as e:
        return f"[ERROR] Failed to quarantine: {e}"

def clean_file(file_path):
    ext = Path(file_path).suffix.lower()
    entropy = calculate_entropy(file_path)
    file_hash = get_md5(file_path)

    try:
        if file_hash in MALWARE_HASHES:
            os.remove(file_path)
            return f"[CLEANED] Known malware removed: {file_path}"

        if ext in {".bat", ".vbs", ".js"} and entropy > 7.5:
            os.remove(file_path)
            return f"[CLEANED] Suspicious script deleted: {file_path}"

        if ext in {".exe", ".dll"} and entropy > 7.8:
            os.remove(file_path)
            return f"[CLEANED] Packed binary removed: {file_path}"

        return f"[SKIPPED] File looks safe: {file_path}"
    except Exception:
        q = quarantine_file(file_path)
        return f"[FAILED DELETE] Quarantined instead: {file_path}\n{q}"

def scan_file(file_path):
    file_name = os.path.basename(file_path).lower()

    # Privacy policy lookup
    privacy_note = ""
    if "obs" in file_name:
        privacy_note = open_privacy_policy("OBS")

    # Local detection
    file_hash = get_md5(file_path)
    if not file_hash:
        return f"[ERROR] Could not read: {file_path}"

    result = ""
    if file_hash in MALWARE_HASHES:
        result += f"[ALERT] Known malware: {file_name}\n{clean_file(file_path)}"
    elif is_suspicious_file(file_path):
        entropy = calculate_entropy(file_path)
        if entropy > 7.5:
            result += f"[WARNING] Packed/Encrypted file: {file_name} (entropy={entropy:.2f})\n{clean_file(file_path)}"
        else:
            result += f"[NOTICE] Suspicious file: {file_name} (entropy={entropy:.2f})"
    else:
        result += f"[OK] File is clean: {file_name}"

    # VirusTotal check
    vt_result = check_virustotal(file_path)
    result += f"\n{vt_result}"

    # Privacy policy note
    if privacy_note:
        result += f"\n{privacy_note}"

    return result



# --- GUI Setup ---
def launch_app():
    root = tk.Tk()
    root.title("Malvinse by F(ox)Safety")
    root.geometry("800x550")
    root.resizable(True, True)

    settings = {
        "auto_scan": tk.BooleanVar(master=root, value=False),
        "show_hidden": tk.BooleanVar(master=root, value=False),
    }

    style = ttk.Style()
    style.configure("TNotebook.Tab", font=("Arial", 11, "bold"))

    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill="both")

    # --- Home Tab ---
    home_tab = ttk.Frame(notebook)
    notebook.add(home_tab, text="Home")

    tk.Label(home_tab, text="Welcome to Malvinse by F(ox)Safety", font=("Arial", 16)).pack(pady=20)
    tk.Label(home_tab, text="Version 1.1 • Real Cleaning • No pip required", font=("Arial", 10)).pack()

    # --- Scanner Tab ---
    scan_tab = ttk.Frame(notebook)
    notebook.add(scan_tab, text="Scanner")

    scan_output = tk.Text(scan_tab, wrap=tk.WORD, font=("Courier", 10))
    scan_output.pack(expand=True, fill="both", padx=10, pady=10)

    def choose_and_scan_folder():
        folder = filedialog.askdirectory()
        if folder:
            scan_output.delete("1.0", tk.END)
            scan_directory(folder, scan_output, settings)

    def choose_and_scan_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            scan_output.insert(tk.END, f"[INFO] Scanning file: {file_path}\n")
            result = scan_file(file_path)
            scan_output.insert(tk.END, result + "\n")
            scan_output.see(tk.END)

    tk.Button(scan_tab, text="Scan Folder", command=choose_and_scan_folder, font=("Arial", 12)).pack(pady=5)
    tk.Button(scan_tab, text="Scan Specific File", command=choose_and_scan_file, font=("Arial", 12)).pack(pady=5)

    # --- Quarantine Tab ---
    quarantine_tab = ttk.Frame(notebook)
    notebook.add(quarantine_tab, text="Quarantine")

    tk.Label(quarantine_tab, text="Quarantined Files:", font=("Arial", 12)).pack(pady=5)
    q_list = tk.Listbox(quarantine_tab, font=("Courier", 10))
    q_list.pack(expand=True, fill="both", padx=10, pady=10)

    def refresh_quarantine():
        q_list.delete(0, tk.END)
        for file in QUARANTINE_DIR.glob("*"):
            q_list.insert(tk.END, file.name)

    tk.Button(quarantine_tab, text="Refresh List", command=refresh_quarantine).pack(pady=5)

    # --- Settings Tab ---
    settings_tab = ttk.Frame(notebook)
    notebook.add(settings_tab, text="Settings")

    tk.Label(settings_tab, text="App Settings", font=("Arial", 14)).pack(pady=10)

    tk.Checkbutton(settings_tab, text="Auto Scan on Launch", variable=settings["auto_scan"]).pack(anchor="w", padx=20)
    tk.Checkbutton(settings_tab, text="Show Hidden Files", variable=settings["show_hidden"]).pack(anchor="w", padx=20)

    def clean_system():
        scan_output.delete("1.0", tk.END)
        scan_all_drives(scan_output, settings)

    tk.Button(settings_tab, text="Clean System", command=clean_system, font=("Arial", 12), bg="#d9534f", fg="white").pack(pady=20)

    # --- Auto Scan if enabled ---
    if settings["auto_scan"].get():
        scan_all_drives(scan_output, settings)

    root.mainloop()

if __name__ == "__main__":
    launch_app()