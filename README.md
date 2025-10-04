# 🛡️ Malvinse by F(ox)Safety

**Malvinse** is a hybrid malware scanner built for streamers, developers, and power users who demand real cleaning — not just quarantine. It combines offline detection (hash, entropy, extension) with online reputation checks via VirusTotal, and pulls privacy policies for scanned products. No pip installs. No fluff. Just results.

[![Uses Python](![Static Badge](https://img.shields.io/badge/Uses_Python-blue)](python.org)

---

## 🚀 Features

- ✅ **Real Cleaning Logic** — deletes known and suspicious files, not just flags them
- ✅ **Offline Detection** — hash matching, entropy analysis, extension checks
- ✅ **VirusTotal API Integration** — reputation checks when online
- ✅ **Privacy Transparency** — opens privacy policies for scanned apps (e.g. OBS, Discord)
- ✅ **Stream-Ready GUI** — built with Tkinter, no dependencies
- ✅ **Quarantine System** — safely moves failed deletes
- ✅ **Settings Tab** — toggle auto-scan, hidden file visibility
- ✅ **Modular Design** — easy to extend with new features

---

## 🖼️ GUI Preview

> Malwarebytes-style interface with tabs for Home, Scanner, Quarantine, and Settings.  
> Built with `tkinter` — no pip required.

---

## 📦 Installation

You can download it from our website ```https://fox-studio.github.io/F-ox-Safety/malvinse-download.html```

No pip installs required. Just run it.

🔍 How It Works
Scan Folder or File

Uses entropy, extension, and hash checks

Cleans or quarantines infected files

VirusTotal Check

Hash lookup via VT API

Shows how many engines flagged the file

Privacy Policy Lookup

Opens browser to product’s privacy page (e.g. OBS, Chrome)

🔐 VirusTotal Setup
To enable VT checks:

Get your free API key from VirusTotal

Paste it into the VIRUSTOTAL_API_KEY variable in malvinse.py

python
VIRUSTOTAL_API_KEY = "your-api-key-here"
🧪 Detection Logic
Known Malware: MD5 hash match

Suspicious Scripts: .bat, .js, .vbs with entropy > 7.5

Packed Binaries: .exe, .dll with entropy > 7.8

Fallback: Quarantine if delete fails

🧰 File Structure
Code
malvinse-by-foxsafety/
├── malvinse.py
├── quarantine/         # Auto-created folder for quarantined files
├── README.md
└── LICENSE             # MIT License
📜 License
This project is licensed under the MIT License. Feel free to use, modify, and share — just credit F(ox)Safety.

💬 Community
Join the conversation in the F(ox)Safety Discord Server. Share scans, request features, or just vibe with other security-minded creators.

⭐️ Give It a Star
If you find this useful, give it a ⭐️ on GitHub. It helps others discover it and shows support for open-source security tools.
