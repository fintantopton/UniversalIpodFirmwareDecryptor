"""Patch: Route ALL Category 2 devices through native Windows path."""
content = open(r'c:\KIRO\iPodUniversalDecrypt\ipod_universal_decrypt_b.py', encoding='utf-8').read()

# 1. Dispatch - already patched from previous run, check both
old1a = '                if self._is_nano45g():\n                    self._decrypt_category2_native()\n                else:\n                    self._decrypt_category2()'
old1b = '                # All Category 2 use native Windows path (no WSL needed)\n                self._decrypt_category2_native()'

if old1a in content:
    content = content.replace(old1a, '# All Category 2 use native Windows path (no WSL needed)\n                self._decrypt_category2_native()', 1)
    print("Dispatch: OK (was nano45g conditional)")
elif old1b in content:
    print("Dispatch: Already done")
else:
    print("Dispatch: NOT FOUND"); exit(1)

# 2. Driver frame
old2 = '            if self._is_nano45g():\n                self.driver_frame.pack(fill="x", pady=(5, 0))\n            else:\n                self.driver_frame.pack_forget()'
if old2 in content:
    content = content.replace(old2, 'self.driver_frame.pack(fill="x", pady=(5, 0))', 1)
    print("Driver frame: OK")
else:
    # Maybe already patched
    if 'self.driver_frame.pack(fill="x", pady=(5, 0))' in content:
        print("Driver frame: Already done")
    else:
        print("Driver frame: NOT FOUND"); exit(1)

# 3. Label update
old3 = 'Nano 4G/5G: WinUSB driver required for native Windows decrypt'
new3 = 'WinUSB driver required (one-time setup via Zadig)'
if old3 in content:
    content = content.replace(old3, new3, 1)
    print("Label: OK")
elif new3 in content:
    print("Label: Already done")
else:
    print("Label: NOT FOUND"); exit(1)

# 4. Method log
old4 = 'Category 2 - Native Windows'
new4 = 'Category 2 - Hardware AES, Native'
if old4 in content:
    content = content.replace(old4, new4, 1)
    print("Method log: OK")
elif new4 in content:
    print("Method log: Already done")
else:
    print("Method log: NOT FOUND"); exit(1)

# 5. Prereq UI - replace WSL labels with native labels
# Find the actual emoji in the file
if 'self.wsl_label' in content and 'self.usbipd_label' in content:
    # Remove wsl_label and usbipd_label, keep wind3x_label, add driver_status_label
    # Find the section
    import re
    pattern = r'        self\.wsl_label = ttk\.Label\(self\.prereq_frame.*?\n        self\.wsl_label\.pack\(anchor="w"\)\n        self\.usbipd_label = ttk\.Label\(self\.prereq_frame.*?\n        self\.usbipd_label\.pack\(anchor="w"\)\n        self\.wind3x_label = ttk\.Label\(self\.prereq_frame.*?\n        self\.wind3x_label\.pack\(anchor="w"\)'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        replacement = '''        self.wind3x_label = ttk.Label(self.prereq_frame, text="\u23f3 wInd3x (native): Not checked")
        self.wind3x_label.pack(anchor="w")
        self.driver_status_label = ttk.Label(self.prereq_frame, text="\u23f3 WinUSB driver: Not checked")
        self.driver_status_label.pack(anchor="w")'''
        content = content[:match.start()] + replacement + content[match.end():]
        print("Prereq UI: OK")
    else:
        print("Prereq UI: regex failed"); exit(1)
elif 'driver_status_label' in content:
    print("Prereq UI: Already done")
else:
    print("Prereq UI: NOT FOUND"); exit(1)

# 6. Replace _check_prerequisites method
old6 = '    def _check_prerequisites(self):\n        """Check WSL'
idx = content.find(old6)
if idx == -1:
    old6 = '    def _check_prerequisites(self):\n        """Check native'
    idx = content.find(old6)
    if idx >= 0:
        print("Prerequisites: Already native")
    else:
        print("Prerequisites: NOT FOUND"); exit(1)
else:
    end_marker = '\n    def _browse_ipsw(self):'
    end_idx = content.find(end_marker, idx)
    if end_idx > idx:
        new_prereq = '''    def _check_prerequisites(self):
        """Check native Windows prerequisites (wInd3x-win.exe + WinUSB driver)"""
        def check():
            wind3x = get_bundled_path(WIND3X_WIN_NAME)
            if wind3x:
                self.wind3x_label.config(text="\u2705 wInd3x (native): Ready")
                self.wind3x_ready = True
            else:
                self.wind3x_label.config(text="\u274c wInd3x-win.exe: Not found")
                return
            pid = None
            if self.detected_family_id in IPOD_MODELS:
                _, _, _, pid = IPOD_MODELS[self.detected_family_id]
            if pid and check_winusb_installed(pid):
                self.driver_status_label.config(text=f"\u2705 WinUSB: Installed (PID {pid})")
            else:
                self.driver_status_label.config(
                    text=f"\u26a0\ufe0f WinUSB: Not detected \u2014 click Install below")
        threading.Thread(target=check, daemon=True).start()

'''
        content = content[:idx] + new_prereq + content[end_idx:]
        print("Prerequisites: OK")
    else:
        print("Prerequisites: end not found"); exit(1)

open(r'c:\KIRO\iPodUniversalDecrypt\ipod_universal_decrypt_b.py', 'w', encoding='utf-8').write(content)
print("\nDone. ALL Category 2 now uses native Windows. No WSL dependency.")
