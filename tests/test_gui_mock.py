import sys, types, time, unittest
from unittest.mock import MagicMock

import os
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
sys.path.insert(0, _HERE)

def make_stub(name):
    m = types.ModuleType(name)
    return m

tk = make_stub("tkinter")
class _TclError(Exception): pass
tk.TclError = _TclError
for n in ("Canvas","Text","StringVar","BooleanVar","Tk"):
    setattr(tk, n, MagicMock())
sys.modules["tkinter"] = tk
ttk = make_stub("tkinter.ttk")
for n in ("Frame","LabelFrame","Label","Button","Entry","Checkbutton",
          "Progressbar","Scrollbar","Canvas"):
    setattr(ttk, n, MagicMock())
tk.ttk = ttk
sys.modules["tkinter.ttk"] = ttk
mb = make_stub("tkinter.messagebox"); sys.modules["tkinter.messagebox"] = mb
fdm = make_stub("tkinter.filedialog"); sys.modules["tkinter.filedialog"] = fdm

import ipod_universal_decrypt_b as app
import make_fixtures as fx
import os, tempfile


def _run_gui_smoke():

    def patch_widget_mocks(a):
        """Give common Tk queries sane mock values (real Tk returns these types)."""
        for w in (a.partition_checks_frame, a.nano2g_device_info_label,
                  a.silverimagesdb_row, a.silverimagesdb_checkbutton):
            w.winfo_children.return_value = []
            w.winfo_ismapped.return_value = False
        a.root.winfo_screenheight.return_value = 1080
        a.main_frame.winfo_reqwidth.return_value = 800
        a.main_frame.winfo_reqheight.return_value = 500
        a.btn_frame.winfo_reqheight.return_value = 40
        a.content_scrollbar.winfo_reqwidth.return_value = 16

    a = app.UniversalDecryptorApp(tk, ttk, mb, fdm)
    patch_widget_mocks(a)
    print("GUI constructed OK")

    tmp = tempfile.mkdtemp()
    fw = fx.build_mse_firmware(nano3=True)
    ipsw = os.path.join(tmp, "iPod_26.1.1.3.ipsw")
    fx.make_ipsw(ipsw, fw)
    out_dir = os.path.join(tmp, "out")

    a.ipsw_var = MagicMock(); a.ipsw_var.get.return_value = ipsw
    a.ipsw_var.trace_add = lambda *a, **k: None
    a.output_var = MagicMock(); a.output_var.get.return_value = out_dir
    a.output_var.set = MagicMock()

    a._on_ipsw_changed()
    print("model detection OK ->", a.detected_model, "cat", a.detected_category)

    deadline = time.time() + 5
    while time.time() < deadline and not a.category2_members:
        a._pump(); time.sleep(0.02)
    assert a.category2_members, "members never arrived"
    print("members OK ->", sorted(a.category2_members))
    assert "osos" in a.partition_selected and "rsrc" in a.partition_selected

    a._start_decrypt()
    deadline = time.time() + 10
    while time.time() < deadline and a.is_running:
        a._pump(); time.sleep(0.02)
    assert not a.is_running
    print("decrypt flow finished")
    dialogs = []
    while True:
        try:
            kind, args = a._ui_queue.get_nowait()
            if kind == "dialog":
                dialogs.append(args)
        except Exception:
            break
    for d in dialogs:
        print("dialog:", d[0], "-", d[1])
    assert any(d[0] == "error" for d in dialogs), "expected wInd3x-missing error"

    p = os.path.join(out_dir, "rsrc.bin")
    assert os.path.isfile(p), f"missing {p}"
    print("raw export present: rsrc.bin")
    assert not os.path.isfile(os.path.join(out_dir, "osos.bin"))
    print("osos correctly not produced (no wInd3x in sandbox)")

    a.detected_family_id = 19
    a.detected_category = 4
    a.model_state()
    print("cat4 model_state OK")
    a._scan_device()
    deadline = time.time() + 3
    while time.time() < deadline:
        a._pump(); time.sleep(0.05)
    print("scan thread OK")

    a2 = app.UniversalDecryptorApp(tk, ttk, mb, fdm)
    patch_widget_mocks(a2)
    p1 = os.path.join(tmp, "iPod_13.1.2_4E9.ipsw")
    fx.make_ipsw(p1, fx.build_cat1_firmware(b"CAT1BODY" * 1024))
    a2.ipsw_var = MagicMock(); a2.ipsw_var.get.return_value = p1
    a2.ipsw_var.trace_add = lambda *a, **k: None
    a2.output_var = MagicMock(); a2.output_var.get.return_value = os.path.join(tmp, "cat1.bin")
    a2.output_var.set = MagicMock()
    a2._on_ipsw_changed()
    print("cat1 detection OK ->", a2.detected_model, a2.detected_category)
    a2._start_decrypt()
    deadline = time.time() + 10
    while time.time() < deadline and a2.is_running:
        a2._pump(); time.sleep(0.02)
    assert not a2.is_running
    data = open(os.path.join(tmp, "cat1.bin"), "rb").read()
    assert data == b"CAT1BODY" * 1024
    print("cat1 GUI flow OK, output verified")
    print("\nALL GUI SMOKE TESTS PASSED")


class TestGuiMocked(unittest.TestCase):
    def test_gui_flow_with_stubbed_tkinter(self):
        _run_gui_smoke()


if __name__ == "__main__":
    unittest.main(verbosity=2)
