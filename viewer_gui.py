import tkinter as tk
from tkinter import ttk
import pymem
import pymem.process
import ctypes
import sys
import os
import struct

###############################################################################
# Configuration
###############################################################################
REFRESH_HZ = 5  # times per second
REFRESH_INTERVAL_MS = int(1000 / REFRESH_HZ)

TYPE_SIZES = {
    "int8": 1,
    "uint8": 1,
    "int16": 2,
    "uint16": 2,
    "int32": 4,
    "uint32": 4,
    "float": 4,
    "int64": 8,
    "uint64": 8,
    "double": 8,
    "pointer": 8,
    "string": 1,  # minimal
}


def compute_struct_offsets(fields):
    offset = 0
    results = []
    for fname, ftype in fields:
        t = ftype.lower().strip()
        size = (
            8 if t.startswith("pointer->") or t == "pointer" else TYPE_SIZES.get(t, 8)
        )
        results.append((fname, ftype, offset))
        offset += size
    return results

import json


def load_struct_definitions(json_file):
    with open(json_file, "r") as f:
        structs = json.load(f)

    converted = {}
    for struct_name, fields in structs.items():
        converted[struct_name] = []
        for var_name, var_type in fields.items():
            if isinstance(var_type, list):
                type_str = "->".join(var_type)  # Convert list to "->" notation
            else:
                type_str = var_type  # Keep as string if not a list
            converted[struct_name].append((var_name, type_str))

    return converted


STRUCT_DEFINITIONS = load_struct_definitions("structs.json")


def get_type_size_bytes(field_type: str) -> int:
    t = field_type.lower().strip()
    if t.startswith("pointer->") or t == "pointer":
        return 8
    return TYPE_SIZES.get(t, 8)


def decimal_and_masked_hex(value, field_type):
    if value is None:
        return "NULL"
    if field_type == "string":
        return f'"{value}"'
    size_bytes = get_type_size_bytes(field_type)
    mask = (1 << (size_bytes * 8)) - 1

    if field_type in ("float", "double"):
        if field_type == "float":
            packed = struct.pack("!f", value)
            bits = struct.unpack("!I", packed)[0] & mask
        else:
            packed = struct.pack("!d", value)
            bits = struct.unpack("!Q", packed)[0] & mask
        return f"{value} (0x{bits:X})"

    # integer
    return f"{value} (0x{(value & mask):X})"


###############################################################################
# Memory reading
###############################################################################
class GameMemoryViewer:
    def __init__(self, process_name):
        self.process_name = process_name
        self.pm = pymem.Pymem(process_name)
        mod = pymem.process.module_from_name(self.pm.process_handle, process_name)
        self.game_base = mod.lpBaseOfDll if mod else 0
        self.known_structs = {}  # { key: (baseAddr, structType, structName) }

    def add_struct(self, key_str, base_addr, struct_type, struct_name=""):
        self.known_structs[key_str] = (base_addr, struct_type, struct_name)

    def rename_struct(self, old_key, new_key, base_addr, struct_type, struct_name):
        """Remove old_key entry, add new_key."""
        if old_key in self.known_structs:
            del self.known_structs[old_key]
        self.known_structs[new_key] = (base_addr, struct_type, struct_name)

    def set_struct_type(self, key_str, new_type):
        if key_str in self.known_structs:
            base_addr, _oldType, sname = self.known_structs[key_str]
            self.known_structs[key_str] = (base_addr, new_type, sname)

    def set_struct_address(self, key_str, new_addr):
        if key_str in self.known_structs:
            _, stype, sname = self.known_structs[key_str]
            self.known_structs[key_str] = (new_addr, stype, sname)

    def set_struct_name(self, key_str, new_name):
        if key_str in self.known_structs:
            b, t, _old_name = self.known_structs[key_str]
            self.known_structs[key_str] = (b, t, new_name)

    def remove_struct(self, key_str):
        if key_str in self.known_structs:
            del self.known_structs[key_str]

    def close(self):
        self.pm.close_process()

    # Basic read
    def read_int8(self, addr):
        try:
            return self.pm.read_byte(addr, signed=True)
        except:
            return None

    def read_uint8(self, addr):
        try:
            return self.pm.read_byte(addr, signed=False)
        except:
            return None

    def read_int16(self, addr):
        try:
            return self.pm.read_short(addr)
        except:
            return None

    def read_uint16(self, addr):
        try:
            return self.pm.read_ushort(addr)
        except:
            return None

    def read_int32(self, addr):
        try:
            return self.pm.read_int(addr)
        except:
            return None

    def read_uint32(self, addr):
        try:
            return self.pm.read_uint(addr)
        except:
            return None

    def read_int64(self, addr):
        try:
            return self.pm.read_longlong(addr)
        except:
            return None

    def read_uint64(self, addr):
        try:
            return self.pm.read_ulonglong(addr)
        except:
            return None

    def read_pointer(self, addr):
        return self.read_uint64(addr)

    def read_string(self, addr, length=64):
        try:
            return self.pm.read_string(addr, length)
        except:
            return None

    def read_float(self, addr):
        try:
            return self.pm.read_float(addr)
        except:
            return None

    def read_double(self, addr):
        try:
            return self.pm.read_double(addr)
        except:
            return None

    def read_value(self, addr, field_type):
        t = field_type.lower().strip()
        if t.startswith("pointer->"):
            sub = t.split("->", 1)[1]
            pval = self.read_pointer(addr)
            if not pval:
                return None
            return self.read_value(pval, sub)
        elif t == "pointer":
            return self.read_pointer(addr)
        elif t == "int8":
            return self.read_int8(addr)
        elif t == "uint8":
            return self.read_uint8(addr)
        elif t == "int16":
            return self.read_int16(addr)
        elif t == "uint16":
            return self.read_uint16(addr)
        elif t == "int32":
            return self.read_int32(addr)
        elif t == "uint32":
            return self.read_uint32(addr)
        elif t == "int64":
            return self.read_int64(addr)
        elif t == "uint64":
            return self.read_uint64(addr)
        elif t == "float":
            return self.read_float(addr)
        elif t == "double":
            return self.read_double(addr)
        elif t == "string":
            return self.read_string(addr)
        return None

    def pointer_chain(self, addr, max_depth=5):
        chain = []
        current = addr
        for _ in range(max_depth):
            if current is None:
                break
            chain.append(current)
            nxt = self.read_pointer(current)
            if not nxt:
                break
            current = nxt
        return chain


###############################################################################
# StructWindow with auto-refresh, color-coded text, optional name
###############################################################################
class StructWindow:
    """
    Toplevel that shows (structType, baseAddr, structName).
    Allows:
      - pick a struct type (left),
      - edit the base address & optional name (top),
      - auto-refresh the field values at 5Hz,
      - color-coded text lines
    """

    def __init__(self, master, viewer, base_addr, key_str, on_close, rename_in_main_cb):
        self.master = master
        self.viewer = viewer
        self.key_str = key_str
        self.on_close = on_close
        self.rename_in_main_cb = rename_in_main_cb
        self.win = tk.Toplevel(master)
        self.win.geometry("800x500")
        self.win.protocol("WM_DELETE_WINDOW", self.close_window)

        # Retrieve from viewer
        ba, stype, sname = self.viewer.known_structs[key_str]
        self.base_addr = ba
        self.current_type = stype if stype else "NoType"
        self.struct_name = sname if sname else ""
        self.fields_with_offsets = compute_struct_offsets(
            STRUCT_DEFINITIONS.get(self.current_type, [])
        )

        # Setup Toplevel
        self.win.title(
            self.make_title(self.struct_name, self.current_type, self.base_addr)
        )

        # PanedWindow
        paned = ttk.Panedwindow(self.win, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left: struct definitions
        left_frame = ttk.Frame(paned, borderwidth=2, relief=tk.GROOVE)
        paned.add(left_frame, weight=0)

        ttk.Label(left_frame, text="Struct Definitions").pack(anchor=tk.NW)
        self.struct_list = tk.Listbox(left_frame, width=20, height=15)
        self.struct_list.pack(fill=tk.BOTH, expand=True)

        for k in STRUCT_DEFINITIONS.keys():
            self.struct_list.insert(tk.END, k)
        self.struct_list.bind("<<ListboxSelect>>", self.on_select_struct_type)

        # Right: top row for address + name, then text area
        right_frame = ttk.Frame(paned, borderwidth=2, relief=tk.GROOVE)
        paned.add(right_frame, weight=1)

        addr_frame = ttk.Frame(right_frame)
        addr_frame.pack(side=tk.TOP, fill=tk.X, pady=2)

        # Address
        ttk.Label(addr_frame, text="Address:").pack(side=tk.LEFT)
        self.addr_var = tk.StringVar(value=f"0x{self.base_addr:X}")
        ttk.Entry(addr_frame, textvariable=self.addr_var, width=20).pack(
            side=tk.LEFT, padx=5
        )

        # Optional name
        ttk.Label(addr_frame, text="Name:").pack(side=tk.LEFT)
        self.name_var = tk.StringVar(value=self.struct_name)
        ttk.Entry(addr_frame, textvariable=self.name_var, width=30).pack(
            side=tk.LEFT, padx=5
        )

        ttk.Button(addr_frame, text="Apply", command=self.on_apply_changes).pack(
            side=tk.RIGHT, padx=5
        )

        # Text area
        self.text = tk.Text(right_frame, width=60, height=15)
        self.text.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Define color tags
        self.text.tag_config("offset", foreground="red")
        self.text.tag_config("addr", foreground="darkgreen")
        self.text.tag_config("varname", foreground="blue")
        self.text.tag_config("value", foreground="darkorange")
        self.text.tag_config("header", foreground="gray", underline=True)

        self.refresh_scheduled = False
        self.schedule_refresh()

    def make_title(self, name, stype, addr):
        """e.g. "MyName (ExampleStructA) @ 0x12345" or "NoName (NoType) @ 0x0" """
        nm = name.strip()
        if nm:
            return f"{stype} ({nm}) @ 0x{addr:X}"
        else:
            return f"{stype} @ 0x{addr:X}"

    def close_window(self):
        self.cancel_refresh()
        self.viewer.remove_struct(self.key_str)
        self.on_close(self.key_str)
        self.win.destroy()

    def schedule_refresh(self):
        """Schedule next refresh after REFRESH_INTERVAL_MS."""
        if not self.refresh_scheduled:
            self.refresh_scheduled = True
            self.win.after(REFRESH_INTERVAL_MS, self.refresh)

    def cancel_refresh(self):
        self.refresh_scheduled = False

    def refresh(self):
        if not self.refresh_scheduled:
            return
        self.refresh_scheduled = False  # so we can schedule again

        self.draw_struct_contents()
        # schedule next
        if self.win.winfo_exists():
            self.schedule_refresh()

    def draw_struct_contents(self):
        self.text.delete("1.0", tk.END)

        # 1) Print a header row
        # "Address: 0x... | Struct Type: X | Struct Name: Y"
        hdr_line = f"Address: 0x{self.base_addr:X} | Struct Type: {self.current_type}"
        if self.struct_name:
            hdr_line += f" | Struct Name: {self.struct_name}"
        self.insert_colored(hdr_line + "\n", "header")

        if self.current_type == "NoType":
            self.insert_colored("No struct type selected.\n", "value")
            return

        self.insert_colored("\n", None)  # blank line

        for fname, ftype, offset in self.fields_with_offsets:
            # Build partial line
            # [offset] address offset
            # e.g. "[0000 | 0x7FFFAAABBBCC]" " name: " "value"
            line_offset = f"[{offset:04X} | "
            addr_plus_off = f"0x{(self.base_addr + offset):X}] "
            var_part = f"{fname}: "
            val_str = self.format_value(self.base_addr + offset, ftype)

            # Insert partial with color tags
            self.insert_colored(line_offset, "offset")
            self.insert_colored(addr_plus_off, "addr")
            self.insert_colored(var_part, "varname")
            self.insert_colored(val_str + "\n", "value")

    def insert_colored(self, text_str, tag):
        """Insert text into self.text with optional color tag."""
        if tag:
            self.text.insert(tk.END, text_str, tag)
        else:
            self.text.insert(tk.END, text_str)

    def on_select_struct_type(self, event):
        sel = self.struct_list.curselection()
        if not sel:
            return
        new_type = self.struct_list.get(sel[0])
        self.set_struct_type(new_type)

    def on_apply_changes(self):
        """User pressed 'Apply' after editing address/name."""
        new_addr = self.parse_address(self.addr_var.get().strip())
        new_name = self.name_var.get().strip()

        if new_addr is not None:
            self.base_addr = new_addr
            self.viewer.set_struct_address(self.key_str, new_addr)

        self.struct_name = new_name
        self.viewer.set_struct_name(self.key_str, new_name)

        # rename key in main
        # get current type
        ba, st, sn = self.viewer.known_structs[self.key_str]
        new_key = self.make_title(sn, st, ba)  # e.g. "MyName (StructType) @ 0xBASE"
        self.rename_in_main_cb(self.key_str, new_key, ba, st, sn)
        self.key_str = new_key

        # also update window title
        self.win.title(new_key)
        # immediate refresh
        self.draw_struct_contents()

    def parse_address(self, addr_str):
        proc_name = self.viewer.process_name
        prefix = proc_name + "+"
        if addr_str.lower().startswith(prefix.lower()):
            offset_str = addr_str[len(prefix) :]
            try:
                offset_val = int(offset_str, 16)
                return self.viewer.game_base + offset_val
            except:
                return None
        try:
            return int(addr_str, 16)
        except:
            return None

    def set_struct_type(self, new_type):
        self.current_type = new_type
        self.fields_with_offsets = compute_struct_offsets(
            STRUCT_DEFINITIONS.get(new_type, [])
        )
        self.viewer.set_struct_type(self.key_str, new_type)

        # rename key in main
        ba, _old, sname = self.viewer.known_structs[self.key_str]
        new_key = self.make_title(sname, new_type, ba)
        self.rename_in_main_cb(self.key_str, new_key, ba, new_type, sname)
        self.key_str = new_key
        self.win.title(new_key)

        self.draw_struct_contents()

    def format_value(self, addr, ftype):
        if ftype == "pointer":
            chain = self.viewer.pointer_chain(addr, max_depth=5)
            if not chain:
                return "NULL"
            parts = [f"0x{x:X}" for x in chain]
            return " -> ".join(parts)
        if ftype.lower().startswith("pointer->"):
            ptr_val = self.viewer.read_pointer(addr)
            if not ptr_val:
                return "(NULL pointer)"
            sub_type = ftype.split("->", 1)[1]
            ptr_hex = f"0x{ptr_val:X}"
            sub_val = self.viewer.read_value(ptr_val, sub_type)
            return f"{ptr_hex} -> {decimal_and_masked_hex(sub_val, sub_type)}"
        val = self.viewer.read_value(addr, ftype)
        return decimal_and_masked_hex(val, ftype)


###############################################################################
# Main GUI
###############################################################################
class MemoryViewerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Viewer - Multiple Windows")

        self.viewer = None
        self.open_windows = {}

        # Process row
        proc_frame = ttk.Frame(root)
        proc_frame.pack(side=tk.TOP, fill=tk.X, pady=2)

        ttk.Label(proc_frame, text="Process Name:").pack(side=tk.LEFT)
        self.process_name_var = tk.StringVar(value="MK11.exe")
        ttk.Entry(proc_frame, textvariable=self.process_name_var, width=15).pack(
            side=tk.LEFT, padx=5
        )

        ttk.Button(proc_frame, text="Connect", command=self.connect_to_process).pack(
            side=tk.LEFT, padx=5
        )

        ttk.Label(proc_frame, text="Game Base:").pack(side=tk.LEFT, padx=10)
        self.game_base_var = tk.StringVar(value="N/A")
        ttk.Entry(
            proc_frame, textvariable=self.game_base_var, width=20, state="readonly"
        ).pack(side=tk.LEFT)

        self.admin_button = ttk.Button(
            proc_frame, text="Request Admin", command=self.request_admin
        )
        self.admin_button.pack(side=tk.RIGHT, padx=5)

        # Base address row
        addr_frame = ttk.Frame(root)
        addr_frame.pack(side=tk.TOP, fill=tk.X, pady=2)

        ttk.Label(addr_frame, text="Base Address:").pack(side=tk.LEFT)
        self.struct_addr_var = tk.StringVar()
        ttk.Entry(addr_frame, textvariable=self.struct_addr_var, width=20).pack(
            side=tk.LEFT, padx=5
        )

        ttk.Button(
            addr_frame, text="Add Struct Window", command=self.add_struct_window
        ).pack(side=tk.LEFT, padx=5)

        # Active windows
        bottom_frame = ttk.Frame(root)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, pady=2)

        ttk.Label(bottom_frame, text="Active Windows").pack(anchor=tk.NW)
        self.active_list = tk.Listbox(bottom_frame, height=10)
        self.active_list.pack(fill=tk.BOTH, expand=True)

    def request_admin(self):
        path = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{a}"' for a in sys.argv[1:]])
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{path}" {params}', None, 1
        )
        if rc <= 32:
            print("Failed to elevate privileges.")
        else:
            self.root.destroy()

    def connect_to_process(self):
        pname = self.process_name_var.get().strip()
        if not pname:
            return
        try:
            if self.viewer:
                self.viewer.close()
            self.viewer = GameMemoryViewer(pname)
            base_str = (
                f"0x{self.viewer.game_base:08X}" if self.viewer.game_base else "N/A"
            )
            self.game_base_var.set(base_str)
        except Exception as e:
            self.game_base_var.set("Error")
            print(f"Failed to attach: {e}")

    def parse_address(self, addr_str):
        if not self.viewer:
            return None
        prefix = self.process_name_var.get().strip() + "+"
        addr_str = addr_str.strip()
        if addr_str.lower().startswith(prefix.lower()):
            offset_str = addr_str[len(prefix) :]
            try:
                offset_val = int(offset_str, 16)
                return self.viewer.game_base + offset_val
            except:
                return None
        try:
            return int(addr_str, 16)
        except:
            return None

    def add_struct_window(self):
        if not self.viewer:
            return
        base_str = self.struct_addr_var.get().strip()
        if not base_str:
            return
        base_addr = self.parse_address(base_str)
        if base_addr is None:
            return

        key_str = f"NoType @ 0x{base_addr:X}"
        # store with empty struct name
        self.viewer.add_struct(key_str, base_addr, "NoType", "")

        w = StructWindow(
            master=self.root,
            viewer=self.viewer,
            base_addr=base_addr,
            key_str=key_str,
            on_close=self.on_child_close,
            rename_in_main_cb=self.rename_window_in_main,
        )
        self.open_windows[key_str] = w
        self.active_list.insert(tk.END, key_str)

    def on_child_close(self, key_str):
        if key_str in self.open_windows:
            del self.open_windows[key_str]
        for i, item in enumerate(self.active_list.get(0, tk.END)):
            if item == key_str:
                self.active_list.delete(i)
                break

    def rename_window_in_main(self, old_key, new_key, new_addr, new_type, new_name):
        if old_key not in self.open_windows:
            return
        self.viewer.rename_struct(old_key, new_key, new_addr, new_type, new_name)
        self.open_windows[new_key] = self.open_windows.pop(old_key)
        self.open_windows[new_key].key_str = new_key

        items = list(self.active_list.get(0, tk.END))
        idx = None
        for i, it in enumerate(items):
            if it == old_key:
                idx = i
                break
        if idx is not None:
            self.active_list.delete(idx)
            self.active_list.insert(idx, new_key)


if __name__ == "__main__":
    root = tk.Tk()
    app = MemoryViewerGUI(root)
    root.mainloop()

    if app.viewer:
        app.viewer.close()
