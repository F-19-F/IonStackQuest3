https://files.cocaine.trade/firmware/meta/Quest%203/q3_52345320035400520.zip
"""
IonStack Kernel Config Generator
=================================
Parses an ARM64 kernel ELF (vmlinux) and generates an ionstack.conf
with symbol offsets relative to kimage_text_base (_text).

Usage:
    python gen_ionstack_config.py kernel.elf [output.conf]
    python gen_ionstack_config.py kernel.elf --json           # JSON output
    python gen_ionstack_config.py kernel.elf --check          # validate vs built-in

Requirements:
    pip install pyelftools

The script handles kernels with and without CFI (Control Flow Integrity).
For CFI-enabled kernels, function pointer targets use .cfi_jt entries.
For non-CFI kernels, the actual function address is used.
"""

import sys
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile


# ============================================================
# Symbol resolution rules for each config key.
# Each rule has:
#   key       : config key name
#   symbols   : ordered list of symbol names to try (first match wins)
#   cfi_first : if True, prefer <symbol>.cfi_jt over <symbol> for function targets
#   compound  : (base_symbol, offset_adjustment) for struct-field targets
# ============================================================

RESOLVE_RULES = [
    # ---- base ----
    {
        "key": "kimage_text_base",
        "symbols": ["_text"],
        "cfi_first": False,
        "absolute": True,   # output the absolute address, not offset
    },
    # ---- file_operations / fops structs (DATA) ----
    {
        "key": "random_misc_fops_off",
        "symbols": ["random_fops"],       # value inside miscdevice->fops field
        "cfi_first": False,
        "indirect": "random_fops",         # look up the pointer stored here
        "fallback_method": "pointer_to",
    },
    {
        "key": "ashmem_misc_fops_off",
        "symbols": ["ashmem_misc"],
        "cfi_first": False,
        "compound_offset": 0x10,           # fops field inside struct miscdevice
    },
    {
        "key": "ashmem_fops_off",
        "symbols": ["ashmem_fops"],
        "cfi_first": False,
    },
    # ---- function pointers (CFI-aware) ----
    {
        "key": "ashmem_ioctl_off",
        "symbols": ["ashmem_ioctl"],
        "cfi_first": True,
    },
    {
        "key": "ashmem_compat_ioctl_off",
        "symbols": ["compat_ashmem_ioctl"],
        "cfi_first": True,
    },
    {
        "key": "ashmem_mmap_off",
        "symbols": ["ashmem_mmap"],
        "cfi_first": True,
    },
    {
        "key": "ashmem_open_off",
        "symbols": ["ashmem_open"],
        "cfi_first": True,
    },
    {
        "key": "ashmem_release_off",
        "symbols": ["ashmem_release"],
        "cfi_first": True,
    },
    {
        "key": "ashmem_show_fdinfo_off",
        "symbols": ["ashmem_show_fdinfo"],
        "cfi_first": True,
    },
    {
        "key": "ashmem_read_iter_off",
        "symbols": ["ashmem_read_iter"],
        "cfi_first": True,
    },
    {
        "key": "configfs_read_file_off",
        "symbols": ["configfs_read_file"],
        "cfi_first": True,
    },
    {
        "key": "configfs_write_bin_file_off",
        "symbols": ["configfs_write_bin_file"],
        "cfi_first": True,
    },
    {
        "key": "copy_splice_read_off",
        "symbols": ["copy_splice_read", "generic_file_splice_read"],
        "cfi_first": True,
    },
    {
        "key": "noop_llseek_off",
        "symbols": ["noop_llseek"],
        "cfi_first": True,
    },
    # ---- kernel globals ----
    {
        "key": "init_task_off",
        "symbols": ["init_task"],
        "cfi_first": False,
    },
    {
        "key": "init_uts_ns_off",
        "symbols": ["init_uts_ns"],
        "cfi_first": False,
    },
    {
        "key": "empty_zero_page_off",
        "symbols": ["empty_zero_page"],
        "cfi_first": False,
    },
    {
        "key": "root_task_group_off",
        "symbols": ["root_task_group"],
        "cfi_first": False,
    },
    {
        "key": "selinux_blob_sizes_off",
        "symbols": ["selinux_blob_sizes"],
        "cfi_first": False,
    },
    {
        "key": "selinux_enforcing_off",
        "symbols": ["selinux_state"],      # CONFIG key says "enforcing" but symbol is selinux_state
        "cfi_first": False,
    },
    {
        "key": "security_hook_heads_off",
        "symbols": ["security_hook_heads"],
        "cfi_first": False,
    },
    {
        "key": "kmalloc_caches_off",
        "symbols": ["kmalloc_caches"],
        "cfi_first": False,
    },
    {
        "key": "anon_pipe_buf_ops_off",
        "symbols": ["anon_pipe_buf_ops"],
        "cfi_first": False,
    },
    # ---- slide (infoleak) variables ----
    {
        "key": "slide_random_boot_id_data_off",
        "symbols": ["random_table"],
        "cfi_first": False,
        "compound_offset": 0x108,           # boot_id data within random_table
    },
    {
        "key": "slide_sysctl_bootid_off",
        "symbols": ["sysctl_bootid"],
        "cfi_first": False,
    },
    {
        "key": "slide_loggers_0_1_off",
        "symbols": ["loggers"],
        "cfi_first": False,
        "compound_offset": 0x8,             # loggers[1]
    },
    {
        "key": "slide_nfulnl_logger_off",
        "symbols": ["nfulnl_logger"],
        "cfi_first": False,
    },
]


class SymbolResolver:
    """Resolve symbols from an ARM64 kernel ELF."""

    def __init__(self, elf_path: str):
        self.elf_path = elf_path
        self.elf = None
        self.symtab = None
        self._sym_cache = {}        # name -> address (or None)
        self._cfi_available = None
        self.kimage_text_base = None

    def open(self):
        self.elf = ELFFile(open(self.elf_path, 'rb'))
        self.symtab = self.elf.get_section_by_name('.symtab')
        if not self.symtab:
            # Try .dynsym as fallback
            self.symtab = self.elf.get_section_by_name('.dynsym')
            if not self.symtab:
                raise ValueError(f"No symbol table found in {self.elf_path}")
        self._build_cache()
        self._detect_cfi()
        self._find_base()
        return self

    def _build_cache(self):
        """Pre-load all symbols into a cache for fast lookup."""
        for sym in self.symtab.iter_symbols():
            name = sym.name
            addr = sym['st_value']
            if addr == 0:
                continue
            # Keep the first occurrence (usually the defining one)
            if name not in self._sym_cache:
                self._sym_cache[name] = addr

    def _detect_cfi(self):
        """Detect if the kernel has CFI enabled by looking for .cfi_jt symbols."""
        cfi_count = sum(1 for name in self._sym_cache if name.endswith('.cfi_jt'))
        self._cfi_available = cfi_count > 10
        print(f"[*] CFI detected: {self._cfi_available} ({cfi_count} .cfi_jt entries found)")

    def _find_base(self):
        """Find kimage_text_base from _text symbol."""
        addr = self._sym_cache.get('_text')
        if addr is None:
            # Try alternatives
            for alt in ['_stext', 'stext', '__entry_text_start']:
                addr = self._sym_cache.get(alt)
                if addr:
                    break
        if addr is None:
            raise ValueError("Cannot find _text symbol for kimage_text_base")
        self.kimage_text_base = addr
        print(f"[*] kimage_text_base (_text) = 0x{addr:016x}")

    def lookup(self, name: str) -> int:
        """Look up a symbol by name. Returns address or None."""
        return self._sym_cache.get(name)

    def resolve_cfi(self, func_name: str) -> int:
        """
        For a function symbol, resolve to the appropriate target:
        - If CFI is available, return <func>.cfi_jt address
        - Otherwise, return the function address itself
        """
        if self._cfi_available:
            cfi_name = f"{func_name}.cfi_jt"
            addr = self._sym_cache.get(cfi_name)
            if addr:
                return addr
            # Some CFI entries have different naming; try without dot
            cfi_name = f"{func_name}.cfi"
            addr = self._sym_cache.get(cfi_name)
            if addr:
                return addr
        # Fallback: function address itself
        return self._sym_cache.get(func_name)


def resolve_all(elf_path: str):
    """Resolve all config entries for a kernel ELF."""
    resolver = SymbolResolver(elf_path).open()
    base = resolver.kimage_text_base

    results = {}
    warnings = []
    errors = []

    for rule in RESOLVE_RULES:
        key = rule["key"]
        addr = None
        method = None

        # ---- Special: kimage_text_base ----
        if rule.get("absolute"):
            addr = base
            method = "_text (absolute base)"

        # ---- Special: random_misc_fops_off (pointer indirection) ----
        elif rule.get("fallback_method") == "pointer_to":
            target_name = rule.get("indirect")
            if target_name:
                # Find the field within miscdevice struct that points to <target_name>
                # This is the address of the pointer itself, not the target
                addr = _find_pointer_to(resolver, target_name)
                method = f"pointer to {target_name}"
            if addr is None:
                # Fallback: try the first symbol directly
                for sym_name in rule["symbols"]:
                    addr = resolver.lookup(sym_name)
                    if addr:
                        method = f"direct symbol {sym_name} (pointer-to fallback)"
                        warnings.append(f"{key}: using direct symbol {sym_name} as fallback; "
                                        f"pointer-to resolution failed")
                        break

        # ---- Compound offset (struct field) ----
        elif rule.get("compound_offset"):
            for sym_name in rule["symbols"]:
                base_addr = resolver.lookup(sym_name)
                if base_addr:
                    addr = base_addr + rule["compound_offset"]
                    method = f"{sym_name} + 0x{rule['compound_offset']:x}"
                    break

        # ---- CFI-aware function pointer ----
        elif rule.get("cfi_first"):
            for sym_name in rule["symbols"]:
                addr = resolver.resolve_cfi(sym_name)
                if addr:
                    method = (f"{sym_name}.cfi_jt (CFI)" if resolver._cfi_available
                              else f"{sym_name} (no-CFI)")
                    break

        # ---- Direct symbol lookup ----
        else:
            for sym_name in rule["symbols"]:
                addr = resolver.lookup(sym_name)
                if addr:
                    method = sym_name
                    break

        if addr is None:
            tried = ", ".join(rule["symbols"])
            if rule.get("cfi_first"):
                tried += " [.cfi_jt variants also tried]"
            errors.append(f"{key}: no symbol found (tried: {tried})")
            continue

        offset = addr - base
        results[key] = {
            "addr": addr,
            "offset": offset,
            "method": method,
        }

    return results, warnings, errors


def _find_pointer_to(resolver: SymbolResolver, target_name: str) -> int:
    """
    Find a data field that contains a pointer to `target_name`.
    Scans data sections for a qword that equals the address of the target symbol.
    Returns the address of the pointer field itself.
    """
    target_addr = resolver.lookup(target_name)
    if target_addr is None:
        return None

    target_bytes = struct.pack('<Q', target_addr)

    elf = resolver.elf
    for section in elf.iter_sections():
        # Only scan writable data sections (not code, not read-only if avoidable)
        name = section.name
        if not name.startswith('.data') and name not in ('.bss', '.rodata', '.kernel'):
            continue

        data = section.data()
        if not data:
            continue

        sh_addr = section['sh_addr']
        if sh_addr == 0:
            continue

        # Search for the pointer value
        pos = 0
        while True:
            idx = data.find(target_bytes, pos)
            if idx == -1:
                break
            addr = sh_addr + idx
            # Verify it's not in the middle of code or a string
            if resolver.lookup(target_name) is None or addr != target_addr:
                # It's a reference to our target
                return addr
            pos = idx + 8

    return None


def generate_config(results: dict, output_path: str = None):
    """Generate ionstack.conf from resolved symbols."""
    lines = []
    lines.append("# IonStack kernel symbol overrides")
    lines.append("#")
    lines.append(f"# Auto-generated from: {Path(sys.argv[1]).name if len(sys.argv) > 1 else 'kernel.elf'}")
    lines.append("# Push to /data/local/tmp/ionstack.conf (or set $IONSTACK_CONFIG)")
    lines.append("#")
    lines.append("# kimage_text_base is the absolute link-time base; every other key is")
    lines.append("# an offset relative to it, so overriding only kimage_text_base shifts")
    lines.append("# all symbols at once.")
    lines.append("")

    # First output the base
    if "kimage_text_base" in results:
        r = results["kimage_text_base"]
        lines.append(f"kimage_text_base            = 0x{r['addr']:016x}")
        lines.append("")

    # Group output by category
    groups = [
        ("# file_operations / function pointers",
         ["random_misc_fops_off", "ashmem_misc_fops_off", "ashmem_fops_off",
          "ashmem_ioctl_off", "ashmem_compat_ioctl_off", "ashmem_mmap_off",
          "ashmem_open_off", "ashmem_release_off", "ashmem_show_fdinfo_off",
          "ashmem_read_iter_off", "configfs_read_file_off",
          "configfs_write_bin_file_off", "copy_splice_read_off",
          "noop_llseek_off"]),
        ("# kernel variables",
         ["init_task_off", "init_uts_ns_off", "empty_zero_page_off",
          "root_task_group_off", "selinux_blob_sizes_off",
          "selinux_enforcing_off", "security_hook_heads_off",
          "kmalloc_caches_off", "anon_pipe_buf_ops_off"]),
        ("# slide (boot_id infoleak) variables",
         ["slide_random_boot_id_data_off", "slide_sysctl_bootid_off",
          "slide_loggers_0_1_off", "slide_nfulnl_logger_off"]),
    ]

    for comment, keys in groups:
        lines.append(comment)
        for key in keys:
            r = results.get(key)
            if r:
                offset_str = f"0x{r['offset']:08x}"
                lines.append(f"{key:30s}= {offset_str}")
        lines.append("")

    output = "\n".join(lines)

    if output_path:
        with open(output_path, 'w') as f:
            f.write(output)
        print(f"[*] Config written to: {output_path}")

    return output


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    elf_path = sys.argv[1]
    if not Path(elf_path).exists():
        print(f"Error: {elf_path} not found")
        sys.exit(1)

    print(f"[*] Parsing: {elf_path}")
    results, warnings, errors = resolve_all(elf_path)

    # Print resolution report
    print(f"\n{'='*70}")
    print(f"{'Config Key':35s} {'Offset':>10s}  {'Method'}")
    print(f"{'='*70}")
    for key in RESOLVE_RULES:
        k = key["key"]
        r = results.get(k)
        if r:
            print(f"{k:35s} 0x{r['offset']:08x}  ({r['method']})")
        else:
            print(f"{k:35s} {'<<< MISSING >>>':>10s}")
    print(f"{'='*70}")

    if warnings:
        print(f"\n[WARNINGS]")
        for w in warnings:
            print(f"  ! {w}")

    if errors:
        print(f"\n[ERRORS]")
        for e in errors:
            print(f"  X {e}")

    print(f"\n[*] Resolved: {len(results)}/{len(RESOLVE_RULES)} symbols")

    # Determine output
    output_path = None
    if len(sys.argv) >= 3 and not sys.argv[2].startswith('--'):
        output_path = sys.argv[2]
    else:
        output_path = str(Path(elf_path).with_suffix('.conf'))

    if output_path:
        config_text = generate_config(results, output_path)
        if not any(flag in sys.argv for flag in ['--json', '--check']):
            print(f"\n{config_text}")

    if errors:
        print("\n[!] Some symbols could not be resolved. You may need to manually")
        print("    add them to the config or use a kernel with matching symbols.")
        sys.exit(1)


if __name__ == "__main__":
    main()
