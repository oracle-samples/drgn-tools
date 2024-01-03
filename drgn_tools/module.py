# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from collections import defaultdict
from pathlib import Path
from typing import Dict
from typing import Iterable
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import overload
from typing import Tuple
from typing import Union

from drgn import cast
from drgn import IntegerLike
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn import Symbol
from drgn import SymbolBinding
from drgn import SymbolKind
from drgn.helpers.linux.list import list_for_each_entry

try:
    # drgn v0.21.0+
    from drgn.helpers.common import escape_ascii_string
except ImportError:
    # drgn <v0.21.0
    from drgn.helpers import escape_ascii_string

from drgn_tools.debuginfo import fetch_debuginfo
from drgn_tools.debuginfo import find_debuginfo
from drgn_tools.taint import Taint


__all__ = (
    "ensure_debuginfo",
    "load_module_debuginfo",
    "ModuleLayout",
    "module_address_region",
    "module_init_region",
    "module_percpu_region",
    "module_symbols",
    "module_exports",
    "module_unified_symbols",
    "for_each_module",
    "find_module",
    "address_to_module",
    "KernelModule",
    "module_build_id",
)


class ModuleLayout(NamedTuple):
    """
    Represents a module's layout in memory.

    Module memory layout is organized into three sections. First is the text
    section, which is read-only (RO). Next is the RO data section, which is
    usually protected with no-execute (NX) permissions. Next is additional
    data which becomes RO after init, and finally is the RW data. The below
    diagram from the kernel source code demonstrates this layout (note that
    for clarity, we refer to ``size`` as ``total_size``).

    .. code-block::

      General layout of module is:
               [text] [read-only-data] [ro-after-init] [writable data]
      text_size -----^                ^               ^               ^
      ro_size ------------------------|               |               |
      ro_after_init_size -----------------------------|               |
      size -----------------------------------------------------------|
    """

    base: Object
    """The base address of the memory region, as a ``void *``."""
    total_size: int
    """The total length of the memory region."""
    text_size: int
    """The length of the text section."""
    ro_size: int
    """The length of the read-only memory (text, and RO data)"""
    ro_after_init_size: int
    """The length of the read-only memory, plus memory which is RO after init"""

    def contains(self, address: IntegerLike) -> bool:
        offset = int(address) - self.base.value_()
        return 0 <= offset < self.total_size


def _layout_from_module_layout(layout: Object) -> ModuleLayout:
    try:
        ro_after_init_size = layout.ro_after_init_size.value_()
    except AttributeError:
        # Prior to 4.8, 444d13ff10fb ("modules: add ro_after_init support"),
        # there was no ro_after_init support. Pretend it existed and it was
        # just zero-length.
        ro_after_init_size = layout.ro_size.value_()
    return ModuleLayout(
        layout.base,
        layout.size.value_(),
        layout.text_size.value_(),
        layout.ro_size.value_(),
        ro_after_init_size,
    )


def _layout_from_module(module: Object, kind: str) -> ModuleLayout:
    return ModuleLayout(
        module.member_(f"module_{kind}"),
        module.member_(f"{kind}_size").value_(),
        module.member_(f"{kind}_text_size").value_(),
        module.member_(f"{kind}_ro_size").value_(),
        module.member_(f"{kind}_ro_size").value_(),
    )


def module_address_region(mod: Object) -> ModuleLayout:
    """
    Lookup the core memory region of a module.

    Given a ``struct module *``, return the address and length of its code and
    data. This region ignores the "__init" data of the module; see

    :func: ``module_init_region()`` to find that.
    :param mod: Object of type ``struct module *``
    :returns: A tuple representing the address and size of the memory, along
      with the size of various protection zones within.
    """
    try:
        return _layout_from_module_layout(mod.core_layout)
    except AttributeError:
        # Prior to 4.5, 7523e4dc5057 ("module: use a structure to encapsulate
        # layout."), the layout information was stored as plain fields on the
        # module.
        return _layout_from_module(mod, "core")


def module_init_region(mod: Object) -> Optional[ModuleLayout]:
    """
    Lookup the init memory region of a module.

    Given a ``struct module *``, return the address and length of the
    ``__init`` memory regions. This memory is typically freed after the module
    is loaded, so under most circumstances, this will return None.

    :param mod: Object of type ``struct module *``
    :returns: A tuple representing the layout of the init memory
    """
    try:
        layout = _layout_from_module_layout(mod.init_layout)
    except AttributeError:
        layout = _layout_from_module(mod, "init")
    if not layout.base.value_():
        return None
    return layout


def module_percpu_region(mod: Object) -> Optional[Tuple[Object, int]]:
    """
    Lookup the percpu memory region of a module.

    Given a ``struct module *``, return the address and the length of the
    percpu memory region. Modules may have a NULL percpu region, in which case
    ``(void *)NULL`` is returned. Rarely, on kernels without ``CONFIG_SMP``,
    there is no percpu region at all, and this function returns ``None``.

    :param mod: Object of type ``struct module *``
    :returns: A tuple containing the base address and length of the region
    """
    try:
        return mod.percpu, mod.percpu_size.value_()
    except AttributeError:
        return None


def for_each_module(prog: Program) -> Iterable[Object]:
    """
    Get all loaded kernel module objects in kernel

    :param prog: Program being debugged
    :returns: Iterable of ``struct module *`` objects
    """
    return list_for_each_entry(
        "struct module", prog["modules"].address_of_(), "list"
    )


def find_module(prog: Program, name: Union[str, bytes]) -> Optional[Object]:
    """
    Return the module with the given name
    :param name: Module name
    :returns: if found, ``struct module *``
    """
    if isinstance(name, str):
        name = name.encode()
    for module in for_each_module(prog):
        if module.name.string_() == name:
            return module
    return None


@overload
def address_to_module(addr: Object) -> Optional[Object]:
    """"""
    ...


@overload
def address_to_module(prog: Program, addr: IntegerLike) -> Optional[Object]:
    ...


def address_to_module(  # type: ignore  # Need positional-only arguments.
    prog_or_addr: Union[Program, Object],
    addr: Optional[IntegerLike] = None,
) -> Optional[Object]:
    """
    Try to find the module corresponding to a memory address.

    Search for the given address in the list of loaded kernel modules. If it
    is within the address range corresponding to a kernel module, return that
    module. This function searches the module's core (normal memory) region,
    the module's init region (if present) and the module's percpu region (if
    present). Note that it's impossible to detect memory **allocated** by a
    particular kernel module: this function only deals with static data.

    This helper performs a linear search of the list of modules, which could
    grow quite large. As a result, the performance may suffer on repeated
    lookups.

    :param addr: address to lookup
    :returns: if the address corresponds to a module, ``struct module *``
    """
    if addr is None:
        assert isinstance(prog_or_addr, Object)
        prog = prog_or_addr.prog_
        addr = prog_or_addr.value_()
    else:
        assert isinstance(prog_or_addr, Program)
        prog = prog_or_addr
        addr = int(addr)

    for module in for_each_module(prog):
        region = module_address_region(module)
        if region.contains(addr):
            return module
        pcpu_region = module_percpu_region(module)
        if pcpu_region:
            pcpu, pcpu_len = pcpu_region
            if 0 <= addr - pcpu.value_() < pcpu_len:
                return module
        init_region = module_init_region(module)
        if init_region and init_region.contains(addr):
            return module

    return None


def module_build_id(mod: Object) -> str:
    """
    Return the build ID (as a hex string) for this module.

    :param mod: Object of ``struct module *``
    :returns: Build ID as hex string
    """
    prog = mod.prog_
    notes_attrs = mod.notes_attrs
    for i in range(notes_attrs.notes.value_()):
        attr = notes_attrs.attrs[i]
        if attr.attr.name.string_() == b".note.gnu.build-id":
            data = prog.read(attr.private, attr.size.value_())
            # Hack / simplification: note data comes at the end of the ELF note
            # structure. It's 4-byte padded, but build IDs are 20 bytes. So
            # just use the last 20 bytes rather than fiddling with the offset
            # math.
            return data[-20:].hex()
    raise ValueError("Build ID not found!")


class ParamInfo(NamedTuple):
    """Contains information about a kernel module parameter"""

    name: str
    kernel_param: Object
    type_name: str
    value: Optional[Object]


_MOD_PARAM_TYPES = {
    "param_get_byte": "unsigned char",
    "param_get_short": "short",
    "param_get_ushort": "unsigned short",
    "param_get_int": "int",
    "param_get_uint": "unsigned int",
    "param_get_long": "long",
    "param_get_ulong": "unsigned long",
    "param_get_ullong": "unsigned long long",
    "param_get_bool": "bool",
    "param_get_charp": "char *",
}


def decode_param(kp: Object) -> ParamInfo:
    """
    Given a ``struct kernel_param *``, return its value

    This fills out a :class:`ParamInfo` based on the value of the module
    parameter. In the ideal case, a human-readable type, and the parameter's
    value itself are both created. However, there are some cases where we cannot
    determine the object, in which case the type name is still provided, in as
    much detail as possible.

    Please note that the resulting object is not guaranteed to be readable. For
    instance, strings may be NULL. Another relatively common issue is that some
    module parameters are marked ``__initdata``, so their data will be thrown
    out after the module is loaded. Thus, users should take care to handle a
    potential ``FaultError`` when using the parameter value.

    :param kp: ``struct kernel_param *``
    :returns: a :class:`ParamInfo`

    """
    prog = kp.prog_
    name = kp.name.string_().decode("utf-8")
    try:
        param_type = prog.symbol(kp.ops.get).name
    except LookupError:
        return ParamInfo(name, kp, "UNKNOWN", None)

    PREFIX = "param_get_"
    if param_type in _MOD_PARAM_TYPES:
        obj = Object(prog, _MOD_PARAM_TYPES[param_type], address=kp.arg)
        param_type = param_type[len(PREFIX) :]
    elif param_type == "param_get_string":
        obj = cast("char *", kp.arg)
        param_type = "string"
    elif param_type == "param_array_get":
        length = int(kp.arr.num[0] if kp.arr.num else kp.arr.max)
        try:
            elem_type = prog.symbol(kp.arr.ops.get).name
        except LookupError:
            return ParamInfo(name, kp, f"UNKNOWN[{length}]", None)

        if elem_type not in _MOD_PARAM_TYPES:
            return ParamInfo(name, kp, f"<{elem_type}?>[{length}]", None)

        type_ = prog.type(_MOD_PARAM_TYPES[elem_type])
        elem_type = elem_type[len(PREFIX) :]
        param_type = f"{elem_type}[{length}]"
        if sizeof(type_) != kp.arr.elemsize:
            return ParamInfo(name, kp, param_type, None)
        obj = Object(prog, prog.array_type(type_, length), address=kp.arr.elem)
    else:
        return ParamInfo(name, kp, f"<{param_type}?>", None)
    return ParamInfo(name, kp, param_type, obj)


def module_params(mod: Object) -> Dict[str, ParamInfo]:
    """
    Return a dictionary of kernel module parameters

    :param mod: the kernel module, ``struct module *``
    :returns: a dict mapping parameter name to information about it
    """
    ret = {}
    for i in range(mod.num_kp):
        info = decode_param(mod.kp[i])
        ret[info.name] = info
    return ret


def module_symbols(module: Object) -> List[Tuple[str, Object]]:
    """
    Return a list of ELF symbols for a module via kallsyms.

    Kernel modules may have a ``module_kallsyms`` field which contains ELF
    symbol objects describing all kallsyms symbols. This function accesses this
    symbol information.

    Returns a list of objects of type ``Elf_Sym``. This object is a typedef to
    an architecture specific type (either 64 or 32 bits), either of which
    contain the same fields -- see :manpage:`elf(5)` for their definition. Since
    the ``st_name`` field is merely an index and can't be interpreted without
    the string table, this helper returns a tuple of the decoded name, and the
    symbol object.

    :param module: Object of ``struct module *``
    :returns: A list of name, ``Elf_Sym`` pairs
    """
    try:
        ks = module.kallsyms
    except AttributeError:
        # Prior to 8244062ef1e54 ("modules: fix longstanding /proc/kallsyms vs
        # module insertion race."), the kallsyms variables were stored directly
        # on the module object. This commit was introduced in 4.5, but was
        # backported to some stable kernels too. Fall back to the module object
        # in cases where kallsyms field isn't available.
        ks = module

    prog = module.prog_
    num_symtab = ks.num_symtab.value_()

    # The symtab field is a pointer, but it points at an array of Elf_Sym
    # objects. Indexing it requires drgn to do pointer arithmetic and issue a
    # lot of very small /proc/kcore reads, which can be a real performance
    # issue. So convert it into an object representing a correctly-sized array,
    # and then read that object all at once. This does one /proc/kcore read,
    # which is a major improvement!
    symtab = Object(
        prog,
        type=prog.array_type(ks.symtab.type_.type, num_symtab),
        address=ks.symtab.value_(),
    ).read_()

    # The strtab is similarly a pointer into a contigous array of strings packed
    # next to each other. Reading individual strings from /proc/kcore can be
    # quite slow. So read the entire array of bytes into a Python bytes value,
    # and we'll extract the individual symbol strings from there.
    last_string_start = symtab[num_symtab - 1].st_name.value_()
    last_string_len = (
        len(ks.strtab[last_string_start].address_of_().string_()) + 1
    )
    strtab = prog.read(ks.strtab.value_(), last_string_start + last_string_len)
    syms = []
    # Start range at index 1, because the first ELF symbol is always bogus
    for i in range(1, ks.num_symtab.value_()):
        elfsym = symtab[i]
        str_index = elfsym.st_name.value_()
        nul_byte = strtab.find(b"\x00", str_index)
        name = strtab[str_index:nul_byte].decode("ascii")
        syms.append((name, elfsym))
    return syms


def _first_kallsyms_symbol(module: Object) -> Optional[int]:
    try:
        ks = module.kallsyms
    except AttributeError:
        ks = module
    if ks.num_symtab >= 2:
        return int(ks.symtab[1].st_value)
    return None


def module_has_debuginfo(module: Object) -> bool:
    """
    Return true if a module has debuginfo

    We do this by looking at the first symbol in the kallsyms. If drgn can find
    a symbol for it, we return True, otherwise False. This is a fast, but
    imperfect heuristic. In the future, drgn will have an API which lets us
    enumerate modules directly query whether it has loaded debuginfo.
    """
    fst = _first_kallsyms_symbol(module)
    if not fst:
        return False
    try:
        module.prog_.symbol(fst)
        return True
    except LookupError:
        return False


def _elf_sym_to_symbol(name: str, obj: Object) -> Symbol:
    """See drgn_symbol_from_elf() in libdrgn/symbol.c"""
    info = obj.st_info.value_()
    binding = info >> 4
    STB_WEAK = 2
    STB_GNU_UNIQUE = 10
    if binding <= STB_WEAK or binding == STB_GNU_UNIQUE:
        binding = SymbolBinding(binding + 1)
    else:
        binding = SymbolBinding.UNKNOWN
    type_ = info & 0xF
    STT_TLS = 6
    STT_GNU_IFUNC = 10
    if type_ <= STT_TLS or type_ == STT_GNU_IFUNC:
        kind = SymbolKind(type_)
    else:
        kind = SymbolKind.UNKNOWN
    return Symbol(
        name,
        obj.st_value.value_(),
        obj.st_size.value_(),
        binding,
        kind,
    )


def module_exports(module: Object) -> List[Tuple[int, str]]:
    """
    Return a list of names and addresses from the exported symbols

    Kernel modules may have various fields like ``syms``, ``gpl_syms``, etc.
    These fields correspond to **exported** symbols, that is, the symbols for
    which there was an ``EXPORT_SYMBOL()`` macro declared. The exported symbols
    are the only ones which may be used by other modules.

    This function returns names and addresses for each exported symbol. It
    includes all symbols available, regardless of license. The symbols are
    returned in sorted order by increasing address. Note that size information
    is not provided by the kernel, and so it is not returned here.

    :param module: Object of ``struct module *``
    :returns: A list of address, name pairs
    """
    values = []
    prog = module.prog_

    ksym = prog.type("struct kernel_symbol")
    if ksym.has_member("value_offset"):
        # Handle the case of CONFIG_HAVE_ARCH_PREL32_RELOCATIONS, ever since
        # 7290d58095712 ("module: use relative references for __ksymtab
        # entries"), which was introduced in Linux 4.19.

        void_star = prog.type("void *")
        char_star = prog.type("char *")
        unsigned_long = prog.type("void *")

        def offset_to_ptr(off: Object):
            # Integer overflow is actually baked into the design of this
            # function! Some values intentionally overflow, so that they can
            # refer to a percpu variable. If we used Python integer addition,
            # the overflow wouldn't happen, and we'd get a value too large to
            # convert back to drgn types. Instead, do the addition using the
            # unsigned long type, just like the kernel does. Drgn faithfully
            # reproduces the overflow, as intended.
            address = Object(prog, unsigned_long, off.address_)
            return cast(void_star, address + off)

        def add_symbols(count: Object, array: Object):
            for i in range(count.value_()):
                symbol = array[i]
                # See offset_to_ptr
                value = offset_to_ptr(symbol.value_offset)
                name_ptr = cast(char_star, offset_to_ptr(symbol.name_offset))
                values.append(
                    (value.value_(), name_ptr.string_().decode("ascii"))
                )

    else:

        def add_symbols(count: Object, array: Object):
            for i in range(count.value_()):
                symbol = array[i]
                values.append(
                    (
                        symbol.value.value_(),
                        symbol.name.string_().decode("ascii"),
                    )
                )

    add_symbols(module.num_syms, module.syms)
    add_symbols(module.num_gpl_syms, module.gpl_syms)
    if hasattr(module, "unused_syms"):
        add_symbols(module.num_unused_syms, module.unused_syms)
    if hasattr(module, "unused_gpl_syms"):
        add_symbols(module.num_unused_gpl_syms, module.unused_gpl_syms)

    values.sort()
    return values


def module_unified_symbols(module: Object) -> List[Tuple[str, int, int]]:
    """
    Unify all sources of module symbols and return basics: name, value, length.

    There are multiple possible sources of module symbol information: kallsyms,
    exports, etc. This function unifies them all and attempts to give just basic
    info. Note that in some cases, we have to infer the symbol length. This
    helper does that as best it can.

    :param module: Object of ``struct module *``
    :returns: A list of (name, address, length) for each symbol. The list is in
      sorted order, sorted by the address.
    """
    # We have two sources of symbols: the module_kallsyms which contains real
    # ELF symbols, and the exports, which are just name / address pairs.
    # If kallsyms doesn't contain data, then the exports could be helpful, but
    # they contain less data (fewer symbols and no extra metadata like size).
    #
    # This function combines the symbol data sources and infers symbol length as
    # best it can. It's not ideal, but sadily it's all we can do.
    elf_syms = module_symbols(module)
    elf_by_name = dict(elf_syms)
    elf_by_addr = {sym.st_value.value_(): sym for _, sym in elf_syms}
    exports = module_exports(module)

    # Remove any exported symbols which are also present in the kallsyms - the
    # exports have less data.
    for i in reversed(range(len(exports))):
        addr, name = exports[i]
        elf_sym = elf_by_name.get(name)
        if elf_sym is not None and elf_sym.st_value.value_() == addr:
            del exports[i]
            continue
        elf_sym = elf_by_addr.get(addr)
        if elf_sym:
            # It's a match, but not a name match... strange.
            print(
                "Warning: matching address between export/kallsyms, but not matching name"
            )
            print(
                "Export name: {}, ELF name: {}, address: {:x}".format(
                    name, elf_sym.name.string_().decode("ascii"), addr
                )
            )
            del exports[i]

    # Create a unified list of (address, name, maybe_length)
    unified: List[Tuple[int, str, Optional[int]]] = []
    unified.extend((e[0], e[1], None) for e in exports)
    unified.extend(
        (elf_sym.st_value.value_(), name, elf_sym.st_size.value_())
        for name, elf_sym in elf_syms
    )
    unified.sort()  # by address

    # One strategy for finding the end of a symbol is noticing that it is within
    # a module address region, and realizing that it should not stretch past it.
    # Implement the strategy here.
    core_layout = module_address_region(module)
    init_layout = module_init_region(module)
    percpu_layout = module_percpu_region(module)
    layouts: List[Optional[ModuleLayout]] = [
        core_layout,
        init_layout,
    ]

    def find_end_scn(addr: int) -> Optional[int]:
        for layout in layouts:
            if not layout or not layout.contains(addr):
                continue
            for kind in ("text", "ro", "ro_after_init", "total"):
                boundary = layout.base.value_() + getattr(
                    layout, f"{kind}_size"
                )
                if addr < boundary:
                    return boundary
            assert False, "Impossible to reach this line"
        if percpu_layout is not None:
            pcpu_reg, pcpu_len = percpu_layout
            if addr >= pcpu_reg and addr < pcpu_reg + pcpu_len:
                return pcpu_reg + pcpu_len
        return None

    # Iterate over each symbol, and if the length is missing, try to infer.
    final: List[Tuple[str, int, int]] = []
    for i in range(len(unified)):
        addr, name, maybe_len = unified[i]
        if maybe_len:
            final.append((name, addr, maybe_len))
            continue
        # Beyond the "end_scn" approach shown above, the other possibility is
        # using the next symbol in sorted order as the boundary.
        next_addr = None
        if i + 1 < len(unified):
            next_addr = unified[i + 1][0]
        end_scn = find_end_scn(addr)

        # If we have both, choose the minimum length, or 0 if we have neither.
        if not next_addr and not end_scn:
            # found neither, fall back to zero-length symbol
            length = 0
        elif next_addr and end_scn:
            # found both, choose the smaller one
            length = min(end_scn, next_addr) - addr
        elif next_addr:
            length = next_addr - addr
        elif end_scn:
            length = end_scn - addr
        else:
            # should not reach this line
            length = 0
        final.append((name, addr, length))
    return final


class ModuleSymbolFinder:
    """
    A symbol finder implementation for Linux kernel modules.

    This finder is capable of looking up symbols from the ``struct module *``
    objects in the kernel, so long as module kallsyms is enabled. When used with
    :meth:`Program.add_symbol_finder()`, it allows stack traces,
    :meth:`Program.symbol()`, and other parts of drgn to function using module
    symbols, even when debugging information is not loaded for kernel modules.

    >>> finder = ModuleSymbolFinder(prog)
    >>> finder("nft_redir_dump", None, False)
    [Symbol(name='nft_redir_dump', address=0xffffffffc0925000, size=0xa6, binding=<SymbolBinding.LOCAL: 1>, kind=<SymbolKind.FUNC: 2>)]
    >>> prog.add_symbol_finder(finder)
    >>> prog.symbol("nft_redir_dump")
    Symbol(name='nft_redir_dump', address=0xffffffffc0925000, size=0xa6, binding=<SymbolBinding.LOCAL: 1>, kind=<SymbolKind.FUNC: 2>)
    """

    prog: Program

    name_map: Dict[str, List[Symbol]]
    """Maps name to (maybe multiple) symbols"""
    page_map: Dict[int, List[Symbol]]
    """Maps page address to all symbols spanning it."""
    all_syms: List[Symbol]
    """List of all symbols for fast return."""

    def __init__(self, prog):
        self.prog = prog
        self.name_map = defaultdict(list)
        self.all_syms = []
        for mod in for_each_module(prog):
            for name, sym in module_symbols(mod):
                symbol = _elf_sym_to_symbol(name, sym)
                self.name_map[name].append(symbol)
                self.all_syms.append(symbol)

        # We need to support queries by name and by address. By name is rather
        # easy.  By address is a bit difficult. _Ideally_ we would use an
        # interval tree, since that is the "correct" way to represent possibly
        # overlapping ranges.  But really, that's a pain to implement, and we
        # can be reasonably efficient by adopting a poor man's radix tree...
        # store a list of symbols for each page of memory, and then use linear
        # search on that.
        self.page_map = defaultdict(list)
        page_shift = self.prog["PAGE_SHIFT"].value_()
        for sym in self.all_syms:
            page_start = sym.address >> page_shift
            page_end = (sym.address + sym.size) >> page_shift
            for page in range(page_start, page_end + 1):
                self.page_map[page].append(sym)

    def _filter_contains(
        self, symbols: List[Symbol], addr: int
    ) -> List[Symbol]:
        return [
            sym
            for sym in symbols
            if sym.address <= addr < sym.address + sym.size
        ]

    def __call__(
        self, name: Optional[str], addr: Optional[int], one: bool
    ) -> List[Symbol]:
        """
        Lookup symbols by name or address.

        See :meth:`Program.add_symbol_finder()` for documentation on the
        arguments and return value.
        """
        if name is None and addr is None:
            return self.all_syms

        if name is not None:
            ret = self.name_map[name]
            if addr is not None:
                ret = self._filter_contains(ret, addr)
        else:
            assert addr is not None  # mypy can't tell on its own
            page = addr >> self.prog["PAGE_SHIFT"].value_()
            ret = self._filter_contains(self.page_map[page], addr)
        if one and len(ret) > 1:
            ret = [ret[0]]
        return ret


class KernelModule:
    """
    Provides a more "object-oriented" interface to the module helpers.

    This class wraps an object of type ``struct module *``, and adds methods
    which can be used to interact with it. For example:

    >>> km = KernelModule.find(prog, "nf_nat")
    >>> km
    KernelModule(nf_nat)
    >>> km.address_region()
    ModuleLayout(base=Object(prog, 'void *', address=0xffffffffc0878580), total_size=40960, text_size=16384, ro_size=20480, ro_after_init_size=24576)
    >>> km.init_region()
    >>> km.percpu_region()
    (Object(prog, 'void *', address=0xffffffffc0878688), 0)
    >>> hex(km.address_region().base + 123)
    '0xffffffffc087207b'
    >>> KernelModule.lookup_address(prog, 0xffffffffc087207b)
    KernelModule(nf_nat)
    """

    name: str
    obj: Object

    @classmethod
    def all(cls, prog: Program) -> Iterable["KernelModule"]:
        """
        Get an iterator of KernelModule helpers for each loaded module

        :param prog: Program being debugged
        :returns: Iterable of kernel module helpers
        """
        for m in for_each_module(prog):
            yield KernelModule(m)

    @classmethod
    def find(cls, prog: Program, name: str) -> Optional["KernelModule"]:
        """
        Return a KernelModule helper for ``name`` if present

        :param prog: Program being debugged
        :returns: Iterable of kernel module helpers
        """
        maybe_mod = find_module(prog, name)
        if maybe_mod:
            maybe_mod = KernelModule(maybe_mod)
        return maybe_mod

    @classmethod
    @overload
    def lookup_address(cls, addr: Object) -> Optional["KernelModule"]:
        ...

    @classmethod
    @overload
    def lookup_address(
        cls, prog: Program, addr: IntegerLike
    ) -> Optional["KernelModule"]:
        ...

    @classmethod  # type: ignore  # Need positional-only arguments.
    def lookup_address(
        cls,
        prog_or_addr: Union[Program, Object],
        addr: Optional[IntegerLike] = None,
    ) -> Optional["KernelModule"]:
        """
        Lookup the module containing this address and return the KernelModule
        helper for it, if found. See :func:`address_to_module()`.
        """
        mod = address_to_module(prog_or_addr, addr)
        if mod:
            mod = KernelModule(mod)
        return mod

    def __init__(self, obj: Object):
        self.name = escape_ascii_string(
            obj.name.string_(), escape_backslash=True
        )
        self.obj = obj

    def __repr__(self) -> str:
        return f"KernelModule({self.name})"

    def __str__(self) -> str:
        return repr(self)

    def have_debuginfo(self) -> bool:
        """
        Determine whether debuginfo is loaded for this module.

        :returns: True if debuginfo exists for this module
        """
        return module_has_debuginfo(self.obj)

    def find_debuginfo(self) -> Optional[Path]:
        """
        Search for a debuginfo file matching this module.

        :return: Path to file, or None on failure.
        """
        return find_debuginfo(self.obj.prog_, self.name)

    def load_debuginfo(
        self,
        extract: bool = False,
        need_dwarf: bool = False,
    ) -> None:
        """
        If the module's debuginfo is not loaded, find and load it

        :param extract: If true, attempts to extract the module
        :param need_dwarf: Currently nused, but this will avoid using CTF/BTF
          when full DWARF debuginfo is required
        """
        if not self.have_debuginfo():
            info = self.find_debuginfo()
            if not info and extract:
                release = (
                    self.obj.prog_["UTS_RELEASE"].string_().decode("ascii")
                )
                print("extracting from RPM...")
                name = self.name.replace("-", "_")
                info = fetch_debuginfo(release, [name]).get(name)
            if info:
                self.obj.prog_.load_debug_info([info])
            else:
                raise FileNotFoundError("Could not find debuginfo for module")

    def address_region(self) -> ModuleLayout:
        """
        Return the core region of the module. See
        :func:`module_address_region()`.

        :returns: Layout of the "core" (non-init) region
        """
        return module_address_region(self.obj)

    def init_region(self) -> Optional[ModuleLayout]:
        """
        Return the init memory region of the module.
        """
        return module_init_region(self.obj)

    def percpu_region(self) -> Optional[Tuple[Object, int]]:
        """
        Return the percpu memory region of the module, see
        :func:`module_percpu_region()`.
        """
        return module_percpu_region(self.obj)

    def build_id(self) -> str:
        """
        Return the build ID of this module, useful for matching debuginfo.
        """
        return module_build_id(self.obj)

    def params(self) -> Dict[str, ParamInfo]:
        """
        Return a dictionary of the parameters of the module, see
        :func:`module_params()`
        """
        return module_params(self.obj)

    def symbols(self) -> List[Tuple[str, Object]]:
        """
        Return a list of ELF symbol objects via kallsyms, and their names.

        This function is intended to be used when the DWARF debuginfo for a
        module is not available, but when the debuginfo for vmlinux is
        available. If the module's debuginfo is loaded, this should not be used;
        instead, just rely on drgn's built-in symbol lookup behavior.

        .. note::

            Please note that this only returns the symbols from the module's
            kallsyms table, and does not include any symbols from the exported
            symbol list. This is usually ok, but sometimes the exports are
            useful. The ```unified_symbols()`` interface includes the rest, but
            they are not represented as ELF symbols, instead just as names,
            addresses, and sizes.

        :returns: List of tuples: (symbol name, ``Elf64_Sym`` object)
        """
        return module_symbols(self.obj)

    def exports(self) -> List[Tuple[int, str]]:
        """
        Return a list of exported (with or without GPL) symbol name & address
        """
        return module_exports(self.obj)

    def unified_symbols(self) -> List[Tuple[str, int, int]]:
        """
        Return a sorted list of all symbols we can find for a module.

        This function is intended to be used when the DWARF debuginfo for a
        module is not available, but when the debuginfo for vmlinux is
        available. If the module's debuginfo is loaded, this should not be used;
        instead, just rely on drgn's built-in symbol lookup behavior.

        :returns: List of tuples: (symbol name, address, size)
        """
        return module_unified_symbols(self.obj)

    def get_symbol(self, addr: IntegerLike) -> Optional[str]:
        """
        Lookup a symbol by address.

        This function is intended to be used when the DWARF debuginfo for a
        module is not available, but when the debuginfo for vmlinux is
        available. If the module's debuginfo is loaded, this should not be used;
        instead, just rely on drgn's built-in symbol lookup behavior.

        Note that this function relies on the list of symbols returned by
        ``unified_symbols()``, the most complete list available.

        :param addr: Address to lookup
        :returns: A symbol name, if found
        """
        addr = int(addr)
        for name, sym_addr, sym_len in module_unified_symbols(self.obj):
            if sym_addr <= addr < sym_addr + sym_len:
                return name
        return None

    def is_oot(self) -> bool:
        """
        Return true if the module is out of tree.

        This is determined using the module.taints field: modules which are
        tainted OOT_MODULE, PROPRIETARY_MODULE, or UNSIGNED_MODULE, could not
        have come from our debuginfo RPMs, and so they are considered out of
        tree. Unfortunately, OOT_MODULE itself is not enough: for some reason,
        it seems that not all out-of-tree modules get that taint applied.
        """
        # Any of the following flags means that a module could not have come
        # from the debuginfo RPMs, and that's what matters in our case.
        oot_taints = (
            (1 << Taint.OOT_MODULE)
            | (1 << Taint.PROPRIETARY_MODULE)
            | (1 << Taint.UNSIGNED_MODULE)
        )
        return bool(self.obj.taints & oot_taints)


def load_module_debuginfo(
    prog: Program,
    modules: Union[None, List[str], List[KernelModule]] = None,
    extract: bool = False,
    strict: bool = False,
    quiet: bool = False,
) -> None:
    """
    Load all available debuginfo for all modules, with optional extraction

    This function uses the normal search paths to find debuginfo (See
    find_debuginfo() for details). For modules whose debuginfo is not found, if
    extract is True, it attempts to extract the debuginfo from the vmlinux
    repo. When strict is true, it raises an error if not all module debuginfo
    could be found and loaded.

    This function ignores all modules which are tainted as OOT_MODULE,
    PROPRIETARY_MODULE, or UNSIGNED_MODULE. These modules will not be found in
    the debuginfo RPMs so there's no point in looking.

    :param modules: list of modules to load. The list may be provided as a
      list of strings, or a list of ``KernelModule`` objects -- but they cannot
      be mixed! If not provided, we fall back to loading all modules.
    :param extract: when true, attempt to extract debuginfo
    :param strict: when true, raise an exception if we couldn't load all modules
    :param quiet: when true, silence output regarding missing or OOT modules
    """

    # mypy can be really great sometimes, but it also really sucks sometimes.
    # The statements below have the effect of ensuring that modules is a list of
    # KernelModule, but mypy won't allow it. So there's some unpleasantness in
    # this function to satisfy the beast.
    if modules and isinstance(modules[0], str):
        # Support a list of str
        mod_set = set(modules)
        modules = [km for km in KernelModule.all(prog) if km.name in mod_set]
        not_loaded = mod_set - set(km.name for km in modules)
        if not_loaded and strict:
            raise ValueError(
                "The following modules are not loaded: {}".format(
                    ", ".join(str(s) for s in not_loaded)
                )
            )
    elif not modules:
        # Fall back to all modules
        modules = list(KernelModule.all(prog))
    to_load = []
    name_set = {m.name.replace("-", "_") for m in modules}  # type: ignore
    in_tree = set()
    already_loaded = set()
    found_set = set()
    to_extract = set()
    for mod_ in modules:
        # mypy silliness:
        mod: KernelModule = mod_  # type: ignore
        # no use wasting time searching for out-of-tree modules
        if mod.is_oot():
            continue

        mod_name = mod.name.replace("-", "_")
        in_tree.add(mod_name)

        # no need to load debuginfo we already have
        if mod.have_debuginfo():
            already_loaded.add(mod_name)
            continue

        dinfo = mod.find_debuginfo()
        if dinfo:
            to_load.append(dinfo)
            found_set.add(mod_name)
        elif extract:
            to_extract.add(mod_name)

    if extract and to_extract:
        print("extracting debuginfo from vmlinux_repo...")
        extracted = fetch_debuginfo(
            prog["UTS_RELEASE"].string_().decode("ascii"), list(to_extract)
        )
        for extracted_name, path in extracted.items():
            to_load.append(path)
            found_set.add(extracted_name)

    missing = in_tree - already_loaded - found_set
    if missing and strict:
        raise FileNotFoundError(
            "Could not load debuginfo for: {}".format(", ".join(missing))
        )
    elif missing and not quiet:
        print(
            "warning: Could not load debuginfo for: {}".format(
                ", ".join(missing)
            )
        )

    oot = name_set - in_tree
    if oot and not quiet:
        print(
            "warning: out-of-tree modules not loaded: {}".format(
                ", ".join(oot)
            )
        )

    prog.load_debug_info(to_load)


def ensure_debuginfo(prog: Program, modules: List[str]) -> Optional[str]:
    """
    Ensure that the modules listed are loaded in the kernel and have
    debuginfo available. If the modules are not present in the kernel or
    the debuginfo cannot be loaded, return an error message.
    """
    try:
        load_module_debuginfo(
            prog,
            modules,
            strict=True,
        )
    except FileNotFoundError as e:
        return str(e)
    except ValueError as e:
        return str(e)
    return None


class ModuleLoadSummary(NamedTuple):
    """
    A simple class to represent a summary of all loaded modules.

    You can print this to get a human-friendly overview of the modules for a
    vmcore, which is useful for deciding whether you want to extract more
    debuginfo or not.
    """

    total_mods: int
    ksplice_mods: List[KernelModule]
    other_oot: List[KernelModule]
    loaded_mods: List[KernelModule]
    missing_mods: List[KernelModule]

    def __str__(self) -> str:
        text = f"{self.total_mods} kernel modules are loaded: "
        details = []
        if self.ksplice_mods:
            details.append(f"{len(self.ksplice_mods)} are ksplices")
        if self.other_oot:
            details.append(
                f"{len(self.other_oot)} are other out-of-tree modules"
            )
        if self.loaded_mods:
            details.append(f"{len(self.loaded_mods)} have debuginfo")
        # it's nice to have confirmation, regardless of whether it is 0
        details.append(f"{len(self.missing_mods)} are missing debuginfo")
        return text + ", ".join(details)


def get_module_load_summary(prog: Program) -> ModuleLoadSummary:
    """
    Compute the current status of all modules.
    """
    total_mods = 0
    ksplice_mods = []
    other_oot = []
    loaded_mods = []
    missing_mods = []
    for mod in KernelModule.all(prog):
        total_mods += 1
        if mod.name.startswith("ksplice"):
            ksplice_mods.append(mod)
        elif mod.is_oot():
            other_oot.append(mod)
        elif mod.have_debuginfo():
            loaded_mods.append(mod)
        else:
            missing_mods.append(mod)
    return ModuleLoadSummary(
        total_mods, ksplice_mods, other_oot, loaded_mods, missing_mods
    )
