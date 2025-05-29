# Copyright (c) 2024-2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from typing import Dict
from typing import Iterable
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Tuple
from typing import Union

from drgn import cast
from drgn import FaultError
from drgn import Module
from drgn import ModuleFileStatus
from drgn import Object
from drgn import Program
from drgn import RelocatableModule
from drgn import sizeof
from drgn.helpers.common import escape_ascii_string
from drgn.helpers.linux import module_address_regions
from drgn.helpers.linux import module_percpu_region

from drgn_tools.taint import Taint


__all__ = (
    "KernelModule",
    "ParamInfo",
    "ensure_debuginfo",
    "module_build_id",
    "module_exports",
    "module_params",
)


def module_build_id(mod: Object) -> str:
    """
    Return the build ID (as a hex string) for this module.

    :param mod: Object of ``struct module *``
    :returns: Build ID as hex string
    """
    prog = mod.prog_
    notes_attrs = mod.notes_attrs

    if hasattr(notes_attrs, "grp"):
        # In 6.14, 4723f16de64e1 ("module: sysfs: Add notes attributes through
        # attribute_group") changes the storage to use an attribute, and the
        # array here is null-terminated.
        def attrs():
            attr = notes_attrs.grp.bin_attrs[0]
            while attr:
                yield attr
                attr += 1

    else:
        # Pre-6.14, there was an array with an explicit length.
        def attrs():
            for i in range(notes_attrs.notes.value_()):
                yield notes_attrs.attrs[i]

    for attr in attrs():
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
    """Name of the parameter"""
    kernel_param: Object
    """The ``struct kernel_param *`` of this parameter"""
    type_name: str
    """Type name (e.g. byte, short, uint)"""
    value: Optional[Object]
    """If possible, the parameter's decoded value"""


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
        # The "kp.arr.num" is a pointer into the module, at an integer variable
        # which stores the number of elements of the array. If the array itself
        # is initdata, then it's likely that this integer is also initdata, so
        # we need to be prepared to handle this FaultError. There is a "max"
        # field we could substitute with.
        length = None
        if kp.arr.num:
            try:
                length = int(kp.arr.num[0])
            except FaultError:
                pass
        if length is None:
            length = int(kp.arr.max)
        # Be cautious and ensure no accidantal negative number was used
        length = max(0, length)
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


class KernelModule:
    """
    Provides a more "object-oriented" interface to the module helpers.

    This class wraps an object of type ``struct module *``, and adds methods
    which can be used to interact with it. For example:

    >>> km = KernelModule.find(prog, "nf_nat")
    >>> km
    KernelModule(nf_nat)
    >>> km.address_regions()
    [(Object(prog, 'void *', address=0xffffffffc0878688), 0)]
    >>> KernelModule(prog.module("nf_nat"))
    KernelModule(nf_nat)
    >>> KernelModule(prog.module(0xffffffffc087207b))
    KernelModule(nf_nat)
    """

    name: str
    obj: Object
    mod: Module

    @classmethod
    def all(cls, prog: Program) -> Iterable["KernelModule"]:
        """
        Get an iterator of KernelModule helpers for each loaded module

        :param prog: Program being debugged
        :returns: Iterable of kernel module helpers
        """
        for m in prog.modules():
            if isinstance(m, RelocatableModule):
                yield KernelModule(m)

    @classmethod
    def find(cls, prog: Program, name: str) -> Optional["KernelModule"]:
        """
        Return a KernelModule helper for ``name`` if present

        :param prog: Program being debugged
        :returns: Iterable of kernel module helpers
        """
        try:
            return KernelModule(prog.module(name))
        except LookupError:
            return None

    def __init__(self, obj: Union[Object, Module]):
        if isinstance(obj, Object):
            self.obj = obj
            self.mod = obj.prog_.linux_kernel_loadable_module(obj)
        elif isinstance(obj, RelocatableModule):
            self.mod = obj
            self.obj = self.mod.object
        else:
            raise TypeError("Either a struct module * or Module is required")
        self.name = escape_ascii_string(
            self.obj.name.string_(), escape_backslash=True
        )

    def __repr__(self) -> str:
        return f"KernelModule({self.name})"

    def __str__(self) -> str:
        return repr(self)

    def have_debuginfo(self) -> bool:
        """
        Determine whether debuginfo is loaded for this module.

        :returns: True if debuginfo exists for this module
        """
        if self.obj.prog_.cache.get("using_ctf") and not self.is_oot():
            return True
        return self.mod.debug_file_status != ModuleFileStatus.WANT

    def address_regions(self) -> List[Tuple[int, int]]:
        """
        Return the core region of the module. See
        :func:`module_address_region()`.

        :returns: Layout of the "core" (non-init) region
        """
        return module_address_regions(self.obj)

    def mem_usage(self) -> int:
        """
        Return the sum of the memory usage of this module.
        """
        return sum(r[1] for r in self.address_regions())

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

    def exports(self) -> List[Tuple[int, str]]:
        """
        Return a list of exported (with or without GPL) symbol name & address
        """
        return module_exports(self.obj)

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


def ensure_debuginfo(prog: Program, modules: List[str]) -> Optional[str]:
    """
    Ensure that the modules listed are loaded in the kernel and have
    debuginfo available. If the modules are not present in the kernel or
    the debuginfo cannot be loaded, return an error message.
    """
    mods = []
    missing = []
    for modname in modules:
        try:
            module = prog.module(modname)
            mods.append(module)
        except LookupError:
            missing.append(modname)
    if missing:
        return "error: the following modules are not loaded: " + ", ".join(
            missing
        )
    prog.load_module_debug_info(*mods)
    for mod in mods:
        if mod.wants_debug_file():
            missing.append(mod.name)
    if missing:
        return "error: could not find debuginfo for: " + ", ".join(missing)
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
