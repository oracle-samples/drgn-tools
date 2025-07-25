# Copyright (c) 2024-2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from textwrap import fill
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Tuple

from drgn import cast
from drgn import FaultError
from drgn import Module
from drgn import Object
from drgn import Program
from drgn import ProgramFlags
from drgn import RelocatableModule
from drgn import sizeof

from drgn_tools.taint import Taint


__all__ = (
    "ParamInfo",
    "ModuleLoadSummary",
    "ensure_debuginfo",
    "get_module_load_summary",
    "module_exports",
    "module_is_in_tree",
    "module_is_ksplice_cold_patch",
    "module_params",
)


def module_is_ksplice_cold_patch(module: RelocatableModule) -> bool:
    # Normally, ksplice modules are live patches, which are loaded into the
    # kernel and patch the already loaded code. For patched kernel modules,
    # ksplices may also contain a "cold-patched" module which is a new copy of
    # the module with the updated code, avoiding the need to live-patch if the
    # module is not yet loaded. The downside is that these are new build
    # artifacts with different build IDs. The packaged debuginfo does not apply
    # to them, and drgn rightly rejects them.
    return "__tripwire_table" in module.section_addresses


def module_is_in_tree(module: Module) -> bool:
    return (
        module.prog.flags & ProgramFlags.IS_LINUX_KERNEL
        and isinstance(module, RelocatableModule)
        and not (module.object.taints & (1 << Taint.OOT_MODULE))
        and not module_is_ksplice_cold_patch(module)
    )


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


def _decode_param(kp: Object) -> ParamInfo:
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
        info = _decode_param(mod.kp[i])
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
    ksplice_mods: List[RelocatableModule]
    ksplice_cold_patch_mods: List[RelocatableModule]
    other_oot: List[RelocatableModule]
    loaded_mods: List[RelocatableModule]
    missing_mods: List[RelocatableModule]

    def __str__(self) -> str:
        text = f"{self.total_mods} kernel modules are loaded: "
        details = []
        if self.ksplice_mods:
            details.append(f"{len(self.ksplice_mods)} are ksplices")
        if self.ksplice_cold_patch_mods:
            details.append(
                f"{len(self.ksplice_cold_patch_mods)} are cold-patched "
                "ksplice modules"
            )
        if self.other_oot:
            details.append(
                f"{len(self.other_oot)} are other out-of-tree modules"
            )
        if self.loaded_mods:
            details.append(f"{len(self.loaded_mods)} have debuginfo")
        # it's nice to have confirmation, regardless of whether it is 0
        details.append(f"{len(self.missing_mods)} are missing debuginfo")
        return text + ", ".join(details)

    def verbose_str(self, width: int = 80) -> str:
        lines = [f"{self.total_mods} kernel_modules are loaded."]

        def add(mods: List[RelocatableModule], kind: str) -> None:
            if not mods:
                return
            lines.append(f"{len(mods)} are {kind}:")
            lines.append(
                fill(
                    " ".join(sorted(m.name for m in mods)),
                    width=(width - 4),
                    initial_indent="    ",
                    subsequent_indent="    ",
                )
            )

        add(self.loaded_mods, "in-tree with debuginfo")
        add(self.missing_mods, "in-tree, but missing debuginfo")
        add(self.ksplice_mods, "ksplice patches")
        add(self.ksplice_cold_patch_mods, "ksplice cold-patched modules")
        add(self.other_oot, "other out-of-tree modules")
        return "\n".join(lines)

    def all_mods(self) -> List[RelocatableModule]:
        return (
            self.ksplice_mods
            + self.ksplice_cold_patch_mods
            + self.other_oot
            + self.loaded_mods
            + self.missing_mods
        )


def get_module_load_summary(prog: Program) -> ModuleLoadSummary:
    """
    Compute the current status of all kernel modules.
    """
    total_mods = 0
    ksplice_mods = []
    ksplice_cold_patch_mods = []
    other_oot = []
    loaded_mods = []
    missing_mods = []
    using_ctf = prog.cache.get("using_ctf")
    for mod in prog.modules():
        if not isinstance(mod, RelocatableModule):
            continue
        total_mods += 1
        if module_is_in_tree(mod):
            if mod.wants_debug_file() and not using_ctf:
                missing_mods.append(mod)
            else:
                loaded_mods.append(mod)
        elif mod.name.startswith("ksplice"):
            ksplice_mods.append(mod)
        elif module_is_ksplice_cold_patch(mod):
            ksplice_cold_patch_mods.append(mod)
        else:
            other_oot.append(mod)
    return ModuleLoadSummary(
        total_mods,
        ksplice_mods,
        ksplice_cold_patch_mods,
        other_oot,
        loaded_mods,
        missing_mods,
    )
