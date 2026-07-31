from __future__ import annotations

import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / ".tools"))

import pefile  # type: ignore[import-not-found]
from triton import (  # type: ignore[import-not-found]
    ARCH,
    CPUSIZE,
    Instruction,
    MemoryAccess,
    MODE,
    TritonContext,
)

from solve_password import derive_required_fnv


FUNCTIONS = [
    0x004028B0,
    0x00402D80,
    0x00403250,
    0x004033A0,
    0x00403410,
    0x00403480,
    0x00403500,
    0x00403570,
    0x004035E0,
    0x00403650,
    0x00402910,
    0x00402980,
    0x004029F0,
    0x00402A60,
    0x00402AD0,
    0x00402B40,
    0x00402BB0,
    0x00402C20,
    0x00402C90,
    0x00402D10,
    0x00402DF0,
    0x00402E60,
    0x00402ED0,
    0x00402F40,
    0x00402FB0,
    0x00403020,
    0x00403090,
    0x00403100,
    0x00403170,
    0x004031E0,
    0x004032C0,
    0x00403330,
]

TARGET_TABLE = 0x00404320
IMAGE_BASE = 0x00400000
STACK = 0x10000000
CONTEXT = 0x20000000
PASSWORD = 0x30000000
STOP = 0xDEADC0DE
INTEGRITY_KEY = 0xDE2F567F
CONTEXT_XOR = 0x30D2A80B


def u32(value: int) -> int:
    return value & 0xFFFFFFFF


def load_image(pe: pefile.PE) -> bytes:
    return pe.get_memory_mapped_image(ImageBase=IMAGE_BASE)


def execute_function(ctx: TritonContext, address: int) -> None:
    ctx.setConcreteRegisterValue(ctx.registers.eip, address)
    for _ in range(256):
        pc = ctx.getConcreteRegisterValue(ctx.registers.eip)
        if pc == STOP:
            return
        opcode = bytes(ctx.getConcreteMemoryAreaValue(pc, 16))
        inst = Instruction(pc, opcode)
        ctx.processing(inst)
        if inst.getDisassembly().startswith("ret"):
            return
    raise RuntimeError(f"Function 0x{address:08X} did not return")


def recover_for_length(pe: pefile.PE, length: int, timeout_ms: int = 60000) -> str | None:
    required_fnv = derive_required_fnv(pe)
    target_values = [
        struct.unpack("<I", pe.get_data(TARGET_TABLE - IMAGE_BASE + index * 4, 4))[0]
        for index in range(32)
    ]
    image = load_image(pe)
    ctx = TritonContext(ARCH.X86)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setConcreteMemoryAreaValue(IMAGE_BASE, image)
    ctx.setConcreteMemoryAreaValue(PASSWORD, b"A" * max(length, 32))

    fixed_context = [
        PASSWORD,
        length,
        INTEGRITY_KEY,
        required_fnv,
        1,
        0,
        required_fnv ^ INTEGRITY_KEY ^ CONTEXT_XOR,
    ]
    ctx.setConcreteMemoryAreaValue(CONTEXT, struct.pack("<7I", *fixed_context))

    custom_var = ctx.symbolizeMemory(MemoryAccess(CONTEXT + 16, CPUSIZE.DWORD), "custom_hash")
    loader_var = ctx.symbolizeMemory(MemoryAccess(CONTEXT + 20, CPUSIZE.DWORD), "loader_value")
    char_vars = [
        ctx.symbolizeMemory(MemoryAccess(PASSWORD + index, CPUSIZE.BYTE), f"char_{index}")
        for index in range(length)
    ]

    ast = ctx.getAstContext()
    constraints = []
    for variable in char_vars:
        node = ast.variable(variable)
        constraints.append(ast.bvuge(node, ast.bv(0x20, 8)))
        constraints.append(ast.bvule(node, ast.bv(0x7E, 8)))

    for index, function in enumerate(FUNCTIONS):
        ctx.concretizeAllRegister()
        ctx.clearPathConstraints()
        ctx.setConcreteRegisterValue(ctx.registers.esp, STACK)
        ctx.setConcreteMemoryAreaValue(STACK, struct.pack("<II", STOP, CONTEXT))
        execute_function(ctx, function)
        target = target_values[index]
        constraints.append(ast.equal(ctx.getRegisterAst(ctx.registers.eax), ast.bv(target, 32)))

    query = ast.land(constraints)
    model, status, solving_time = ctx.getModel(query, True, timeout_ms)
    print(f"length {length}: {status}, {solving_time} ms", flush=True)
    if not model:
        return None

    by_id = {entry.getVariable().getId(): entry.getValue() for entry in model.values()}
    custom_value = by_id.get(custom_var.getId())
    loader_value = by_id.get(loader_var.getId())
    chars = bytes(by_id.get(variable.getId(), ord("?")) for variable in char_vars)
    print(f"  custom_hash=0x{custom_value:08X}" if custom_value is not None else "  custom_hash=?")
    print(f"  loader_value=0x{loader_value:08X}" if loader_value is not None else "  loader_value=?")
    return chars.decode("ascii")


def main() -> None:
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    end = int(sys.argv[2]) if len(sys.argv) > 2 else 32
    for length in range(start, end + 1):
        pe = pefile.PE(str(ROOT / "crackme.exe"))
        password = recover_for_length(pe, length)
        pe.close()
        if password is not None:
            print(f"candidate: {password}", flush=True)
            return
    print("candidate: not found", flush=True)


if __name__ == "__main__":
    main()
