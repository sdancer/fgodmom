// native/capstone_ex/src/lib.rs

use crate::ArchDetail::X86Detail;
use crate::arch::x86::ArchMode;
use capstone::arch::x86::X86InsnDetail;
use capstone::arch::x86::X86OperandType;
use capstone::prelude::*;
use rustler::{Atom, Binary, Encoder, Env, NifResult, OwnedBinary, Term};

mod atoms {
    rustler::atoms! {
        // Common return values
        ok,
        error,

        // Architectures
        x86,
        arm,
        arm64,

        // Modes
        mode16,
        mode32,
        mode64,
        mode_arm,
        mode_thumb,

        // --- Atoms for map keys and values ---
        // Instruction map keys
        address,
        mnemonic,
        operands,
        bytes,

        // Operand map keys
        op_type, // `type` is a Rust keyword
        reg,    // Also used as a value
        value,
        base,
        index,
        scale,
        disp,
        segment, // --- ADDED: Atom for the segment register ---

        // Operand type values
        imm,
        mem,
        other,
    }
}

#[rustler::nif]
fn disassemble<'a>(
    env: Env<'a>,
    code: Binary,
    arch_atom: Atom,
    mode_atom: Atom, // --- CHANGED: Use the mode_atom parameter ---
    base: u64,
) -> NifResult<Term<'a>> {
    // 1. Convert Elixir atoms to Capstone enums
    // --- CHANGED: Properly handle architecture and mode ---
    let cs = match arch_atom.to_term(env).atom_to_string().as_deref() {
        Ok("x86") => {
            let mode = match mode_atom.to_term(env).atom_to_string().as_deref() {
                Ok("mode16") => ArchMode::Mode16,
                Ok("mode32") => ArchMode::Mode32,
                Ok("mode64") => ArchMode::Mode64,
                _ => return Ok((atoms::error(), "unsupported_x86_mode").encode(env)),
            };
            Capstone::new().x86().mode(mode)
        }
        // TODO: Add other architectures like arm, arm64
        _ => return Ok((atoms::error(), "unsupported_architecture").encode(env)),
    };

    // 2. Initialize Capstone
    let cs = cs
        .detail(true)
        .build()
        .map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;

    // 3. Disassemble the code
    let insns = match cs.disasm_all(code.as_slice(), base) {
        Ok(insns) => insns,
        Err(err) => return Ok((atoms::error(), err.to_string()).encode(env)),
    };

    // 4. Convert the result into a list of Elixir maps
    let mut result_list: Vec<Term<'a>> = Vec::new();

    for i in insns.iter() {
        let mut insn_map = rustler::types::map::map_new(env);
        insn_map = insn_map
            .map_put(atoms::address(), i.address().encode(env))
            .unwrap();
        insn_map = insn_map
            .map_put(
                atoms::mnemonic(),
                i.mnemonic().unwrap_or("").encode(env),
            )
            .unwrap();

        // 5. Get instruction details and build a list of structured operands
        let mut operands_list: Vec<Term<'a>> = Vec::new();

        if let Ok(detail) = cs.insn_detail(i) {
            let arch_detail = detail.arch_detail();
            if let X86Detail(x86) = arch_detail {
                for op in x86.operands() {
                    let mut op_map = rustler::types::map::map_new(env);
                    match op.op_type {
                        X86OperandType::Reg(reg) => {
                            op_map = op_map.map_put(atoms::op_type(), atoms::reg()).unwrap();
                            op_map = op_map
                                .map_put(
                                    atoms::reg(),
                                    cs.reg_name(reg).unwrap_or("".to_string()).encode(env),
                                )
                                .unwrap();
                        }
                        X86OperandType::Imm(imm) => {
                            op_map = op_map.map_put(atoms::op_type(), atoms::imm()).unwrap();
                            op_map = op_map
                                .map_put(atoms::value(), imm.encode(env))
                                .unwrap();
                        }
                        X86OperandType::Mem(mem) => {
                            op_map = op_map.map_put(atoms::op_type(), atoms::mem()).unwrap();

                            // --- ADDED: Handle segment override ---
                            let segment_reg = mem.segment();
                            // reg_name() returns None for invalid/default registers, which is perfect.
                            if let Some(segment_name) = cs.reg_name(segment_reg) {
                                op_map = op_map
                                    .map_put(atoms::segment(), segment_name.encode(env))
                                    .unwrap();
                            }

                            if let Some(base_reg) = cs.reg_name(mem.base()) {
                                op_map = op_map
                                    .map_put(atoms::base(), base_reg.encode(env))
                                    .unwrap();
                            }
                            if let Some(index_reg) = cs.reg_name(mem.index()) {
                                op_map = op_map
                                    .map_put(atoms::index(), index_reg.encode(env))
                                    .unwrap();
                            }
                            if mem.scale() != 1 {
                                op_map = op_map
                                    .map_put(atoms::scale(), mem.scale().encode(env))
                                    .unwrap();
                            }
                            if mem.disp() != 0 {
                                op_map = op_map
                                    .map_put(atoms::disp(), mem.disp().encode(env))
                                    .unwrap();
                            }
                        }
                        _ => {
                            op_map = op_map.map_put(atoms::op_type(), atoms::other()).unwrap();
                        }
                    }
                    operands_list.push(op_map);
                }
            }
        }

        insn_map = insn_map
            .map_put(atoms::operands(), operands_list.encode(env))
            .unwrap();

        let bytes_slice = i.bytes();
        let mut owned_binary = OwnedBinary::new(bytes_slice.len()).unwrap();
        owned_binary.as_mut_slice().copy_from_slice(bytes_slice);

        insn_map = insn_map
            .map_put(atoms::bytes(), owned_binary.release(env).encode(env))
            .unwrap();
        result_list.push(insn_map);
    }

    Ok((atoms::ok(), result_list).encode(env))
}

// Register the NIF with Erlang
rustler::init!("Elixir.CapstoneEx.Native", [disassemble]);
