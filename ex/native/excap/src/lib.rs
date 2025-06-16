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
    }
}

#[rustler::nif]
fn disassemble<'a>(
    env: Env<'a>,
    code: Binary,
    arch_atom: Atom,
    _mode_atom: Atom,
    base: u64,
) -> NifResult<Term<'a>> {
    // 1. Convert Elixir atoms to Capstone enums
    let cs = match arch_atom.to_term(env).atom_to_string().as_deref() {
        Ok("x86") => Capstone::new().x86().mode(ArchMode::Mode16),
        _ => return Ok((atoms::error(), "unsupported_architecture").encode(env)),
    };

    // 2. Initialize Capstone
    let cs = cs
        .detail(true) // We'll ask for details, though we won't use them all yet
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
            .map_put("address".encode(env), i.address().encode(env))
            .unwrap();
        insn_map = insn_map
            .map_put(
                "mnemonic".encode(env),
                i.mnemonic().unwrap_or("").encode(env),
            )
            .unwrap();

        // 5. Get instruction details and build a list of structured operands
        let mut operands_list: Vec<Term<'a>> = Vec::new();

        // The detail struct is owned by the Capstone instance, not the instruction
        if let Ok(detail) = cs.insn_detail(i) {
            let arch_detail = detail.arch_detail();
            if let X86Detail(x86) = arch_detail {
                //println!("{:?}", x86.operands());
                for op in x86.operands() {
                    let mut op_map = rustler::types::map::map_new(env);
                    match op.op_type {
                        X86OperandType::Reg(reg) => {
                            op_map = op_map
                                .map_put("type".encode(env), "reg".encode(env))
                                .unwrap();
                            op_map = op_map
                                .map_put(
                                    "reg".encode(env),
                                    cs.reg_name(reg).unwrap_or("".to_string()).encode(env),
                                )
                                .unwrap();
                        }
                        X86OperandType::Imm(imm) => {
                            op_map = op_map
                                .map_put("type".encode(env), "imm".encode(env))
                                .unwrap();
                            op_map = op_map
                                .map_put("value".encode(env), imm.encode(env))
                                .unwrap();
                        }
                        X86OperandType::Mem(mem) => {
                            op_map = op_map
                                .map_put("type".encode(env), "mem".encode(env))
                                .unwrap();
                            if let Some(base_reg) = cs.reg_name(mem.base()) {
                                op_map = op_map
                                    .map_put("base".encode(env), base_reg.encode(env))
                                    .unwrap();
                            }
                            if let Some(index_reg) = cs.reg_name(mem.index()) {
                                op_map = op_map
                                    .map_put("index".encode(env), index_reg.encode(env))
                                    .unwrap();
                            }
                            if mem.scale() != 1 {
                                // Only include scale if it's not the default
                                op_map = op_map
                                    .map_put("scale".encode(env), mem.scale().encode(env))
                                    .unwrap();
                            }
                            if mem.disp() != 0 {
                                // Only include displacement if non-zero
                                op_map = op_map
                                    .map_put("disp".encode(env), mem.disp().encode(env))
                                    .unwrap();
                            }
                        }
                        _ => {
                            // Handle other operand types like FP if necessary
                            op_map = op_map
                                .map_put("type".encode(env), "other".encode(env))
                                .unwrap();
                        }
                    }
                    operands_list.push(op_map);
                }
            }
        }

        // Add the list of operand maps to the main instruction map

        println!("{:?}", operands_list);
        insn_map = insn_map
            .map_put("operands".encode(env), operands_list.encode(env))
            .unwrap();

        let bytes_slice = i.bytes();
        let mut owned_binary = OwnedBinary::new(bytes_slice.len()).unwrap();
        owned_binary.as_mut_slice().copy_from_slice(bytes_slice);
        insn_map = insn_map
            .map_put("bytes".encode(env), owned_binary.release(env).encode(env))
            .unwrap();
        result_list.push(insn_map);
    }

    Ok((atoms::ok(), result_list).encode(env))
}

// Register the NIF with Erlang
rustler::init!("Elixir.CapstoneEx.Native", [disassemble]);
