// native/capstone_ex/src/lib.rs

use crate::arch::x86::ArchMode;
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
    let insns = match cs.disasm_all(code.as_slice(), 0x1000) {
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
        insn_map = insn_map
            .map_put("op_str".encode(env), i.op_str().unwrap_or("").encode(env))
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
