import struct
from unicorn import *
from unicorn.x86_const import *

# --- Configuration ---
FILENAME = "fgodmom.exe"

# --- Global Variables for Unicorn State Tracking ---
# Based on Ghidra's analysis of fgodmom.exe (CS=0x26F6, e_cs=0x16F6),
# the program is loaded at a base segment that results in the observed CS.
# Load base segment = Observed CS - e_cs = 0x26F6 - 0x16F6 = 0x1000.
# Physical address = segment * 16. So, 0x1000 * 16 = 0x10000.
LOAD_BASE_PARAGRAPH = 0x1000
LOAD_CODE_PHYSICAL_BASE = LOAD_BASE_PARAGRAPH * 16

UNPACKED_EXE_DUMPED = False # Flag to indicate if the EXE has been dumped

# --- MZ Header Offsets (Standard DOS EXE) ---
MZ_E_MAGIC_OFFSET = 0x00
MZ_E_CBLP_OFFSET = 0x02    # Bytes on last page
MZ_E_CP_OFFSET = 0x04      # Pages in file
MZ_E_CPARHDR_OFFSET = 0x08 # Size of header in paragraphs
MZ_E_MINALLOC_OFFSET = 0x0A # Minimum extra paragraphs needed
MZ_E_MAXALLOC_OFFSET = 0x0C # Maximum extra paragraphs needed
MZ_E_SS_OFFSET = 0x0E      # Initial (relative) SS value
MZ_E_SP_OFFSET = 0x10      # Initial SP value
MZ_E_IP_OFFSET = 0x14      # Initial IP value
MZ_E_CS_OFFSET = 0x16      # Initial (relative) CS value
MZ_E_LFARLC_OFFSET = 0x1C  # File address of relocation table (used for LZ91 marker)

# --- LZEXE Header Offsets (relative to CS:0000 after load) ---
# These values will be read from the LZEXE header *in memory* at the time of final jump.
LZEXE_REAL_IP_OFFSET = 0x00
LZEXE_REAL_CS_OFFSET = 0x02
LZEXE_REAL_SP_OFFSET = 0x04
LZEXE_REAL_SS_OFFSET = 0x06
# These are read from the LZEXE header *in the original file*
LZEXE_COMPRESSED_SIZE_PARAGRAPHS_OFFSET = 0x08
LZEXE_ADDITIONAL_SIZE_PARAGRAPHS_OFFSET = 0x0A
LZEXE_DECOMPRESSOR_CODE_SIZE_BYTES_OFFSET = 0x0C

# --- Unicorn Hooks ---

def hook_code(uc, address, size, user_data):
    """
    Hook for instructions to detect the final JMPF and dump the unpacked EXE.
    """
    global UNPACKED_EXE_DUMPED
    
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    physical_address = current_cs * 16 + current_ip

    # The final JMPF instruction is at a specific offset within the decompressor's segment.
    # The user_data['final_jmp_addr'] is pre-calculated to hit this exact instruction.
    if physical_address == user_data['final_jmp_addr'] and not UNPACKED_EXE_DUMPED:
        return 
 

def hook_mem_unmapped(uc, access, address, size, value, user_data):
    """
    Hook for debugging unmapped memory access errors.
    """
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    
    access_type = "READ" if access == UC_MEM_READ_UNMAPPED else \
                  "WRITE" if access == UC_MEM_WRITE_UNMAPPED else \
                  "FETCH" if access == UC_MEM_FETCH_UNMAPPED else "UNKNOWN"

    print(f"[*] UC_MEM_{access_type}_UNMAPPED at CS:IP={hex(current_cs)}:{hex(current_ip)}:")
    print(f"    Attempted access to 0x{address:X} (size {size})")
    if access == UC_MEM_WRITE_UNMAPPED:
        print(f"    Value: {value:X}")
    
    # Print more registers for debugging
    print(f"    EFLAGS: {hex(uc.reg_read(UC_X86_REG_EFLAGS))}")
    print(f"    AX: {hex(uc.reg_read(UC_X86_REG_AX))}, BX: {hex(uc.reg_read(UC_X86_REG_BX))}, CX: {hex(uc.reg_read(UC_X86_REG_CX))}, DX: {hex(uc.reg_read(UC_X86_REG_DX))}")
    print(f"    SI: {hex(uc.reg_read(UC_X86_REG_SI))}, DI: {hex(uc.reg_6read(UC_X86_REG_DI))}, BP: {hex(uc.reg_read(UC_X86_REG_BP))}")
    print(f"    DS: {hex(uc.reg_read(UC_X86_REG_DS))}, ES: {hex(uc.reg_read(UC_X86_REG_ES))}, SS: {hex(uc.reg_read(UC_X86_REG_SS))}, SP: {hex(uc.reg_read(UC_X86_REG_SP))}")
    
    return False # Return False to let Unicorn raise the error and stop emulation

def hook_interrupt(uc, intno, user_data):
    """
    Hook for handling DOS interrupts.
    """
    if intno == 0x21:
        ah = uc.reg_read(UC_X86_REG_AH)
        if ah == 0x4C: # DOS function: Terminate with return code
            print(f"[*] INT 21h, AH=4Ch (Terminate Program) detected. Stopping emulation.")
            uc.emu_stop()
        elif ah == 0x09: # DOS function: Print string
            dx = uc.reg_read(UC_X86_REG_DX)
            ds = uc.reg_read(UC_X86_REG_DS)
            try:
                # Read string until '$' (0x24) terminator
                addr = ds * 16 + dx
                s = b""
                while True:
                    byte = uc.mem_read(addr, 1)
                    if byte[0] == 0x24: # '$' terminator
                        break
                    s += byte
                    addr += 1
                print(f"[*] INT 21h, AH=09h (Print String): {s.decode('ascii', errors='ignore')}")
            except UcError:
                print(f"[*] INT 21h, AH=09h (Print String): Failed to read string from {hex(ds)}:{hex(dx)}")
            except Exception as e:
                print(f"[*] INT 21h, AH=09h (Print String): Unexpected error: {e}")
        else:
            print(f"[*] Unhandled INT 21h function: AH={hex(ah)}. Continuing emulation.")
    else:
        print(f"[*] Unhandled interrupt: {hex(intno)}. Stopping emulation.")
        uc.emu_stop()
    

# --- Main Extraction Function ---

def extract_lz91_exe(filename):
    global UNPACKED_EXE_DUMPED

    try:
        with open(filename, 'rb') as f:
            file_content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return

    file_size = len(file_content)
    print(f"[*] Analyzing '{filename}', size: {file_size} bytes")

    # Parse MZ header from file content
    mz_header_file = file_content[0:0x40] # Read enough to cover all relevant fields
    
    e_magic = struct.unpack("<H", mz_header_file[MZ_E_MAGIC_OFFSET:MZ_E_MAGIC_OFFSET+2])[0]
    if e_magic != 0x5A4D: # "MZ"
        print(f"Error: Not a valid MZ executable (magic: {hex(e_magic)})")
        return

    e_cparhdr = struct.unpack("<H", mz_header_file[MZ_E_CPARHDR_OFFSET:MZ_E_CPARHDR_OFFSET+2])[0]
    e_cs_initial_header_val = struct.unpack("<H", mz_header_file[MZ_E_CS_OFFSET:MZ_E_CS_OFFSET+2])[0]
    e_ip_initial_header_val = struct.unpack("<H", mz_header_file[MZ_E_IP_OFFSET:MZ_E_IP_OFFSET+2])[0]
    e_ss_initial_header_val = struct.unpack("<H", mz_header_file[MZ_E_SS_OFFSET:MZ_E_SS_OFFSET+2])[0]
    e_sp_initial_header_val = struct.unpack("<H", mz_header_file[MZ_E_SP_OFFSET:MZ_E_SP_OFFSET+2])[0]

    print(f"[*] MZ Header values (from original file):")
    print(f"    e_cparhdr: {e_cparhdr} ({e_cparhdr * 16} bytes)")
    print(f"    e_cs: {hex(e_cs_initial_header_val)}, e_ip: {hex(e_ip_initial_header_val)}")
    print(f"    e_ss: {hex(e_ss_initial_header_val)}, e_sp: {hex(e_sp_initial_header_val)}")

    # Check LZ91 marker at 0x1C (e_lfarlc position)
    lz91_marker = mz_header_file[MZ_E_LFARLC_OFFSET:MZ_E_LFARLC_OFFSET+4]
    if lz91_marker == b'LZ91':
        print(f"[*] LZ91 marker 'LZ91' found at 0x{MZ_E_LFARLC_OFFSET:X}.")
    else:
        print(f"[*] LZ91 marker not found at 0x{MZ_E_LFARLC_OFFSET:X}. Found: {lz91_marker}. This might not be LZEXE.")

    # Calculate where the executable code/data actually starts in the file
    exe_start_offset_in_file = e_cparhdr * 16
    
    # Read LZEXE header from file content (it's the first 14 bytes after MZ header)
    lzexe_header_file = file_content[exe_start_offset_in_file : exe_start_offset_in_file + 14]
    
    lzexe_additional_size_pgphs = struct.unpack("<H", lzexe_header_file[LZEXE_ADDITIONAL_SIZE_PARAGRAPHS_OFFSET:LZEXE_ADDITIONAL_SIZE_PARAGRAPHS_OFFSET+2])[0]
    lzexe_decompressor_code_size_bytes = struct.unpack("<H", lzexe_header_file[LZEXE_DECOMPRESSOR_CODE_SIZE_BYTES_OFFSET:LZEXE_DECOMPRESSOR_CODE_SIZE_BYTES_OFFSET+2])[0]

    print(f"[*] LZEXE Header values (from original file):")
    print(f"    Additional Size (pgphs): {hex(lzexe_additional_size_pgphs)}")
    print(f"    Decompressor Code Size (bytes): {hex(lzexe_decompressor_code_size_bytes)}")


    # Initialize Unicorn Engine for x86 16-bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_16)

    # Map a 1MB contiguous region of memory for DOS conventional memory
    TOTAL_MEM_SIZE = 0x100000 
    mu.mem_map(0, TOTAL_MEM_SIZE, UC_PROT_ALL)
    print(f"[*] Mapped total memory from 0x0 to {hex(TOTAL_MEM_SIZE)} ({TOTAL_MEM_SIZE // 1024} KB).")

    # Load the executable content *after* the MZ header into memory
    # The program is loaded at LOAD_CODE_PHYSICAL_BASE (0x10000).
    mu.mem_write(LOAD_CODE_PHYSICAL_BASE, file_content[exe_start_offset_in_file:])
    print(f"[*] Loaded executable content from file offset {hex(exe_start_offset_in_file)} at physical address {hex(LOAD_CODE_PHYSICAL_BASE)}.")
    
    # Set up initial registers for the loader stub as DOS would.
    # The PSP is 0x10 paragraphs below the program's load base segment.
    psp_segment = LOAD_BASE_PARAGRAPH - 0x10 

    # Initial CS value in the MZ header (e_cs) is relative to the load base.
    # The actual CS register value will be LOAD_BASE_PARAGRAPH + e_cs.
    initial_cs_segment_actual = LOAD_BASE_PARAGRAPH + e_cs_initial_header_val
    initial_ip_offset_actual = e_ip_initial_header_val
    initial_ss_segment_actual = LOAD_BASE_PARAGRAPH + e_ss_initial_header_val
    initial_sp_offset_actual = e_sp_initial_header_val

    mu.reg_write(UC_X86_REG_CS, initial_cs_segment_actual) 
    mu.reg_write(UC_X86_REG_IP, initial_ip_offset_actual) 
    mu.reg_write(UC_X86_REG_SS, initial_ss_segment_actual) 
    mu.reg_write(UC_X86_REG_SP, initial_sp_offset_actual) 
    mu.reg_write(UC_X86_REG_DS, psp_segment) # DS and ES always point to PSP initially
    mu.reg_write(UC_X86_REG_ES, psp_segment) 

    # Set direction flag to clear (CLD). The program explicitly sets STD later.
    mu.reg_write(UC_X86_REG_EFLAGS, 0x202) # Set bit 9 (IF) and bit 1 (reserved). DF=0.

    print(f"[*] Initial Registers (as DOS would set them):")
    print(f"    CS:IP = {hex(mu.reg_read(UC_X86_REG_CS))}:{hex(mu.reg_read(UC_X86_REG_IP))}")
    print(f"    SS:SP = {hex(mu.reg_read(UC_X86_REG_SS))}:{hex(mu.reg_read(UC_X86_REG_SP))}")
    print(f"    DS:ES (PSP Segment): {hex(psp_segment)}")
    print(f"    Physical start address: {hex(mu.reg_read(UC_X86_REG_CS) * 16 + mu.reg_read(UC_X86_REG_IP))}")
    
    # Calculate the address of the final JMPF instruction
    # The decompressor copies itself to: (initial_CS_segment_actual + lzexe_additional_size_pgphs)
    # The final JMPF (from Ghidra's 4000:0ab5) is at offset 0xAB5 relative to the base of this *new* segment.
    new_decompressor_segment = initial_cs_segment_actual + lzexe_additional_size_pgphs
    FINAL_JMPF_OFFSET_IN_SEGMENT = 0xab5 
    final_jmp_physical_addr = 0x4000 * 16 + FINAL_JMPF_OFFSET_IN_SEGMENT
    print(f"[*] Calculated final JMPF hook address: {hex(final_jmp_physical_addr)}")

    # Add hooks
    # Hook just the jmpf instruction. A JMPF is 3 bytes (opcode + segment:offset).
    mu.hook_add(UC_HOOK_CODE, hook_code, begin=final_jmp_physical_addr, end=final_jmp_physical_addr + 3, user_data={'final_jmp_addr': final_jmp_physical_addr})
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_INTR, hook_interrupt) # Hook for INT instructions (like INT 21h)

    try:
        # Emulate until the program either stops itself (INT 21h, AH=4Ch)
        # or the final JMPF is hit (which triggers the dump and stops emulation).
        mu.emu_start(mu.reg_read(UC_X86_REG_CS) * 16 + mu.reg_read(UC_X86_REG_IP), 
                     TOTAL_MEM_SIZE, 
                     timeout=0,      # No timeout, runs until stop or error
                     count=50000000) # Max 50 million instructions, a safe upper bound
        print("[*] Emulation finished (possibly due to instruction count or exit hook).")

    except UcError as e:
        print(f"[*] Emulation stopped with error: {e}")
        # Print registers for debugging if not already handled by a specific hook
        if not str(e).startswith("UC_ERR_MEM_UNMAPPED"):
            print(f"    CS:IP = {hex(mu.reg_read(UC_X86_REG_CS))}:{hex(mu.reg_read(UC_X86_REG_IP))}")
            print(f"    EFLAGS: {hex(mu.reg_read(UC_X86_REG_EFLAGS))}")
            print(f"    AX: {hex(mu.reg_read(UC_X86_REG_AX))}, BX: {hex(mu.reg_read(UC_X86_REG_BX))}, CX: {hex(mu.reg_read(UC_X86_REG_CX))}, DX: {hex(mu.reg_read(UC_X86_REG_DX))}")
            print(f"    SI: {hex(mu.reg_read(UC_X86_REG_SI))}, DI: {hex(mu.reg_read(UC_X86_REG_DI))}, BP: {hex(mu.reg_read(UC_X86_REG_BP))}")
            print(f"    DS: {hex(mu.reg_read(UC_X86_REG_DS))}, ES: {hex(mu.reg_read(UC_X86_REG_ES))}, SS: {hex(mu.reg_read(UC_X86_REG_SS))}, SP: {hex(mu.reg_read(UC_X86_REG_SP))}")

    if not UNPACKED_EXE_DUMPED:
        print("[!] Unpacked EXE was not dumped. Check emulation log for errors or unhandled conditions.")

# --- Script Execution ---
if __name__ == "__main__":
    extract_lz91_exe(FILENAME)
