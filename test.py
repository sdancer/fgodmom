import struct
from unicorn import *
from unicorn.x86_const import *

# --- Configuration ---
FILENAME = "fgodmom.exe"

# --- Global Variables for Unicorn State Tracking ---
# Based on Ghidra's runtime analysis (CS=0x26F6, IP=0x000E) and original e_cs (0x16F6),
# the program is loaded at a base segment that results in the observed CS.
# If Observed CS (0x26F6) - e_cs (0x16F6) = 0x1000, then the load base segment is 0x1000.
# Physical address = segment * 16. So, 0x1000 * 16 = 0x10000.
LOAD_BASE_PARAGRAPH = 0x1000
LOAD_CODE_PHYSICAL_BASE = LOAD_BASE_PARAGRAPH * 16

# These will be populated by hooks during emulation
initial_copy_dest_start = 0  # Physical address where the initial decompressor copy lands
initial_copy_size = 0        # Size of the initial decompressor copy

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

# --- Unicorn Hooks ---

def hook_code(uc, address, size, user_data):
    """
    Hook for instructions to detect key decompression stages.
    """
    global initial_copy_dest_start, initial_copy_size
    
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    physical_address = current_cs * 16 + current_ip

    # Optional: Uncomment for detailed instruction trace (can be very verbose)
    try:
       ins_bytes = uc.mem_read(physical_address, size).hex()
       print(f"Executing {physical_address:X}: {ins_bytes}")
    except UcError:
       print(f"Executing {physical_address:X}: (could not read bytes)")
    
    # The instruction `MOV CX,word ptr [0xc]` is at 26f6:0011 (physical 0x26F71).
    # This reads the LZEXE header's 'Ch' field (size of decompressor).
    # DS is 0x26F6 at this point due to `PUSH CS; POP DS` earlier.
    if current_cs == 0x26F6 and current_ip == 0x11:
        ds_val = uc.reg_read(UC_X86_REG_DS)
        lzexe_header_ch_physical_addr = ds_val * 16 + 0x0C
        try:
            initial_copy_size = struct.unpack("<H", uc.mem_read(lzexe_header_ch_physical_addr, 2))[0]
            print(f"[*] MOV CX, [DS:0x0C] (physical 0x{lzexe_header_ch_physical_addr:X}) executed. CX read as {hex(initial_copy_size)} (LZEXE header Ch field).")
        except UcError as e:
            print(f"[!] Error reading LZEXE header Ch value from memory at {hex(lzexe_header_ch_physical_addr)}: {e}")
            # Fallback to hardcoded value for fgodmom.exe (0x0FD8) if read fails
            # This should ideally not be needed if memory is mapped correctly
            initial_copy_size = 0x0FD8 
            print(f"    Using hardcoded initial_copy_size: {hex(initial_copy_size)}")

    # The RETF at 26f6:002a is crucial for identifying the jump to the new decompressor copy.
    # The code pushes BX (which holds the new ES/CS segment) and AX (the new IP, 0x2B) before RETF.
    if current_cs == 0x26F6 and current_ip == 0x2A: 
        # ES was calculated as DS (original CS) + LZEXE header[Ah] (additional size for decompression).
        # For fgodmom.exe: 0x26F6 + 0x19A0 = 0x4096.
        initial_copy_dest_start = uc.reg_read(UC_X86_REG_ES) * 16 # ES should be 0x4096 by this point
        
        ss_val = uc.reg_read(UC_X86_REG_SS)
        sp_val = uc.reg_read(UC_X86_REG_SP)
        # Stack grows downwards. New IP is at SS:SP, New CS is at SS:SP+2.
        new_ip = struct.unpack("<H", uc.mem_read(ss_val * 16 + sp_val, 2))[0]
        new_cs = struct.unpack("<H", uc.mem_read(ss_val * 16 + sp_val + 2, 2))[0]
        
        print(f"[*] Reached initial RETF at {hex(current_cs)}:{hex(current_ip)}. Next CS:IP will be {hex(new_cs)}:{hex(new_ip)}.")
        print(f"[*] Initial decompressor block copied to {hex(initial_copy_dest_start)} with size {hex(initial_copy_size)}.")


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
    print(f"    SI: {hex(uc.reg_read(UC_X86_REG_SI))}, DI: {hex(uc.reg_read(UC_X86_REG_DI))}, BP: {hex(uc.reg_read(UC_X86_REG_BP))}")
    print(f"    DS: {hex(uc.reg_read(UC_X86_REG_DS))}, ES: {hex(uc.reg_read(UC_X86_REG_ES))}, SS: {hex(uc.reg_read(UC_X86_REG_SS))}, SP: {hex(uc.reg_read(UC_X86_REG_SP))}")
    
    return False # Return False to let Unicorn raise the error and stop emulation


# --- Main Extraction Function ---

def extract_lz91_exe(filename):
    global initial_copy_dest_start, initial_copy_size

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
    e_cs_initial_header = struct.unpack("<H", mz_header_file[MZ_E_CS_OFFSET:MZ_E_CS_OFFSET+2])[0]
    e_ip_initial_header = struct.unpack("<H", mz_header_file[MZ_E_IP_OFFSET:MZ_E_IP_OFFSET+2])[0]
    e_ss_initial_header = struct.unpack("<H", mz_header_file[MZ_E_SS_OFFSET:MZ_E_SS_OFFSET+2])[0]
    e_sp_initial_header = struct.unpack("<H", mz_header_file[MZ_E_SP_OFFSET:MZ_E_SP_OFFSET+2])[0]
    e_minalloc = struct.unpack("<H", mz_header_file[MZ_E_MINALLOC_OFFSET:MZ_E_MINALLOC_OFFSET+2])[0]
    e_maxalloc = struct.unpack("<H", mz_header_file[MZ_E_MAXALLOC_OFFSET:MZ_E_MAXALLOC_OFFSET+2])[0]

    print(f"[*] MZ Header values (from original file):")
    print(f"    e_cparhdr: {e_cparhdr} ({e_cparhdr * 16} bytes)")
    print(f"    e_cs: {hex(e_cs_initial_header)}, e_ip: {hex(e_ip_initial_header)}")
    print(f"    e_ss: {hex(e_ss_initial_header)}, e_sp: {hex(e_sp_initial_header)}")
    print(f"    e_minalloc: {hex(e_minalloc)}, e_maxalloc: {hex(e_maxalloc)}")

    # Check LZ91 marker at 0x1C (e_lfarlc position)
    lz91_marker = mz_header_file[MZ_E_LFARLC_OFFSET:MZ_E_LFARLC_OFFSET+4]
    if lz91_marker == b'LZ91':
        print(f"[*] LZ91 marker 'LZ91' found at 0x{MZ_E_LFARLC_OFFSET:X}.")
    else:
        print(f"[*] LZ91 marker not found at 0x{MZ_E_LFARLC_OFFSET:X}. Found: {lz91_marker}")
        # Continue anyway, as the unpacking logic might still apply to similar packers

    # Calculate where the executable code/data actually starts in the file
    exe_start_offset_in_file = e_cparhdr * 16
    
    # Initialize Unicorn Engine for x86 16-bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_16)

    # Map a 1MB contiguous region of memory for DOS conventional memory
    # Max possible physical address in DOS 1MB conventional memory is 0x100000 - 1.
    TOTAL_MEM_SIZE = 0x100000 
    mu.mem_map(0, TOTAL_MEM_SIZE, UC_PROT_ALL)
    print(f"[*] Mapped total memory from 0x0 to {hex(TOTAL_MEM_SIZE)} ({TOTAL_MEM_SIZE // 1024} KB).")

    # Load the executable content *after* the MZ header into memory
    # The program is loaded at LOAD_CODE_PHYSICAL_BASE (0x10000).
    mu.mem_write(LOAD_CODE_PHYSICAL_BASE, file_content[exe_start_offset_in_file:])
    print(f"[*] Loaded executable content from file offset {hex(exe_start_offset_in_file)} at physical address {hex(LOAD_CODE_PHYSICAL_BASE)}.")
    
    # Set up initial registers for the loader stub as DOS would.
    # The observed CS (0x26F6) minus the e_cs from the header (0x16F6) gives the program's load segment (0x1000).
    # The PSP is 0x10 paragraphs below the load segment.
    psp_segment = LOAD_BASE_PARAGRAPH - 0x10 

    mu.reg_write(UC_X86_REG_CS, 0x26F6) # Observed initial CS from Ghidra
    mu.reg_write(UC_X86_REG_IP, 0x000E) # Observed initial IP from Ghidra
    mu.reg_write(UC_X86_REG_SS, 0x4194) # Observed initial SS from Ghidra
    mu.reg_write(UC_X86_REG_SP, 0x0080) # Observed initial SP from Ghidra
    mu.reg_write(UC_X86_REG_DS, psp_segment) # DS and ES always point to PSP initially
    mu.reg_write(UC_X86_REG_ES, psp_segment) 

    # Set direction flag to clear (CLD). The program explicitly sets STD later.
    mu.reg_write(UC_X86_REG_EFLAGS, 0x202) # Set bit 9 (IF) and bit 1 (reserved). DF=0.

    print(f"[*] Starting emulation at CS:IP = {hex(mu.reg_read(UC_X86_REG_CS))}:{hex(mu.reg_read(UC_X86_REG_IP))}")
    print(f"    Physical start address: {hex(mu.reg_read(UC_X86_REG_CS) * 16 + mu.reg_read(UC_X86_REG_IP))}")
    print(f"    Initial DS/ES (PSP Segment): {hex(psp_segment)}")
    
    # Add hooks
    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_unmapped)

    try:
        # Emulate until the program attempts to jump to the unpacked entry point,
        # or an unmapped memory access (indicating decompression is done or failed).
        # Set a generous instruction count limit to ensure completion.
        mu.emu_start(mu.reg_read(UC_X86_REG_CS) * 16 + mu.reg_read(UC_X86_REG_IP), 
                     TOTAL_MEM_SIZE, 
                     timeout=0,      # No timeout, runs until stop or error
                     count=50000000) # Max 50 million instructions
        print("[*] Emulation finished (possibly due to instruction count or exit).")

    except UcError as e:
        print(f"[*] Emulation stopped with error: {e}")
        # Register values are already printed by hook_mem_unmapped if it was a memory error.
        # Otherwise, print them here for general errors.
        if not str(e).startswith("UC_ERR_MEM_UNMAPPED"):
            print(f"    CS:IP = {hex(mu.reg_read(UC_X86_REG_CS))}:{hex(mu.reg_read(UC_X86_REG_IP))}")
            print(f"    EFLAGS: {hex(mu.reg_read(UC_X86_REG_EFLAGS))}")
            print(f"    AX: {hex(mu.reg_read(UC_X86_REG_AX))}, BX: {hex(mu.reg_read(UC_X86_REG_BX))}, CX: {hex(mu.reg_read(UC_X86_REG_CX))}, DX: {hex(mu.reg_read(UC_X86_REG_DX))}")
            print(f"    SI: {hex(mu.reg_read(UC_X86_REG_SI))}, DI: {hex(mu.reg_read(UC_X86_REG_DI))}, BP: {hex(mu.reg_read(UC_X86_REG_BP))}")
            print(f"    DS: {hex(mu.reg_read(UC_X86_REG_DS))}, ES: {hex(mu.reg_read(UC_X86_REG_ES))}, SS: {hex(mu.reg_read(UC_X86_REG_SS))}, SP: {hex(mu.reg_read(UC_X86_REG_SP))}")


    # After emulation, the decompressed EXE should be at the initial load base address (0x10000).
    print("\n[*] Searching for 'MZ' header in memory...")
    
    search_start_addr = LOAD_CODE_PHYSICAL_BASE 
    search_end_addr = TOTAL_MEM_SIZE 
    
    mz_signature = b'MZ'
    found_mz_headers = []

    # Iterate through memory in chunks to find MZ headers
    chunk_size = 0x10000 # Search in 64KB chunks
    for current_addr in range(search_start_addr, search_end_addr, chunk_size):
        try:
            mem_chunk = mu.mem_read(current_addr, min(chunk_size, search_end_addr - current_addr))
            
            offset = 0
            while True:
                idx = mem_chunk.find(mz_signature, offset)
                if idx == -1:
                    break
                
                found_addr = current_addr + idx
                
                # Verify it's a valid MZ header by checking e_magic and e_cparhdr (header size)
                try:
                    potential_header = mu.mem_read(found_addr, 0x40) # Read 64 bytes for header fields
                    
                    p_e_magic = struct.unpack("<H", potential_header[MZ_E_MAGIC_OFFSET:MZ_E_MAGIC_OFFSET+2])[0]
                    p_e_cparhdr = struct.unpack("<H", potential_header[MZ_E_CPARHDR_OFFSET:MZ_E_CPARHDR_OFFSET+2])[0]

                    # Sanity checks: e_magic must be MZ, header size > 0 and reasonable (e.g., < 0x200 paragraphs = 512 bytes)
                    if p_e_magic == 0x5A4D and p_e_cparhdr > 0 and p_e_cparhdr < 0x200: 
                        print(f"  Found potential MZ header at physical address {hex(found_addr)}")
                        found_mz_headers.append((found_addr, p_e_cparhdr))
                except Exception:
                    pass # Not a valid header or not enough bytes, continue

                offset = idx + 1 # Continue search after this 'MZ'
        except UcError as e:
            print(f"Error reading memory at {hex(current_addr)} during MZ search: {e}")
            break

    if not found_mz_headers:
        print("[!] No valid MZ headers found in memory after emulation. Decompression might have failed or output is non-standard.")
        return

    # Assume the first found MZ header closest to the original load base is the unpacked EXE.
    best_match_addr = sorted(found_mz_headers, key=lambda x: abs(x[0] - LOAD_CODE_PHYSICAL_BASE))[0][0]
    
    # Read the header of the identified unpacked executable from memory
    unpacked_header = mu.mem_read(best_match_addr, 0x40)
    p_e_cblp = struct.unpack("<H", unpacked_header[MZ_E_CBLP_OFFSET:MZ_E_CBLP_OFFSET+2])[0]
    p_e_cp = struct.unpack("<H", unpacked_header[MZ_E_CP_OFFSET:MZ_E_CP_OFFSET+2])[0]
    p_e_cparhdr_unpacked = struct.unpack("<H", unpacked_header[MZ_E_CPARHDR_OFFSET:MZ_E_CPARHDR_OFFSET+2])[0]

    # Calculate the total size of the unpacked executable image (header + code/data)
    # This is the standard DOS formula for image size in bytes.
    image_size_in_bytes = (p_e_cp - 1) * 512 + p_e_cblp if p_e_cblp != 0 else p_e_cp * 512

    print(f"[*] Identified unpacked EXE at {hex(best_match_addr)}")
    print(f"    Unpacked e_cparhdr: {p_e_cparhdr_unpacked} ({p_e_cparhdr_unpacked * 16} bytes)")
    print(f"    Unpacked e_cp: {hex(p_e_cp)}, e_cblp: {hex(p_e_cblp)}")
    print(f"[*] Estimated decompressed EXE size (image size in bytes): {image_size_in_bytes} bytes")

    if best_match_addr is not None and image_size_in_bytes > 0:
        try:
            extracted_data = mu.mem_read(best_match_addr, image_size_in_bytes)
            output_filename = filename.replace(".exe", "_unpacked.exe")
            with open(output_filename, 'wb') as f:
                f.write(extracted_data)
            print(f"[*] Successfully extracted unpacked EXE to '{output_filename}'")
        except UcError as e:
            print(f"Error reading extracted data from memory: {e}")
    else:
        print("[!] Could not determine the location or size of the unpacked executable for dumping.")

# --- Script Execution ---
if __name__ == "__main__":
    extract_lz91_exe(FILENAME)
