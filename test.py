import struct
from unicorn import *
from unicorn.x86_const import *

# File to analyze
FILENAME = "fgodmom.exe"

# Memory addresses for Unicorn emulation
# Based on Ghidra's runtime analysis (CS=0x26F6, IP=0x000E) and original e_cs (0x16F6),
# the program is loaded at physical address 0x10000 (paragraph 0x1000).
LOAD_CODE_PHYSICAL_BASE = 0x10000 # This is page-aligned (0x10 * 0x1000)

# Global variables for tracking initial copy state (compressed data)
initial_copy_dest_start = 0  # Physical address where the initial compressed block lands
initial_copy_size = 0        # Size of the initial copied compressed block

# Hook for instructions to detect the initial copy's completion
def hook_code(uc, address, size, user_data):
    global initial_copy_dest_start, initial_copy_size
    
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    physical_address = current_cs * 16 + current_ip

    print(f"Executing {physical_address:X}: {uc.mem_read(physical_address, size).hex()}") # Uncomment for detailed instruction trace
    
    # The instruction `MOV CX,word ptr [DAT_26f6_000c]` is at 26f6:0011 (physical 0x26F71).
    # This instruction reads the size (e_maxalloc, 0xC228) for the initial REP MOVSB.
    # We hook *before* the instruction executes.
    if current_cs == 0x26F6 and current_ip == 0x11:
        # At this point, DS is 0x26F6 (set by PUSH CS; POP DS earlier).
        # The instruction reads from DS:0x000C (physical 0x26F6C).
        try:
            ds_val = uc.reg_read(UC_X86_REG_DS)
            cx_val_bytes = uc.mem_read(ds_val * 16 + 0x0C, 2)
            initial_copy_size = struct.unpack("<H", cx_val_bytes)[0]
            print(f"[*] MOV CX, [DS:0x0C] (physical 0x{ds_val * 16 + 0x0C:X}) executed. CX read as {hex(initial_copy_size)}.")
        except UcError as e:
            print(f"[!] Error reading CX value from memory at {hex(ds_val * 16 + 0x0C)}: {e}")
            # Fallback to hardcoded value if read fails
            initial_copy_size = 0xC228 
            print(f"    Using hardcoded initial_copy_size: {hex(initial_copy_size)}")

    # The RETF at 26f6:002a is crucial for identifying the jump to the decompressor.
    # The code pushes BX (ES value, which becomes the new CS) and AX (IP value) before RETF.
    if current_cs == 0x26F6 and current_ip == 0x2A: 
        # The initial copy was from DS:SI to ES:DI.
        # ES was calculated as DS + e_minalloc (0x26F6 + 0x2228 = 0x491E).
        # The copy destination segment is 0x491E.
        initial_copy_dest_start = uc.reg_read(UC_X86_REG_ES) * 16 # ES should be 0x491E by this point
        
        ss_val = uc.reg_read(UC_X86_REG_SS)
        sp_val = uc.reg_read(UC_X86_REG_SP)
        # Stack top should contain the new IP (0x002B) then new CS (0x491E).
        new_ip = struct.unpack("<H", uc.mem_read(ss_val * 16 + sp_val, 2))[0]
        new_cs = struct.unpack("<H", uc.mem_read(ss_val * 16 + sp_val + 2, 2))[0]
        
        print(f"[*] Reached initial RETF at {hex(current_cs)}:{hex(current_ip)}. Next CS:IP will be {hex(new_cs)}:{hex(new_ip)}.")
        print(f"[*] Initial compressed block copied to {hex(initial_copy_dest_start)} with size {hex(initial_copy_size)}.")


def hook_mem_unmapped(uc, access, address, size, value, user_data):
    # This hook is primarily for debugging unmapped memory errors.
    # Returning True allows emulation to continue (if desired), but we want to stop on critical errors.
    if access == UC_MEM_READ_UNMAPPED:
        print(f"[*] UC_MEM_READ_UNMAPPED: Attempted read from 0x{address:X} (size {size})")
    elif access == UC_MEM_WRITE_UNMAPPED:
        print(f"[*] UC_MEM_WRITE_UNMAPPED: Attempted write to 0x{address:X} (size {size}, value {value:X})")
    elif access == UC_MEM_FETCH_UNMAPPED:
        print(f"[*] UC_MEM_FETCH_UNMAPPED: Attempted fetch from 0x{address:X} (size {size})")
    return False # Return False to let Unicorn raise the error and stop emulation


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

    # Check LZ91 marker at 0x1C
    lz91_marker = mz_header_file[MZ_E_LFARLC_OFFSET:MZ_E_LFARLC_OFFSET+4]
    if lz91_marker == b'LZ91':
        print(f"[*] LZ91 marker 'LZ91' found at 0x{MZ_E_LFARLC_OFFSET:X} (e_lfarlc position).")
    else:
        print(f"[*] LZ91 marker not found at 0x{MZ_E_LFARLC_OFFSET:X}. Found: {lz91_marker}")
        # Continue anyway, as the unpacking logic might still apply

    # Calculate where the executable code/data actually starts in the file
    # This is after the MZ header
    exe_start_offset_in_file = e_cparhdr * 16
    
    # Initialize Unicorn Engine
    mu = Uc(UC_ARCH_X86, UC_MODE_16)

    # Map a large contiguous region of memory to prevent UC_ERR_READ_UNMAPPED issues
    # DOS programs often assume a flat memory model or allocate memory dynamically.
    TOTAL_MEM_SIZE = 16 * 1024 * 1024 # 16MB should be sufficient for most DOS programs
    mu.mem_map(0, TOTAL_MEM_SIZE, UC_PROT_ALL)
    print(f"[*] Mapped total memory from 0x0 to {hex(TOTAL_MEM_SIZE)}.")

    # Load only the executable content *after* the MZ header into memory
    # The program is loaded such that its e_cs (0x16F6) relative to its base segment
    # results in Ghidra's observed CS (0x26F6).
    # This implies the base segment for the loaded code is 0x1000.
    # So, the physical load address for the *executable code/data* is 0x1000 * 16 = 0x10000.
    mu.mem_write(LOAD_CODE_PHYSICAL_BASE, file_content[exe_start_offset_in_file:])
    print(f"[*] Loaded executable code/data from file offset {hex(exe_start_offset_in_file)} at physical address {hex(LOAD_CODE_PHYSICAL_BASE)}.")
    
    # Set up initial registers for the loader stub
    # These are derived from Ghidra's runtime analysis and the MZ header.
    # CS:IP is 0x26F6:0x000E (physical 0x26F6E)
    # SS:SP is 0x4194:0x0080 (physical 0x41940 + 0x80 = 0x419C0)
    # DS is 0x26F6 (will be set by PUSH CS; POP DS instruction)
    # ES is 0x4000 (initial value from Ghidra, will be changed by program)
    
    mu.reg_write(UC_X86_REG_CS, 0x26F6)
    mu.reg_write(UC_X86_REG_IP, 0x000E)
    mu.reg_write(UC_X86_REG_SS, 0x4194) # Ghidra's SS is 0x4194 (0x1000 base + 0x3194 from header)
    mu.reg_write(UC_X86_REG_SP, 0x0080)
    mu.reg_write(UC_X86_REG_DS, 0x26F6) # Pre-set for consistency, will be overwritten by PUSH CS; POP DS
    mu.reg_write(UC_X86_REG_ES, 0x4000) # Initial ES value from Ghidra, will be changed by program

    # Set direction flag to clear (CLD). The program explicitly sets STD later.
    mu.reg_write(UC_X86_REG_EFLAGS, 0x202) # Set bit 9 (IF) and bit 1 (reserved). DF=0.

    print(f"[*] Starting emulation at CS:IP = {hex(mu.reg_read(UC_X86_REG_CS))}:{hex(mu.reg_read(UC_X86_REG_IP))}")
    print(f"    Physical start address: {hex(mu.reg_read(UC_X86_REG_CS) * 16 + mu.reg_read(UC_X86_REG_IP))}")
    
    # Add hooks
    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_unmapped)


    # Debugging: Print original decompressor start bytes in loaded image
    decompressor_start_physical_original = LOAD_CODE_PHYSICAL_BASE + (0x26F60 - LOAD_CODE_PHYSICAL_BASE) + 0x2B
    print(f"[*] Original decompressor start (physical in loaded image): {hex(decompressor_start_physical_original)}")
    # Bytes at this location in the file (relative to file start after header):
    print(f"    Bytes at original decompressor start: {file_content[exe_start_offset_in_file + (decompressor_start_physical_original - LOAD_CODE_PHYSICAL_BASE) : exe_start_offset_in_file + (decompressor_start_physical_original - LOAD_CODE_PHYSICAL_BASE) + 0x20].hex()}")


    try:
        # Run for a sufficient number of instructions. The decompressor might be complex.
        mu.emu_start(mu.reg_read(UC_X86_REG_CS) * 16 + mu.reg_read(UC_X86_REG_IP), 
                     TOTAL_MEM_SIZE, # End address for emulation (effectively runs until exit or error)
                     timeout=0, count=50000000) 
        print("[*] Emulation finished (possibly due to instruction count or exit).")

    except UcError as e:
        print(f"[*] Emulation stopped with error: {e}")
        print(f"    CS:IP = {hex(mu.reg_read(UC_X86_REG_CS))}:{hex(mu.reg_read(UC_X86_REG_IP))}")
        # Print more registers for debugging if an error occurs
        print(f"    EFLAGS: {hex(mu.reg_read(UC_X86_REG_EFLAGS))}")
        print(f"    AX: {hex(mu.reg_read(UC_X86_REG_AX))}, BX: {hex(mu.reg_read(UC_X86_REG_BX))}, CX: {hex(mu.reg_read(UC_X86_REG_CX))}, DX: {hex(mu.reg_read(UC_X86_REG_DX))}")
        print(f"    SI: {hex(mu.reg_read(UC_X86_REG_SI))}, DI: {hex(mu.reg_read(UC_X86_REG_DI))}, BP: {hex(mu.reg_read(UC_X86_REG_BP))}")
        print(f"    DS: {hex(mu.reg_read(UC_X86_REG_DS))}, ES: {hex(mu.reg_read(UC_X86_REG_ES))}, SS: {hex(mu.reg_read(UC_X86_REG_SS))}, SP: {hex(mu.reg_read(UC_X86_REG_SP))}")

    # After emulation, try to find the decompressed data.
    # The initial copy landed at 0x491E0. The LZ91 decompressor is at 0x491E:0x002B.
    # The decompressor will typically write the unpacked EXE either by overwriting the
    # copied compressed data (at 0x491E0) or to a new memory region.
    
    print("[*] Searching for 'MZ' header in memory...")
    
    # Start search from the base address where the initial block was copied (0x491E0).
    # It's highly probable the unpacked EXE starts at 0x491E0 itself, overwriting the compressed data.
    # If initial_copy_dest_start is 0 (e.g., hook wasn't hit), fallback to LOAD_CODE_PHYSICAL_BASE
    search_start_addr = initial_copy_dest_start if initial_copy_dest_start != 0 else LOAD_CODE_PHYSICAL_BASE
    search_end_addr = TOTAL_MEM_SIZE # Search the entire mapped memory
    
    mz_signature = b'MZ'
    found_mz_headers = []

    # Iterate through memory in chunks to find MZ headers
    chunk_size = 0x10000 # 64KB
    for current_addr in range(search_start_addr, search_end_addr, chunk_size):
        try:
            mem_chunk = mu.mem_read(current_addr, min(chunk_size, search_end_addr - current_addr))
            
            offset = 0
            while True:
                idx = mem_chunk.find(mz_signature, offset)
                if idx == -1:
                    break
                
                found_addr = current_addr + idx
                
                # Verify it's a valid MZ header by checking e_magic and e_cparhdr
                try:
                    potential_header = mu.mem_read(found_addr, 0x40) # Read 64 bytes for header fields
                    
                    p_e_magic = struct.unpack("<H", potential_header[MZ_E_MAGIC_OFFSET:MZ_E_MAGIC_OFFSET+2])[0]
                    p_e_cparhdr = struct.unpack("<H", potential_header[MZ_E_CPARHDR_OFFSET:MZ_E_CPARHDR_OFFSET+2])[0]

                    if p_e_magic == 0x5A4D and p_e_cparhdr > 0 and p_e_cparhdr < 0x1000: # Sanity check for header size
                        print(f"  Found potential MZ header at physical address {hex(found_addr)}")
                        found_mz_headers.append((found_addr, p_e_cparhdr))
                except Exception as e:
                    pass # Not a valid header, continue (e.g., not enough bytes to read header)

                offset = idx + 1 # Continue search after this 'MZ'
        except UcError as e:
            print(f"Error reading memory at {hex(current_addr)}: {e}")
            break

    if not found_mz_headers:
        print("[!] No valid MZ headers found in memory after emulation.")
        print("[!] This might mean the decompression did not complete, or the output is not a standard MZ executable.")
        return

    # Assuming the first found MZ header (at or after the initial copied block) is the unpacked EXE.
    # This is a common pattern for simple unpackers.
    best_match_addr = found_mz_headers[0][0] 
    
    # Read the header of the identified unpacked executable from memory
    unpacked_header = mu.mem_read(best_match_addr, 0x40)
    p_e_cblp = struct.unpack("<H", unpacked_header[MZ_E_CBLP_OFFSET:MZ_E_CBLP_OFFSET+2])[0]
    p_e_cp = struct.unpack("<H", unpacked_header[MZ_E_CP_OFFSET:MZ_E_CP_OFFSET+2])[0]
    p_e_cparhdr_unpacked = struct.unpack("<H", unpacked_header[MZ_E_CPARHDR_OFFSET:MZ_E_CPARHDR_OFFSET+2])[0]

    # Calculate the total size of the unpacked executable image in memory
    # This formula describes the total size of the resident portion of the program, including the header.
    if p_e_cblp == 0:
        best_match_size = p_e_cp * 512
    else:
        best_match_size = (p_e_cp - 1) * 512 + p_e_cblp
    
    print(f"[*] Identified unpacked EXE at {hex(best_match_addr)}")
    print(f"    e_cparhdr: {p_e_cparhdr_unpacked} ({p_e_cparhdr_unpacked * 16} bytes)")
    print(f"    e_cp: {hex(p_e_cp)}, e_cblp: {hex(p_e_cblp)}")
    print(f"[*] Estimated decompressed EXE size: {best_match_size} bytes")

    if best_match_addr and best_match_size:
        try:
            extracted_data = mu.mem_read(best_match_addr, best_match_size)
            output_filename = filename.replace(".exe", "_unpacked.exe")
            with open(output_filename, 'wb') as f:
                f.write(extracted_data)
            print(f"[*] Successfully extracted unpacked EXE to '{output_filename}'")
        except UcError as e:
            print(f"Error reading extracted data from memory: {e}")
    else:
        print("[!] Could not determine the location or size of the unpacked executable.")

if __name__ == "__main__":
    extract_lz91_exe(FILENAME)
