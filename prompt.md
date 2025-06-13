give me an unicorn script to extract the original .exe from an msdos .exe program that is compressed with lz91

filename: fgodmom.exe

relevant snippets from ghidra:

```
                             //
                             // HEADER 
                             // HEADER::00000000-HEADER::0000001f
                             //
             assume CS = <UNKNOWN>
             assume DF = <UNKNOWN>
     R::00000000 4d 5a 58        OLD_IMAG
                 01 c0 00 
                 00 00 02 
        R::00000000 4d 5a           char[2]   "MZ"                    e_magic       Magic number
        R::00000002 58 01           dw        158h                    e_cblp        Bytes of last page
        R::00000004 c0 00           dw        C0h                     e_cp          Pages in file
        R::00000006 00 00           dw        0h                      e_crlc        Relocations
        R::00000008 02 00           dw        2h                      e_cparhdr     Size of header in 
        R::0000000a 28 22           dw        2228h                   e_minalloc    Minimum extra para
        R::0000000c 28 c2           dw        C228h                   e_maxalloc    Maximum extra para
        R::0000000e 94 31           dw        3194h                   e_ss          Initial (relative)
        R::00000010 80 00           dw        80h                     e_sp          Initial SP value
        R::00000012 00 00           dw        0h                      e_csum        Checksum
        R::00000014 0e 00           dw        Eh                      e_ip          Initial IP value
        R::00000016 f6 16           dw        16F6h                   e_cs          Initial (relative)
        R::00000018 1c 00           dw        1Ch                     e_lfarlc      File address of re
        R::0000001a 00 00           dw        0h                      e_ovno        Overlay number
     R::0000001c 4c              ??         4Ch    L
     R::0000001d 5a              ??         5Ah    Z
     R::0000001e 39              ??         39h    9
     R::0000001f 31              ??         31h    1
```

code1 block: lets verify this maps correctly on our script
```
//
                             // CODE_1 
                             // ram:26f6:0000-ram:26f6:0fd7
                             //
             assume CS = 0x26f6
       26f6:0000 78              ??         78h    x
```


entry point: lets verify the fist bytes are correctly mapped
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __cdecl16far entry()
                               assume CS = 0x26f6
                               assume SP = 0x80
                               assume SS = 0x4194
             undefined         AL:1           <RETURN>
                             entry                                                                                                  XREF[1]:     Entry Point(*)  
       26f6:000e 06              PUSH       ES=>DAT_4000_19be                                = ??
             assume SS = <UNKNOWN>
             assume SP = <UNKNOWN>
       2000:6f6f 0e              PUSH       CS=>DAT_4000_19bc                                = ??
       2000:6f70 1f              POP        DS=>DAT_4000_19bc                                = ??
       2000:6f71 8b 0e 0c 00     MOV        CX,word ptr [DAT_26f6_000c]                      = 0FD8h
       2000:6f75 8b f1           MOV        SI,CX
       2000:6f77 4e              DEC        SI
       2000:6f78 89 f7           MOV        DI,SI
       2000:6f7a 8c db           MOV        BX,DS
       2000:6f7c 03 1e 0a 00     ADD        BX,word ptr [DAT_26f6_000a]                      = 19A0h
       2000:6f80 8e c3           MOV        ES,BX
       2000:6f82 fd              STD
       2000:6f83 f3 a4           MOVSB.REP  ES:DI=>DAT_4000_1937,SI=>DAT_26f6_0fd7           = ??
       2000:6f85 53              PUSH       BX=>DAT_4000_19bc                                = ??
       2000:6f86 b8 2b 00        MOV        AX,0x2b
       2000:6f89 50              PUSH       AX=>DAT_4000_19ba                                = ??
       2000:6f8a cb              RETF                                                        = ??

```


current program:
```
import struct
from unicorn import *
from unicorn.x86_const import *

# File to analyze
FILENAME = "fgodmom.exe"

# Memory addresses for Unicorn emulation
# Based on Ghidra's runtime analysis (CS=0x26F6, IP=0x000E) and original e_cs (0x16F6),
# the program is loaded at physical address 0x10000 (paragraph 0x1000).
# This is where the *actual executable code and data* from the file will be mapped.
LOAD_CODE_PHYSICAL_BASE = 0x10000 # This is page-aligned (0x10 * 0x1000)
MAP_SIZE = 4 * 1024 * 1024 # 4MB - Increased for general safety

# MZ Header offsets (relative to file start / base_address)
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

# Global variables for tracking decompression state
decompressed_data_start = 0  # Physical address where the initial copy lands
decompressed_data_size = 0   # Size of the initial copied block

# Hook for instructions to detect the initial copy's completion
def hook_code(uc, address, size, user_data):
    global decompressed_data_start, decompressed_data_size
    
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    physical_address = current_cs * 16 + current_ip

    # print(f"Executing {physical_address:X}: {uc.mem_read(physical_address, size).hex()}") # Uncomment for detailed instruction trace
    
    # The instruction `MOV CX,word ptr [DAT_26f6_000c]` is at 26f6:0011 (physical 0x26F71).
    # This instruction reads the size (e_maxalloc, 0xC228) for the initial REP MOVSB.
    # We hook *before* the instruction executes.
    if current_cs == 0x26F6 and current_ip == 0x11:
        # At this point, DS is 0x26F6 (set by PUSH CS; POP DS earlier).
        # The instruction reads from DS:0x000C (physical 0x26F6C).
        try:
            ds_val = uc.reg_read(UC_X86_REG_DS)
            cx_val_bytes = uc.mem_read(ds_val * 16 + 0x0C, 2)
            decompressed_data_size = struct.unpack("<H", cx_val_bytes)[0]
            print(f"[*] MOV CX, [DS:0x0C] (physical 0x{ds_val * 16 + 0x0C:X}) executed. CX read as {hex(decompressed_data_size)}.")
        except UcError as e:
            print(f"[!] Error reading CX value from memory at {hex(ds_val * 16 + 0x0C)}: {e}")
            # Fallback to hardcoded value if read fails, or if it's not the instruction
            decompressed_data_size = 0xC228 
            print(f"    Using hardcoded decompressed_data_size: {hex(decompressed_data_size)}")

    # The RETF at 26f6:002a is crucial for identifying the jump to the decompressor.
    # The code pushes BX (ES value 0x491E) and AX (IP value 0x002B) before RETF.
    if current_cs == 0x26F6 and current_ip == 0x2A: 
        ss_val = uc.reg_read(UC_X86_REG_SS)
        sp_val = uc.reg_read(UC_X86_REG_SP)
        # Stack top should contain the new IP (0x002B) then new CS (0x491E).
        new_ip = struct.unpack("<H", uc.mem_read(ss_val * 16 + sp_val, 2))[0]
        new_cs = struct.unpack("<H", uc.mem_read(ss_val * 16 + sp_val + 2, 2))[0]
        
        print(f"[*] Reached initial RETF at {hex(current_cs)}:{hex(current_ip)}. Next CS:IP will be {hex(new_cs)}:{hex(new_ip)}.")
        
        # The initial copy was from DS:SI to ES:DI.
        # ES was calculated as DS + e_minalloc (0x26F6 + 0x2228 = 0x491E).
        # The copy destination segment is 0x491E.
        decompressed_data_start = uc.reg_read(UC_X86_REG_ES) * 16 # ES should be 0x491E by this point
        
        print(f"[*] Initial block copied to {hex(decompressed_data_start)} with size {hex(decompressed_data_size)}.")


def extract_lz91_exe(filename):
    global decompressed_data_start, decompressed_data_size

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

    # Map low memory (0x0 to 0x1000) for interrupt vectors/BIOS data
    # Many DOS programs access this area for system calls or BIOS information.
    mu.mem_map(0x0, 0x1000, UC_PROT_ALL)
    print(f"[*] Mapped low memory (0x0-0x1000) for system data.")

    # Map memory for the executable image
    # The program is loaded such that its e_cs (0x16F6) relative to its base segment
    # results in Ghidra's observed CS (0x26F6).
    # This implies the base segment for the loaded code is 0x26F6 - 0x16F6 = 0x1000.
    # So, the physical load address for the *executable code/data* is 0x1000 * 16 = 0x10000.
    mu.mem_map(LOAD_CODE_PHYSICAL_BASE, MAP_SIZE, UC_PROT_ALL)
    # Load only the executable content *after* the MZ header into memory
    mu.mem_write(LOAD_CODE_PHYSICAL_BASE, file_content[exe_start_offset_in_file:])
    print(f"[*] Mapped executable code/data from file offset {hex(exe_start_offset_in_file)} at physical address {hex(LOAD_CODE_PHYSICAL_BASE)} with size {hex(MAP_SIZE)}.")
    
    # Map a stack region. Ensure it's outside the main code/data area.
    # Put stack immediately after mapped program data to avoid overlap and provide sufficient space.
    STACK_PHYSICAL = LOAD_CODE_PHYSICAL_BASE + MAP_SIZE 
    STACK_SIZE = 0x10000 # 64KB stack (can be adjusted if needed)
    mu.mem_map(STACK_PHYSICAL, STACK_SIZE, UC_PROT_ALL)
    print(f"[*] Mapped stack at {hex(STACK_PHYSICAL)} with size {hex(STACK_SIZE)}.")


    # Set up initial registers for the loader stub
    # These are derived from Ghidra's runtime analysis and the MZ header.
    # CS:IP is 0x26F6:0x000E (physical 0x26F6E)
    # SS:SP is 0x4194:0x0080 (physical 0x41940 + 0x80 = 0x419C0)
    # DS is 0x26F6 (set by PUSH CS; POP DS instruction)
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

    try:
        # Run for a sufficient number of instructions. The decompressor might be complex.
        # Increased instruction count further as decompressors can be long-running loops.
        mu.emu_start(mu.reg_read(UC_X86_REG_CS) * 16 + mu.reg_read(UC_X86_REG_IP), 
                     LOAD_CODE_PHYSICAL_BASE + MAP_SIZE + STACK_SIZE, # End address for emulation
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
    # If decompressed_data_start is 0 (e.g., hook wasn't hit), fallback to LOAD_CODE_PHYSICAL_BASE
    search_start_addr = decompressed_data_start if decompressed_data_start != 0 else LOAD_CODE_PHYSICAL_BASE
    search_end_addr = LOAD_CODE_PHYSICAL_BASE + MAP_SIZE 
    
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
    # If multiple are found, the one with the smallest starting address after the initial copy.
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
```

error:
```
[*] Reached initial RETF at 0x26f6:0x2a. Next CS:IP will be 0x4096:0x2b.
[*] Initial block copied to 0x40960 with size 0xfd8.
[*] Emulation stopped with error: Invalid memory read (UC_ERR_READ_UNMAPPED)
    CS:IP = 0x4096:0x11f
    EFLAGS: 0x212
    AX: 0xf, BX: 0x4010, CX: 0x4, DX: 0x101
    SI: 0x2d5d, DI: 0x7, BP: 0x0
    DS: 0x4096, ES: 0x101, SS: 0x4194, SP: 0x80
[*] Searching for 'MZ' header in memory...
```

