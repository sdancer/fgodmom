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

```
//
                             // CODE_1 
                             // ram:26f6:0000-ram:26f6:0fd7
                             //
             assume CS = 0x26f6
       26f6:0000 78              ??         78h    x
```


current program:
```
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
    # try:
    #    ins_bytes = uc.mem_read(physical_address, size).hex()
    #    print(f"Executing {physical_address:X}: {ins_bytes}")
    # except UcError:
    #    print(f"Executing {physical_address:X}: (could not read bytes)")
    
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
```

this is the unpacker logic, our goal is to reach the last jmp, but we are getting stuck 
```
       4000:0960 78 03           dw         378h
       4000:0962 00 00           dw         0h
       4000:0964 00 40           dw         4000h
       4000:0966 04 34           dw         3404h
       4000:0968 f6 16           dw         16F6h
       4000:096a a0 19           dw         19A0h
       4000:096c d8 0f           dw         FD8h
       4000:096e 06              PUSH       ES
       4000:096f 0e              PUSH       CS
       4000:0970 1f              POP        DS
       4000:0971 8b 0e 0c 00     MOV        CX,word ptr [0xc]
       4000:0975 8b f1           MOV        SI,CX
       4000:0977 4e              DEC        SI
       4000:0978 89 f7           MOV        DI,SI
       4000:097a 8c db           MOV        BX,DS
       4000:097c 03 1e 0a 00     ADD        BX,word ptr [0xa]
       4000:0980 8e c3           MOV        ES,BX
       4000:0982 fd              STD
       4000:0983 f3 a4           MOVSB.REP  ES:DI,SI
       4000:0985 53              PUSH       BX
       4000:0986 b8 2b 00        MOV        AX,0x2b
       4000:0989 50              PUSH       AX
       4000:098a cb              RETF
       4000:098b 2e 8b 2e        MOV        BP,word ptr CS:[DAT_4000_0008]
                 08 00
       4000:0990 8c da           MOV        DX,DS
                             LAB_4000_0992                                                                                          XREF[1]:     4000:09b8(j)  
       4000:0992 89 e8           MOV        AX,BP
       4000:0994 3d 00 10        CMP        AX,0x1000
       4000:0997 76 03           JBE        LAB_4000_099c
       4000:0999 b8 00 10        MOV        AX,0x1000
                             LAB_4000_099c                                                                                          XREF[1]:     4000:0997(j)  
       4000:099c 29 c5           SUB        BP,AX
       4000:099e 29 c2           SUB        DX,AX
       4000:09a0 29 c3           SUB        BX,AX
       4000:09a2 8e da           MOV        DS,DX
       4000:09a4 8e c3           MOV        ES,BX
       4000:09a6 b1 03           MOV        CL,0x3
       4000:09a8 d3 e0           SHL        AX,CL
       4000:09aa 89 c1           MOV        CX,AX
       4000:09ac d1 e0           SHL        AX,0x1
       4000:09ae 48              DEC        AX
       4000:09af 48              DEC        AX
       4000:09b0 8b f0           MOV        SI,AX
       4000:09b2 8b f8           MOV        DI,AX
       4000:09b4 f3 a5           MOVSW.REP  ES:DI,SI
       4000:09b6 09 ed           OR         BP,BP
       4000:09b8 75 d8           JNZ        LAB_4000_0992
       4000:09ba fc              CLD
       4000:09bb 8e c2           MOV        ES,DX
       4000:09bd 8e db           MOV        DS,BX
       4000:09bf 31 f6           XOR        SI,SI
       4000:09c1 31 ff           XOR        DI,DI
       4000:09c3 ba 10 00        MOV        DX,0x10
       4000:09c6 ad              LODSW      SI
       4000:09c7 89 c5           MOV        BP,AX
                             LAB_4000_09c9                                                                                          XREF[3]:     4000:09d6(j), 4000:0a21(j), 
                                                                                                                                                4000:0a54(j)  
       4000:09c9 d1 ed           SHR        BP,0x1
       4000:09cb 4a              DEC        DX
       4000:09cc 75 05           JNZ        LAB_4000_09d3
       4000:09ce ad              LODSW      SI
       4000:09cf 89 c5           MOV        BP,AX
       4000:09d1 b2 10           MOV        DL,0x10
                             LAB_4000_09d3                                                                                          XREF[1]:     4000:09cc(j)  
       4000:09d3 73 03           JNC        LAB_4000_09d8
       4000:09d5 a4              MOVSB      ES:DI,SI
       4000:09d6 eb f1           JMP        LAB_4000_09c9
                             LAB_4000_09d8                                                                                          XREF[1]:     4000:09d3(j)  
       4000:09d8 31 c9           XOR        CX,CX
       4000:09da d1 ed           SHR        BP,0x1
       4000:09dc 4a              DEC        DX
       4000:09dd 75 05           JNZ        LAB_4000_09e4
       4000:09df ad              LODSW      SI
       4000:09e0 89 c5           MOV        BP,AX
       4000:09e2 b2 10           MOV        DL,0x10
                             LAB_4000_09e4                                                                                          XREF[1]:     4000:09dd(j)  
       4000:09e4 72 22           JC         LAB_4000_0a08
       4000:09e6 d1 ed           SHR        BP,0x1
       4000:09e8 4a              DEC        DX
       4000:09e9 75 05           JNZ        LAB_4000_09f0
       4000:09eb ad              LODSW      SI
       4000:09ec 89 c5           MOV        BP,AX
       4000:09ee b2 10           MOV        DL,0x10
                             LAB_4000_09f0                                                                                          XREF[1]:     4000:09e9(j)  
       4000:09f0 d1 d1           RCL        CX,0x1
       4000:09f2 d1 ed           SHR        BP,0x1
       4000:09f4 4a              DEC        DX
       4000:09f5 75 05           JNZ        LAB_4000_09fc
       4000:09f7 ad              LODSW      SI
       4000:09f8 89 c5           MOV        BP,AX
       4000:09fa b2 10           MOV        DL,0x10
                             LAB_4000_09fc                                                                                          XREF[1]:     4000:09f5(j)  
       4000:09fc d1 d1           RCL        CX,0x1
       4000:09fe 41              INC        CX
       4000:09ff 41              INC        CX
       4000:0a00 ac              LODSB      SI
       4000:0a01 b7 ff           MOV        BH,0xff
       4000:0a03 8a d8           MOV        BL,AL
       4000:0a05 e9 13 00        JMP        LAB_4000_0a1b
                             LAB_4000_0a08                                                                                          XREF[1]:     4000:09e4(j)  
       4000:0a08 ad              LODSW      SI
       4000:0a09 8b d8           MOV        BX,AX
       4000:0a0b b1 03           MOV        CL,0x3
       4000:0a0d d2 ef           SHR        BH,CL
       4000:0a0f 80 cf e0        OR         BH,0xe0
       4000:0a12 80 e4 07        AND        AH,0x7
       4000:0a15 74 0c           JZ         LAB_4000_0a23
       4000:0a17 88 e1           MOV        CL,AH
       4000:0a19 41              INC        CX
       4000:0a1a 41              INC        CX
                             LAB_4000_0a1b                                                                                          XREF[3]:     4000:0a05(j), 4000:0a1f(j), 
                                                                                                                                                4000:0a2f(j)  
       4000:0a1b 26 8a 01        MOV        AL,byte ptr ES:[BX + DI]
       4000:0a1e aa              STOSB      ES:DI
       4000:0a1f e2 fa           LOOP       LAB_4000_0a1b
       4000:0a21 eb a6           JMP        LAB_4000_09c9
                             LAB_4000_0a23                                                                                          XREF[1]:     4000:0a15(j)  
       4000:0a23 ac              LODSB      SI
       4000:0a24 08 c0           OR         AL,AL
       4000:0a26 74 34           JZ         LAB_4000_0a5c
       4000:0a28 3c 01           CMP        AL,0x1
       4000:0a2a 74 05           JZ         LAB_4000_0a31
       4000:0a2c 88 c1           MOV        CL,AL
       4000:0a2e 41              INC        CX
       4000:0a2f eb ea           JMP        LAB_4000_0a1b
                             LAB_4000_0a31                                                                                          XREF[1]:     4000:0a2a(j)  
       4000:0a31 89 fb           MOV        BX,DI
       4000:0a33 83 e7 0f        AND        DI,0xf
       4000:0a36 81 c7 00 20     ADD        DI,0x2000
       4000:0a3a b1 04           MOV        CL,0x4
       4000:0a3c d3 eb           SHR        BX,CL
       4000:0a3e 8c c0           MOV        AX,ES
       4000:0a40 01 d8           ADD        AX,BX
       4000:0a42 2d 00 02        SUB        AX,0x200
       4000:0a45 8e c0           MOV        ES,AX
       4000:0a47 89 f3           MOV        BX,SI
       4000:0a49 83 e6 0f        AND        SI,0xf
       4000:0a4c d3 eb           SHR        BX,CL
       4000:0a4e 8c d8           MOV        AX,DS
       4000:0a50 01 d8           ADD        AX,BX
       4000:0a52 8e d8           MOV        DS,AX
       4000:0a54 e9 72 ff        JMP        LAB_4000_09c9
       4000:0a57 2a              ??         2Ah    *
       4000:0a58 46              ??         46h    F
       4000:0a59 41              ??         41h    A
       4000:0a5a 42              ??         42h    B
       4000:0a5b 2a              ??         2Ah    *
                             LAB_4000_0a5c                                                                                          XREF[1]:     4000:0a26(j)  
       4000:0a5c 0e              PUSH       CS=>DAT_0000_4000
       4000:0a5d 1f              POP        DS
       4000:0a5e be 58 01        MOV        SI,0x158
       4000:0a61 5b              POP        BX
       4000:0a62 83 c3 10        ADD        BX,0x10
       4000:0a65 89 da           MOV        DX,BX
       4000:0a67 31 ff           XOR        DI,DI
                             LAB_4000_0a69                                                                                          XREF[2]:     4000:0a82(j), 4000:0a8f(j)  
       4000:0a69 ac              LODSB      SI
       4000:0a6a 08 c0           OR         AL,AL
       4000:0a6c 74 16           JZ         LAB_4000_0a84
       4000:0a6e b4 00           MOV        AH,0x0
                             LAB_4000_0a70                                                                                          XREF[1]:     4000:0a94(j)  
       4000:0a70 01 c7           ADD        DI,AX
       4000:0a72 8b c7           MOV        AX,DI
       4000:0a74 83 e7 0f        AND        DI,0xf
       4000:0a77 b1 04           MOV        CL,0x4
       4000:0a79 d3 e8           SHR        AX,CL
       4000:0a7b 01 c2           ADD        DX,AX
       4000:0a7d 8e c2           MOV        ES,DX
       4000:0a7f 26 01 1d        ADD        word ptr ES:[DI],BX
       4000:0a82 eb e5           JMP        LAB_4000_0a69
                             LAB_4000_0a84                                                                                          XREF[1]:     4000:0a6c(j)  
       4000:0a84 ad              LODSW      SI
       4000:0a85 09 c0           OR         AX,AX
       4000:0a87 75 08           JNZ        LAB_4000_0a91
       4000:0a89 81 c2 ff 0f     ADD        DX,0xfff
       4000:0a8d 8e c2           MOV        ES,DX
       4000:0a8f eb d8           JMP        LAB_4000_0a69
                             LAB_4000_0a91                                                                                          XREF[1]:     4000:0a87(j)  
       4000:0a91 3d 01 00        CMP        AX,0x1
       4000:0a94 75 da           JNZ        LAB_4000_0a70
       4000:0a96 8b c3           MOV        AX,BX
       4000:0a98 8b 3e 04 00     MOV        DI,word ptr [0x4]
       4000:0a9c 8b 36 06 00     MOV        SI,word ptr [0x6]
       4000:0aa0 01 c6           ADD        SI,AX
       4000:0aa2 01 06 02 00     ADD        word ptr [0x2],AX
       4000:0aa6 2d 10 00        SUB        AX,0x10
       4000:0aa9 8e d8           MOV        DS,AX
       4000:0aab 8e c0           MOV        ES,AX
       4000:0aad 31 db           XOR        BX,BX
       4000:0aaf fa              CLI
       4000:0ab0 8e d6           MOV        SS,SI
       4000:0ab2 8b e7           MOV        SP,DI
       4000:0ab4 fb              STI
       4000:0ab5 2e ff 2f        JMPF       CS:[BX]=>DAT_4000_0000
```

```
Executing 40AB5: 2eff2f
Executing 10378: 9a00008636
Executing 36860: ba3e38
Executing 36863: 8eda
Executing 36865: 8c064284
Executing 36869: 33ed
Executing 3686B: 8bc4
Executing 3686D: 051300
Executing 36870: b104
Executing 36872: d3e8
Executing 36874: 8cd2
Executing 36876: 03c2
Executing 36878: a31a84
Executing 3687B: a31c84
Executing 3687E: 03061484
Executing 36882: a31e84
Executing 36885: a32884
Executing 36888: a32c84
Executing 3688B: 26a10200
Executing 3688F: 2d0010
Executing 36892: a33084
Executing 36895: bf14bc
Executing 36898: bedd01
Executing 3689B: b91200
Executing 3689E: 90
Executing 3689F: fc
Executing 368A0: 2eac
Executing 368A2: b435
Executing 368A4: cd21
```

we are hitting the last jump of the packer and then quickly breaking at int 21 it seems, can we hook the jmp at 40AB5 and dump the full memory ?
can we add int 21 handling and a vga display?

