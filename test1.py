import struct
import time
import collections # For deque, a double-ended queue for keyboard buffer

from unicorn import *
from unicorn.x86_const import *

# --- Pygame for VGA Display ---
import pygame
from bios import *
from int21 import *

# Initialize Pygame first to allow font loading etc.
pygame.init()

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
LZEXE_REAL_IP_OFFSET = 0x00
LZEXE_REAL_CS_OFFSET = 0x02
LZEXE_REAL_SP_OFFSET = 0x04
LZEXE_REAL_SS_OFFSET = 0x06
LZEXE_COMPRESSED_SIZE_PARAGRAPHS_OFFSET = 0x08
LZEXE_ADDITIONAL_SIZE_PARAGRAPHS_OFFSET = 0x0A
LZEXE_DECOMPRESSOR_CODE_SIZE_BYTES_OFFSET = 0x0C

# --- Unicorn Hooks ---

def hook_code(uc, address, size, user_data):
    """
    Hook for instructions to detect the final JMPF.
    Currently, it does not stop or dump, allowing execution to continue into the unpacked code.
    This is suitable for running the game after unpacking.
    """
    global UNPACKED_EXE_DUMPED
    
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    physical_address = current_cs * 16 + current_ip
    print(f"- {physical_address:X}")

    # The final JMPF instruction is at a specific offset within the decompressor's segment.
    # The user_data['final_jmp_addr'] is pre-calculated to hit this exact instruction.
    if physical_address == user_data['final_jmp_addr'] and not UNPACKED_EXE_DUMPED:
        print(f"[*] Reached final JMPF at {hex(physical_address)}. Unpacking likely complete.")

 

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

def hook_interrupt(uc, intno, user_data):
    """
    Hook for handling DOS and BIOS interrupts.
    Stops emulation if an unsupported interrupt or function is encountered.
    """
    vga_emulator = user_data['vga_emulator'] # Get the VGA emulator instance

    print(intno)

    if intno == 0x21: # DOS Services
        handle_int21(uc, vga_emulator)
    elif intno == 0x10: # Video Services (VGA BIOS)
        handle_int10(uc, vga_emulator)
    elif intno == 0x11: # Get BIOS equipment list
        # AL = BIOS equipment list word, from 0040h:0010h
        # Dummy values for fgodmom.exe:
        # Initial video mode: 80x25 CGA color (10b, bit 5-4)
        # Number of floppy disk drives: 2 (01b, bit 7-6)
        # Assuming no game port, no serial/parallel devices etc.
        # So, 0100 0100 0000 0000 = 0x4400
        # In fact, let's write 0x44 (number of drives) to BDA at 0x475 (0x40:0x475)
        # Equipment list word is at 0x40:0x10 (0x410)
        equipment_word = 0x4400 # 2 floppy drives, 80x25 CGA color
        uc.mem_write(BIOS_DATA_AREA + 0x10, struct.pack("<H", equipment_word))
        uc.reg_write(UC_X86_REG_AX, equipment_word)
        print(f"[*] INT 11h (Get BIOS equipment list). AX={hex(equipment_word)}")
    elif intno == 0x12: # Get memory size
        # Returns AX = kilobytes of contiguous memory starting at 00000h
        # From 0040h:0013h
        total_memory_kb = (TOTAL_MEM_SIZE // 1024) # e.g., 1024 KB
        uc.mem_write(BIOS_DATA_AREA + 0x13, struct.pack("<H", total_memory_kb))
        uc.reg_write(UC_X86_REG_AX, total_memory_kb)
        print(f"[*] INT 12h (Get memory size). AX={total_memory_kb} KB")
    elif intno == 0x13: # Disk Services (BIOS)
        ah = uc.reg_read(UC_X86_REG_AH)
        if ah == 0x00: # Reset disk system
            print(f"[*] INT 13h, AH=00h (Reset Disk System). Acknowledged.")
            # Set AH to 0 and clear CF for success
            uc.reg_write(UC_X86_REG_AH, 0x00)
            eflags = uc.reg_read(UC_X86_REG_EFLAGS)
            eflags &= ~0x0001 # Clear Carry Flag (CF)
            uc.reg_write(UC_X86_REG_EFLAGS, eflags)
        else:
            print(f"[*] Unhandled INT 13h function: AH={hex(ah)}. Stopping emulation.")
            uc.emu_stop()
    elif intno == 0x15: # BIOS Services (e.g., Wait)
        ah = uc.reg_read(UC_X86_REG_AH)
        if ah == 0x86: # BIOS wait function
            cx = uc.reg_read(UC_X86_REG_CX)
            dx = uc.reg_read(UC_X86_REG_DX)
            microseconds = (cx << 16) | dx
            print(f"[*] INT 15h, AH=86h (BIOS Wait): {microseconds} microseconds. (Simulating sleep)")
            # Simulate a brief sleep, but avoid blocking the UI too much
            # time.sleep(microseconds / 1_000_000.0)
            # Just return success instantly to avoid UI freeze during long waits
            eflags = uc.reg_read(UC_X86_REG_EFLAGS)
            eflags &= ~0x0001 # Clear CF for success
            uc.reg_write(UC_X86_REG_EFLAGS, eflags)
        else:
            print(f"[*] Unhandled INT 15h function: AH={hex(ah)}. Stopping emulation.")
            uc.emu_stop()
    elif intno == 0x16: # Keyboard Services (BIOS)
        ah = uc.reg_read(UC_X86_REG_AH)
        if ah == 0x00: # Get keystroke from keyboard (no echo)
            key_data = vga_emulator.get_buffered_key(remove=True)
            if key_data:
                ascii_val, scan_code = key_data
                uc.reg_write(UC_X86_REG_AL, ascii_val)
                uc.reg_write(UC_X86_REG_AH, scan_code)
                print(f"[*] INT 16h, AH=00h (Get Keystroke): AL={hex(ascii_val)}, AH={hex(scan_code)}")
            else:
                print(f"[*] INT 16h, AH=00h (Get Keystroke): Waiting for key...")
                vga_emulator.waiting_for_key = True
                uc.emu_stop() # Stop emulation until key is pressed
        elif ah == 0x01: # Check for keystroke in the keyboard buffer
            key_data = vga_emulator.get_buffered_key(remove=False) # Do not remove
            if key_data:
                ascii_val, scan_code = key_data
                uc.reg_write(UC_X86_REG_AL, ascii_val)
                uc.reg_write(UC_X86_REG_AH, scan_code)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)
                eflags &= ~0x0040 # Clear ZF (keystroke available)
                uc.reg_write(UC_X86_REG_EFLAGS, eflags)
                print(f"[*] INT 16h, AH=01h (Check Keystroke): ZF clear, AL={hex(ascii_val)}, AH={hex(scan_code)}")
            else:
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)
                eflags |= 0x0040 # Set ZF (no keystroke)
                uc.reg_write(UC_X86_REG_EFLAGS, eflags)
                print(f"[*] INT 16h, AH=01h (Check Keystroke): ZF set (no key).")
        else:
            print(f"[*] Unhandled INT 16h function: AH={hex(ah)}. Stopping emulation.")
            uc.emu_stop()

    elif intno == 0x1A: # Get/Set System Time (BIOS)
        ah = uc.reg_read(UC_X86_REG_AH)
        if ah == 0x00: # Get System Time
            # Returns CX:DX = number of clock ticks since midnight.
            # AL = midnight counter, advanced each time midnight passes.
            # Dummy values: 18.2 ticks/sec. 1 sec = ~18 ticks.
            # Use current system time to provide more realistic values
            current_time = time.time()
            ticks_per_day = 18.20648 * 24 * 3600
            ticks_since_midnight = int((current_time % (24 * 3600)) * 18.20648)
            
            uc.reg_write(UC_X86_REG_CX, (ticks_since_midnight >> 16) & 0xFFFF)
            uc.reg_write(UC_X86_REG_DX, ticks_since_midnight & 0xFFFF)
            uc.reg_write(UC_X86_REG_AL, 0x00) # Midnight counter (not emulated)
            print(f"[*] INT 1Ah, AH=00h (Get System Time): CX:DX={hex(uc.reg_read(UC_X86_REG_CX))}:{hex(uc.reg_read(UC_X86_REG_DX))}")
        else:
            print(f"[*] Unhandled INT 1Ah function: AH={hex(ah)}. Stopping emulation.")
            uc.emu_stop()

    elif intno == 0x33: # Mouse Driver
        ax = uc.reg_read(UC_X86_REG_AX)
        if ax == 0x0000: # Mouse initialization
            # Return AX=0xFFFF (success) and BX=number of buttons (2 or 3)
            uc.reg_write(UC_X86_REG_AX, 0xFFFF)
            uc.reg_write(UC_X86_REG_BX, 2) # Assume 2 buttons
            print(f"[*] INT 33h, AX=0000h (Mouse Init): Success (2 buttons).")
        elif ax == 0x0001: # Show mouse pointer
            print(f"[*] INT 33h, AX=0001h (Show Mouse Pointer): Acknowledged.")
            # No visual update for mouse pointer for now.
        elif ax == 0x0002: # Hide mouse pointer
            print(f"[*] INT 33h, AX=0002h (Hide Mouse Pointer): Acknowledged.")
            # No visual update for mouse pointer for now.
        elif ax == 0x0003: # Get mouse position and status of buttons
            # Dummy values for mouse position
            mouse_x = pygame.mouse.get_pos()[0]
            mouse_y = pygame.mouse.get_pos()[1]
            buttons = pygame.mouse.get_pressed()
            
            button_status = 0
            if buttons[0]: # Left button
                button_status |= 0x01
            if buttons[2]: # Right button (Pygame is L, M, R)
                button_status |= 0x02
            # Middle button (buttons[1]) if needed: button_status |= 0x04

            uc.reg_write(UC_X86_REG_BX, button_status)
            uc.reg_write(UC_X86_REG_CX, mouse_x)
            uc.reg_write(UC_X86_REG_DX, mouse_y)
            print(f"[*] INT 33h, AX=0003h (Get Mouse State): BX={hex(button_status)}, CX={mouse_x}, DX={mouse_y}")
        else:
            print(f"[*] Unhandled INT 33h function: AX={hex(ax)}. Stopping emulation.")
            uc.emu_stop()

    else:
        print(f"[*] Unhandled interrupt: {hex(intno)}. Stopping emulation.")
        uc.emu_stop()
    
def hook_mem_write_vga(uc, access, address, size, value, user_data):
    """
    Hook for monitoring writes to VGA memory (0xA0000-0xBFFFF).
    This function will notify the VGA emulator to update its display.
    """
    # This hook is specifically for UC_HOOK_MEM_WRITE, so 'access' will always be UC_MEM_WRITE.
    # However, a robust check for future-proofing or combining hooks is good.
    if access == UC_MEM_WRITE:
        vga_emulator = user_data['vga_emulator']
        
        # Check if the write falls within the VGA memory range
        # A0000-BFFFF (128KB)
        vga_start = VRAM_GRAPHICS_MODE
        vga_end = VRAM_GRAPHICS_MODE + VGA_MEM_SIZE
        
        # Check for overlap: max(start1, start2) < min(end1, end2)
        # Here, range1 is [address, address + size) and range2 is [vga_start, vga_end)
        if max(address, vga_start) < min(address + size, vga_end):

            vga_emulator.written_mem[address] = value 
            # print(f"[*] VGA Memory Write: 0x{address:X} (size {size})") # Uncomment for verbose VRAM writes
            # Inform the VGA emulator about the write.
            # The emulator will then read the updated data from Unicorn's memory.
            # vga_emulator.vga_memory_write_callback(address, size)
            pass
    
def hook_mem_read_low(uc, access, address, size, value, user_data):
    """
    Hook for debugging reads from low memory (below 0x10000).
    """
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    print(f"[DEBUG_LOW_MEM_READ] CS:IP={hex(current_cs)}:{hex(current_ip)} reads from 0x{address:X} (size {size})")

def hook_mem_write_low(uc, access, address, size, value, user_data):
    """
    Hook for debugging writes to low memory (below 0x10000).
    """
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    # Read the actual bytes being written for more detailed logging
    data_written = uc.mem_read(address, size)
    data_hex = "".join(f"{b:02x}" for b in data_written)
    print(f"[DEBUG_LOW_MEM_WRITE] CS:IP={hex(current_cs)}:{hex(current_ip)} writes to 0x{address:X} (size {size}), value_param={hex(value)}, data_written=0x{data_hex}")

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
    # Based on Ghidra's 4000:0ab5 for fgodmom.exe after decompression.
    FINAL_JMPF_SEGMENT = 0x4000
    FINAL_JMPF_OFFSET_IN_SEGMENT = 0xab5 
    final_jmp_physical_addr = FINAL_JMPF_SEGMENT * 16 + FINAL_JMPF_OFFSET_IN_SEGMENT
    print(f"[*] Calculated final JMPF hook address: {hex(final_jmp_physical_addr)}")

    # Initialize Pygame VGA emulator
    vga_emulator = VGAEmulator(mu)

    # Add hooks
    # Hook just the jmpf instruction. A JMPF is 3 bytes (opcode + segment:offset).
    mu.hook_add(UC_HOOK_CODE, hook_code, begin=final_jmp_physical_addr, end=final_jmp_physical_addr + 3, user_data={'final_jmp_addr': final_jmp_physical_addr})
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_INTR, hook_interrupt, user_data={'vga_emulator': vga_emulator}) # Pass vga_emulator instance to hooks
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write_vga, 
                begin=VRAM_GRAPHICS_MODE, 
                end=VRAM_GRAPHICS_MODE + VGA_MEM_SIZE - 1,
                user_data={'vga_emulator': vga_emulator})
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write_low, 
                begin=0, 
                end=0x10000 - 1,
                user_data={'vga_emulator': vga_emulator})


    # Emulation loop
    running = True
    emu_start_addr = mu.reg_read(UC_X86_REG_CS) * 16 + mu.reg_read(UC_X86_REG_IP)
    instructions_per_step = 50000 # Run Unicorn for 50k instructions at a time, an average 286 would run ~3 MIPS

    # Write initial BIOS Data Area values that are commonly read
    # mu.mem_map(BIOS_DATA_AREA, 0x100, UC_PROT_ALL) # <--- REMOVE THIS LINE
    # The memory at BIOS_DATA_AREA (0x400) is already mapped by the 1MB initial map.
    mu.mem_write(BIOS_DATA_AREA + 0x49, struct.pack("<B", 0x03)) # Default video mode: 80x25 text (0x03)
    mu.mem_write(BIOS_DATA_AREA + 0x10, struct.pack("<H", 0x4400)) # Default equipment list (2 floppies, 80x25 color)
    mu.mem_write(BIOS_DATA_AREA + 0x13, struct.pack("<H", TOTAL_MEM_SIZE // 1024)) # Memory size in KB


    while running:
        # 1. Process Pygame events
        running = vga_emulator.process_input()
        if not running:
            break

        # 2. Bridge Pygame keyboard input to the emulated BIOS keyboard buffer
        #    This is the crucial part that was missing!
        while vga_emulator.pygame_keyboard_buffer:
            ascii_val, scan_code = vga_emulator.pygame_keyboard_buffer.popleft()
            if scan_code == 0x46:
                cur_addr = mu.reg_read(UC_X86_REG_CS) * 16 + mu.reg_read(UC_X86_REG_IP)
                print(f"+ debug {mu.reg_read(UC_X86_REG_CS):X} {mu.reg_read(UC_X86_REG_IP):X}")
                print(vga_emulator.written_mem)
                continue 
            # Push the key into the emulated BIOS buffer
            vga_emulator.push_key_to_bios_buffer(ascii_val, scan_code)
            
            # If the emulator was waiting for a key, and we just provided one, resume it
            if vga_emulator.waiting_for_key:
                print("    Key pushed, resuming Unicorn emulation.")
                vga_emulator.waiting_for_key = False
                mu_is_running = True # Signal that Unicorn can run again

        # 2. Run Unicorn emulation in steps
        try:
            if vga_emulator.waiting_for_key:
                # If waiting for a key, only run emulation after a key is available,
                # or for a short period to allow other interrupts.
                # If AH=01h or AH=07h is waiting, don't restart until key is buffered.
                # If AH=0Ah is waiting, wait for user to press ENTER.
                if vga_emulator.keyboard_input_func_al == 0x0A:
                    # Check if ENTER key was pressed to signal end of input
                    enter_pressed = False
                    for event in pygame.event.get(): # Re-process events to check for ENTER
                        if event.type == pygame.KEYDOWN and event.key == pygame.K_RETURN:
                            enter_pressed = True
                            break
                    
                    if enter_pressed:
                        # Simulate input for AH=0Ah
                        # For a real implementation, you'd collect characters typed into a buffer
                        # and then write that buffer to the emulated memory.
                        # For demonstration, let's inject a fixed string.
                        input_string = "TEST INPUT\r" # Example input
                        # Fill the buffer from the emulated program with this string
                        dx = mu.reg_read(UC_X86_REG_DX)
                        ds = mu.reg_read(UC_X86_REG_DS)
                        buffer_addr = ds * 16 + dx
                        max_len = mu.mem_read(buffer_addr, 1)[0]
                        
                        string_to_write = input_string[:max_len-1].encode('cp437', errors='ignore') # -1 for CR
                        actual_len = len(string_to_write)
                        
                        mu.mem_write(buffer_addr + 2, string_to_write) # Write string content
                        mu.mem_write(buffer_addr + 1, bytes([actual_len])) # Write actual length
                        
                        vga_emulator.waiting_for_key = False
                        vga_emulator.keyboard_input_func_al = 0x00 # Clear flag
                        print(f"    AH=0Ah: Injected '{string_to_write.decode('cp437')}' (len {actual_len}). Resuming emulation.")
                        
                elif vga_emulator.get_buffered_key(remove=False):
                    vga_emulator.waiting_for_key = False # A key is now available
                    print(f"    Key detected. Resuming emulation.")
                else:
                    # Still waiting for a key, don't resume Unicorn.
                    # Just keep rendering the screen.
                    vga_emulator.render_frame()
                    pygame.time.Clock().tick(30) # Limit frame rate when waiting
                    continue # Skip Unicorn emulation in this iteration
            
            # Continue emulation from current CS:IP
            current_cs = mu.reg_read(UC_X86_REG_CS)
            current_ip = mu.reg_read(UC_X86_REG_IP)
            mu.emu_start(current_cs * 16 + current_ip, TOTAL_MEM_SIZE, count=instructions_per_step)

        except UcError as e:
            print(f"[*] Emulation stopped with error: {e}")
            running = False # Stop the main loop
            # Print registers for debugging
            print(f"    CS:IP = {hex(mu.reg_read(UC_X86_REG_CS))}:{hex(mu.reg_read(UC_X86_REG_IP))}")
            print(f"    EFLAGS: {hex(mu.reg_read(UC_X86_REG_EFLAGS))}")
            print(f"    AX: {hex(mu.reg_read(UC_X86_REG_AX))}, BX: {hex(mu.reg_read(UC_X86_REG_BX))}, CX: {hex(mu.reg_read(UC_X86_REG_CX))}, DX: {hex(mu.reg_read(UC_X86_REG_DX))}")
            print(f"    SI: {hex(mu.reg_read(UC_X86_REG_SI))}, DI: {hex(mu.reg_read(UC_X86_REG_DI))}, BP: {hex(mu.reg_read(UC_X86_REG_BP))}")
            print(f"    DS: {hex(mu.reg_read(UC_X86_REG_DS))}, ES: {hex(mu.reg_read(UC_X86_REG_ES))}, SS: {hex(mu.reg_read(UC_X86_REG_SS))}, SP: {hex(mu.reg_read(UC_X86_REG_SP))}")


        # 3. Render the VGA display
        vga_emulator.render_frame()
        
        # 4. Control frame rate
        pygame.time.Clock().tick(60) # Limit to 60 FPS

    print("[*] Emulation loop terminated.")
    pygame.quit() # Clean up Pygame

if __name__ == "__main__":
    extract_lz91_exe(FILENAME)
