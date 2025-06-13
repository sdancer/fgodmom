import struct
import time

from unicorn import *
from unicorn.x86_const import *# Helper function to convert segment:offset to linear address

def seg_offset_to_linear(uc, segment_reg, offset_reg):
    segment = uc.reg_read(segment_reg)
    offset = uc.reg_read(offset_reg)
    return (segment << 4) + offset, segment, offset

def handle_ioctl(uc):
    """
    Handles DOS INT 21h, AH=44h (IOCTL) calls.
    Provides detailed debug prints based on the AL subfunction.
    Assumes success for all emulated calls unless specified.
    """
    al = uc.reg_read(UC_X86_REG_AL)
    # Read common registers that might be used by various subfunctions
    dx = uc.reg_read(UC_X86_REG_DX)
    bx = uc.reg_read(UC_X86_REG_BX)
    cx = uc.reg_read(UC_X86_REG_CX)
    ds = uc.reg_read(UC_X86_REG_DS)
    es = uc.reg_read(UC_X86_REG_ES)

    print(f"    IOCTL: AL=0x{al:02X} (", end="")

    return_ax = 0x0000 # Default to AX=0 for success
    clear_cf = True    # Default to clearing Carry Flag for success

    # Decode AL subfunctions
    if al == 0x00: # Get Device Data (Input)
        print(f"Get Device Data (Input). Handle: 0x{dx:04X}).", end="")
        # Often returns DX as device info. For debug, just acknowledge.
    elif al == 0x01: # Set Device Data (Output)
        print(f"Set Device Data (Output). Handle: 0x{dx:04X}).", end="")
    elif al == 0x02: # Read from Control Device
        print(f"Read from Control Device. Handle: 0x{dx:04X}).", end="")
    elif al == 0x03: # Write to Control Device
        print(f"Write to Control Device. Handle: 0x{dx:04X}).", end="")
    elif al == 0x04: # Get Device Information (Handle)
        print(f"Get Device Information (Handle: 0x{dx:04X}).", end="")
        # Common return for character device like CON: AL=0x80
        uc.reg_write(UC_X86_REG_AL, 0x80)
    elif al == 0x05: # Set Device Information (Handle)
        print(f"Set Device Information (Handle: 0x{dx:04X}, Info: 0x{cx:04X}).", end="")
    elif al == 0x06: # Get Input Status
        print(f"Get Input Status (Handle: 0x{dx:04X}).", end="")
        uc.reg_write(UC_X86_REG_AL, 0xFF) # Assume input is available (AL=0xFF)
    elif al == 0x07: # Get Output Status
        print(f"Get Output Status (Handle: 0x{dx:04X}).", end="")
        uc.reg_write(UC_X86_REG_AL, 0xFF) # Assume output is ready (AL=0xFF)
    elif al == 0x08: # Is Device Removable?
        bl = uc.reg_read(UC_X86_REG_BL) # Drive number (0=default, 1=A, 2=B, etc.)
        print(f"Is Device Removable? (Drive: {bl}).", end="")
        uc.reg_write(UC_X86_REG_AL, 0x01) # Assume fixed disk (AL=0x01)
    elif al == 0x09: # Is Handle Local or Remote?
        print(f"Is Handle Local/Remote? (Handle: 0x{dx:04X}).", end="")
        uc.reg_write(UC_X86_REG_AL, 0x00) # Assume local (AL=0x00)
    elif al == 0x0A: # Set Sharing Retry Count
        print(f"Set Sharing Retry Count (Handle: 0x{dx:04X}, Count: 0x{cx:04X}).", end="")
    elif al == 0x0B: # Generic IOCTL for Handles
        # DX = file handle
        # CX = bytes count for read/write or subfunction code
        # DS:DX -> input data buffer (if reading/setting info)
        # ES:BX -> output data buffer (if writing/getting info)
        input_ptr_linear, input_ds_val, input_dx_val = seg_offset_to_linear(uc, UC_X86_REG_DS, UC_X86_REG_DX)
        output_ptr_linear, output_es_val, output_bx_val = seg_offset_to_linear(uc, UC_X86_REG_ES, UC_X86_REG_BX)
        print(f"Generic IOCTL (Handle-based). Handle: 0x{dx:04X}, Bytes/Func: 0x{cx:04X}. "
              f"InBuf: {input_ds_val:04X}:{input_dx_val:04X} (0x{input_ptr_linear:X}), "
              f"OutBuf: {output_es_val:04X}:{output_bx_val:04X} (0x{output_ptr_linear:X})).", end="")
    elif al == 0x0C: # Generic IOCTL for Devices
        # CH = category code, CL = function code
        # DS:DX -> input data buffer
        # ES:BX -> output data buffer
        ch = uc.reg_read(UC_X86_REG_CH)
        cl = uc.reg_read(UC_X86_REG_CL)
        input_ptr_linear, input_ds_val, input_dx_val = seg_offset_to_linear(uc, UC_X86_REG_DS, UC_X86_REG_DX)
        output_ptr_linear, output_es_val, output_bx_val = seg_offset_to_linear(uc, UC_X86_REG_ES, UC_X86_REG_BX)
        print(f"Generic IOCTL (Device-based). Cat: 0x{ch:02X}, Func: 0x{cl:02X}. "
              f"InBuf: {input_ds_val:04X}:{input_dx_val:04X} (0x{input_ptr_linear:X}), "
              f"OutBuf: {output_es_val:04X}:{output_bx_val:04X} (0x{output_ptr_linear:X})).", end="")
        # For these generic calls, specific sub-functions (CH/CL) might require further emulation
        # or more specific debug prints based on common uses (e.g., disk geometry).
    elif al == 0x0D: # Get Logical Drive Map
        print("Get Logical Drive Map).", end="")
        uc.reg_write(UC_X86_REG_BX, 0b111) # Assume A, B, C drives are mapped
    elif al == 0x0E: # Set Logical Drive Map
        print(f"Set Logical Drive Map (Map: 0x{bx:04X}).", end="")
    elif al == 0x0F: # Get Drive Parameters
        bl = uc.reg_read(UC_X86_REG_BL) # Drive number
        output_ptr_linear, output_es_val, output_bx_val = seg_offset_to_linear(uc, UC_X86_REG_ES, UC_X86_REG_BX)
        print(f"Get Drive Parameters (Drive: {bl}). OutBuf: {output_es_val:04X}:{output_bx_val:04X} (0x{output_ptr_linear:X})).", end="")
        # This one often requires writing a fake Drive Parameter Block to the ES:BX buffer.
        # For simple debug, just acknowledge.
    else:
        print(f"Unknown/Unimplemented).", end="")

    print(" Acknowledged, returning success.")

    # Set AX and EFLAGS for success
    uc.reg_write(UC_X86_REG_AX, return_ax)
    eflags = uc.reg_read(UC_X86_REG_EFLAGS)
    if clear_cf:
        eflags &= ~0x0001 # Clear Carry Flag (CF) for success
    else:
        eflags |= 0x0001 # Set Carry Flag (CF) for error (though we default to success here)
    uc.reg_write(UC_X86_REG_EFLAGS, eflags)

def handle_int21(uc, vga_emulator):
    """Handles INT 21h (DOS Services) calls."""
    ah = uc.reg_read(UC_X86_REG_AH)
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    print(f"[*] INT 21h, AH={hex(ah)} {current_cs:X}:{current_ip:X} ")

    if ah == 0x01: # Read character from standard input, with echo
        key_data = vga_emulator.pop_key_from_bios_buffer()
        if key_data:
            ascii_val, scan_code = key_data
            uc.reg_write(UC_X86_REG_AL, ascii_val)
            print(f"    Read char (with echo): '{chr(ascii_val)}'")
            # Echo the character to screen
            vga_emulator.write_char_teletype(ascii_val)
        else:
            # If no char, signal that the emulator should wait for a key
            print(f"    Waiting for key (INT 21h AH=01h)...")
            vga_emulator.waiting_for_key = True
            uc.emu_stop() # Stop emulation until key is pressed

    elif ah == 0x02: # Write character to standard output
        dl = uc.reg_read(UC_X86_REG_DL)
        vga_emulator.write_char_teletype(dl)
        uc.reg_write(UC_X86_REG_AL, dl) # AL = DL on return
        print(f"    Write char: '{chr(dl)}'")

    elif ah == 0x05: # Output character to printer (dummy)
        dl = uc.reg_read(UC_X86_REG_DL)
        print(f"    Printer output (dummy): '{chr(dl)}'")
        uc.reg_write(UC_X86_REG_AL, dl)

    elif ah == 0x06: # Direct console input or output
        dl = uc.reg_read(UC_X86_REG_DL)
        if dl == 0xFF: # Input (non-blocking)
            key_data = vga_emulator.pop_key_from_bios_buffer() # Use pop for non-blocking read
            if key_data:
                ascii_val, scan_code = key_data
                uc.reg_write(UC_X86_REG_AL, ascii_val)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)
                eflags &= ~0x0040 # Clear ZF (Zero Flag)
                uc.reg_write(UC_X86_REG_EFLAGS, eflags)
                print(f"    Direct input: '{chr(ascii_val)}'")
            else:
                uc.reg_write(UC_X86_REG_AL, 0x00) # No character
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)
                eflags |= 0x0040 # Set ZF
                uc.reg_write(UC_X86_REG_EFLAGS, eflags)
                print(f"    Direct input: No character available (ZF set).")
        else: # Output
            vga_emulator.write_char_teletype(dl)
            uc.reg_write(UC_X86_REG_AL, dl)
            print(f"    Direct output: '{chr(dl)}'")

    elif ah == 0x07: # Character input without echo to AL (blocking)
        key_data = vga_emulator.pop_key_from_bios_buffer()
        if key_data:
            ascii_val, scan_code = key_data
            uc.reg_write(UC_X86_REG_AL, ascii_val)
            print(f"    Read char (no echo): '{chr(ascii_val)}'")
        else:
            print(f"    Waiting for key (INT 21h AH=07h)...")
            vga_emulator.waiting_for_key = True
            uc.emu_stop() # Stop emulation until key is pressed

    elif ah == 0x09: # Output string
        dx = uc.reg_read(UC_X86_REG_DX)
        ds = uc.reg_read(UC_X86_REG_DS)
        try:
            addr = ds * 16 + dx
            s = b""
            while True:
                byte = uc.mem_read(addr, 1)
                if byte[0] == 0x24: # '$' terminator
                    break
                s += byte
                addr += 1
            decoded_s = s.decode('cp437', errors='ignore') # Use CP437 for DOS
            print(f"    Output string: '{decoded_s}'")
            # Write char by char using teletype func
            for char_code in s:
                vga_emulator.write_char_teletype(char_code)
        except UcError:
            print(f"    Failed to read string from {hex(ds)}:{hex(dx)}. Stopping.")
            uc.emu_stop()

    elif ah == 0x0A: # Buffered keyboard input
        dx = uc.reg_read(UC_X86_REG_DX)
        ds = uc.reg_read(UC_X86_REG_DS)
        buffer_addr = ds * 16 + dx
        
        # Read max buffer size (first byte)
        max_len = uc.mem_read(buffer_addr, 1)[0]
        
        print(f"    Buffered input (AH=0Ah): Max {max_len} chars. Waiting for ENTER...")
        
        # This is a simplification. A real implementation would handle line editing (backspace, enter)
        # by iteratively processing keys from the BIOS buffer and writing them to the DOS buffer.
        # For now, we'll block and assume the next ENTER from Pygame finishes the line.
        
        vga_emulator.waiting_for_key = True # Indicate that we need input
        vga_emulator.keyboard_input_func_al = ah # Store the subfunction for resume logic
        # Store buffer address for resume logic (hacky, ideally part of emulator state)
        uc.mem_write(BIOS_DATA_AREA + 0x40, struct.pack("<I", buffer_addr)) 
        
        uc.emu_stop() # Stop and wait for user to press enter in pygame loop

    elif ah == 0x0B: # Get input status (non-blocking)
        if not vga_emulator.is_bios_kb_buffer_empty():
            uc.reg_write(UC_X86_REG_AL, 0xFF) # Character available
            print(f"    Input status: Character available (AL=FFh).")
        else:
            uc.reg_write(UC_X86_REG_AL, 0x00) # No character
            print(f"    Input status: No character (AL=00h).")

    elif ah == 0x0C: # Flush keyboard buffer and read standard input
        al_subfunc = uc.reg_read(UC_X86_REG_AL)
        vga_emulator.flush_bios_keyboard_buffer()
        print(f"    Flush buffer, then call input func {hex(al_subfunc)}")
        # Dispatch to the specific input function if AL is valid
        if al_subfunc in [0x01, 0x06, 0x07, 0x08, 0x0A]: # 0x08 is DOS 1.0 read char
            # Simulate the dispatch by calling the handler directly.
            # This is a slight re-entry but works for this context.
            # Need to restore AH after the inner call, or just let it be.
            original_ah = uc.reg_read(UC_X86_REG_AH)
            uc.reg_write(UC_X86_REG_AH, al_subfunc)
            handle_int21(uc, vga_emulator)
            uc.reg_write(UC_X86_REG_AH, original_ah) # Restore original AH
        else:
            print(f"    Invalid subfunction for AH=0Ch: {hex(al_subfunc)}. Buffer flushed, no input.")

    elif ah == 0x0E: # Select default drive
        dl = uc.reg_read(UC_X86_REG_DL) # New default drive (0=A:, 1=B:, etc)
        # Dummy implementation, just print
        print(f"    Select default drive: {chr(ord('A') + dl)}")
        # Return total number of valid drive letters (e.g., 26 for A-Z)
        uc.reg_write(UC_X86_REG_AL, 0x1A) # Assuming 26 drives A-Z
    
    elif ah == 0x19: # Get current default drive
        # Dummy implementation, return drive C: (2)
        uc.reg_write(UC_X86_REG_AL, 0x02) # C:
        print(f"    Get current default drive: {chr(ord('A') + 0x02)}")

    elif ah == 0x25: # Set Interrupt Vector
        al = uc.reg_read(UC_X86_REG_AL)
        dx = uc.reg_read(UC_X86_REG_DX) # New offset
        ds = uc.reg_read(UC_X86_REG_DS) # New segment
        vector_addr = al * 4 
        try:
            uc.mem_write(vector_addr, struct.pack("<H", dx))
            uc.mem_write(vector_addr + 2, struct.pack("<H", ds))
            print(f"    Set Interrupt Vector {hex(al)}h: To {hex(ds)}:{hex(dx)}")
        except UcError:
            print(f"    Failed to write vector to 0:{hex(vector_addr)}. Stopping.")
            uc.emu_stop()

    elif ah == 0x2A: # Get system date
        # Return dummy date (e.g., Jan 1, 2000, Saturday)
        uc.reg_write(UC_X86_REG_CX, 2000) # Year
        uc.reg_write(UC_X86_REG_DH, 1)    # Month (1=Jan)
        uc.reg_write(UC_X86_REG_DL, 1)    # Day (1)
        uc.reg_write(UC_X86_REG_AL, 6)    # Day of week (6=Sat)
        print(f"    Get system date: 2000-01-01 (Sat)")

    elif ah == 0x2C: # Get system time
        # Return dummy time (e.g., 10:30:00.00)
        uc.reg_write(UC_X86_REG_CH, 10) # Hour
        uc.reg_write(UC_X86_REG_CL, 30) # Minute
        uc.reg_write(UC_X86_REG_DH, 0)  # Second
        uc.reg_write(UC_X86_REG_DL, 0)  # 1/100 seconds
        print(f"    Get system time: 10:30:00.00")

    elif ah == 0x35: # Get Interrupt Vector
        al = uc.reg_read(UC_X86_REG_AL)
        vector_addr = al * 4
        try:
            vector_offset = struct.unpack("<H", uc.mem_read(vector_addr, 2))[0]
            vector_segment = struct.unpack("<H", uc.mem_read(vector_addr + 2, 2))[0]
            print(f"    Get Interrupt Vector {hex(al)}h: Returns {hex(vector_segment)}:{hex(vector_offset)}")
            uc.reg_write(UC_X86_REG_ES, vector_segment)
            uc.reg_write(UC_X86_REG_BX, vector_offset)
        except UcError:
            print(f"    Failed to read vector from 0:{hex(vector_addr)}. Stopping.")
            uc.emu_stop()
            
    elif ah == 0x39: # Make Directory (dummy)
        ds = uc.reg_read(UC_X86_REG_DS)
        dx = uc.reg_read(UC_X86_REG_DX)
        path_addr = ds * 16 + dx
        try:
            path_bytes = uc.mem_read(path_addr, 256) # Read a generous buffer
            path = path_bytes.split(b'\x00')[0].decode('cp437', errors='ignore')
            print(f"    Make directory (dummy): '{path}' - Success")
            eflags = uc.reg_read(UC_X86_REG_EFLAGS)
            eflags &= ~0x0001 # Clear CF for success
            uc.reg_write(UC_X86_REG_EFLAGS, eflags)
        except UcError:
            print(f"    Failed to read path for MKDIR from {hex(path_addr)}. Setting CF.")
            eflags = uc.reg_read(UC_X86_REG_EFLAGS)
            eflags |= 0x0001 # Set CF for error
            uc.reg_write(UC_X86_REG_EFLAGS, eflags)
            uc.reg_write(UC_X86_REG_AX, 0x0003) # Path not found (dummy error)

    elif ah == 0x4C: # Terminate with return code
        al = uc.reg_read(UC_X86_REG_AL)
        print(f"    Terminate Program (return code {hex(al)}). Stopping emulation.")
        uc.emu_stop()

    elif ah == 0x44: # IOCTL (Input/Output Control)
        al = uc.reg_read(UC_X86_REG_AL)
        print(f"    IOCTL: AL={hex(al)}. Acknowledged, returning success.")
        uc.reg_write(UC_X86_REG_AX, 0x0000) # Set AX to 0 for success

        handle_ioctl(uc)
        eflags = uc.reg_read(UC_X86_REG_EFLAGS)
        eflags &= ~0x0001 # Clear Carry Flag (CF)
        uc.reg_write(UC_X86_REG_EFLAGS, eflags)
        
    else:
        print(f"    Unhandled INT 21h function: AH={hex(ah)}. Stopping emulation.")
        uc.emu_stop()
