# test_vga.py
import pygame
from unicorn import *
from unicorn.x86_const import *

# Import the VGAEmulator class and constants from your bios.py file
try:
    from bios import VGAEmulator, VRAM_GRAPHICS_MODE, VGA_MEM_SIZE
except ImportError:
    print("Error: Make sure 'bios.py' is in the same directory as this script.")
    exit()

# --- Unicorn and Memory Setup ---
RAM_BASE = 0x0000
RAM_SIZE = 1024 * 1024

def initialize_emulator():
    """Sets up the Unicorn CPU and memory maps."""
    print("Initializing Unicorn CPU and memory...")
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(RAM_BASE, RAM_SIZE)
    print("Unicorn setup complete.")
    return uc

def draw_square_low_level(uc: Uc, vga: VGAEmulator):
    """
    Simulates a DOS program drawing a square by manipulating VGA registers
    and writing directly to VRAM, triggering the low-level hooks.
    This test uses Mode 0x10 (planar) to test handle_vram_write.
    """
    print("\n--- Running LOW-LEVEL Square Drawing Test ---")
    
    # 1. Set a planar graphics mode to test the complex write logic.
    MODE_640x350 = 0x10
    vga.set_mode(MODE_640x350)
    print(f"Set video mode to {hex(MODE_640x350)} (640x350, 16 colors)")

    # 2. Define square properties.
    square_x, square_y, square_size = 100, 50, 80
    border_color_idx = 4  # Red
    fill_color_idx = 12 # Light Red

    # --- SIMULATE DOS PROGRAM DRAWING LOGIC ---

    # A. Clear the screen to black (Color 0)
    # This is a good test for Write Mode 2
    print("Clearing screen to black (Color 0) using WM2...")
    vga.handle_port_write(0x3CE, 5) # Select GC Mode Register
    vga.handle_port_write(0x3CF, 2) # Set Write Mode 2
    vga.handle_port_write(0x3CE, 0) # Select GC Set/Reset Register
    vga.handle_port_write(0x3CF, 0) # Set color to 0 (Black)
    vga.handle_port_write(0x3CE, 8) # Select GC Bit Mask Register
    vga.handle_port_write(0x3CF, 0xFF) # Enable all bits
    
    # Write 0xFF to every byte in VRAM to trigger the clear
    width_in_bytes = 640 // 8
    for y in range(350):
        for i in range(width_in_bytes):
            offset = y * width_in_bytes + i
            # This write will be intercepted by handle_vram_write
            vga.handle_vram_write(VRAM_GRAPHICS_MODE + offset, b'\xFF'[0], 1)

    # B. Draw the filled rectangle (Light Red)
    print(f"Drawing filled rectangle with Light Red (Color {fill_color_idx}) using WM2...")
    vga.handle_port_write(0x3CE, 0) # Select GC Set/Reset Register
    vga.handle_port_write(0x3CF, fill_color_idx) # Set color to Light Red
    
    for y in range(square_y, square_y + square_size):
        for x in range(square_x, square_x + square_size):
            # Calculate VRAM address and the bit for this pixel
            offset = y * width_in_bytes + (x // 8)
            bit_mask = 1 << (7 - (x % 8))
            # Write the bit mask to the VRAM address. In WM2, this tells the
            # VGA "paint this specific pixel with the Set/Reset color".
            vga.handle_vram_write(VRAM_GRAPHICS_MODE + offset, bytes([bit_mask])[0], 1)

    # C. Draw the border (Red)
    print(f"Drawing border with Red (Color {border_color_idx}) using WM2...")
    vga.handle_port_write(0x3CE, 0) # Select GC Set/Reset Register
    vga.handle_port_write(0x3CF, border_color_idx) # Set color to Red

    # Top and bottom borders
    for x in range(square_x, square_x + square_size):
        # Top pixel
        offset_top = square_y * width_in_bytes + (x // 8)
        bit_mask_top = 1 << (7 - (x % 8))
        vga.handle_vram_write(VRAM_GRAPHICS_MODE + offset_top, bytes([bit_mask_top])[0], 1)
        # Bottom pixel
        offset_bot = (square_y + square_size - 1) * width_in_bytes + (x // 8)
        bit_mask_bot = 1 << (7 - (x % 8))
        vga.handle_vram_write(VRAM_GRAPHICS_MODE + offset_bot, bytes([bit_mask_bot])[0], 1)

    # Left and right borders
    for y in range(square_y, square_y + square_size):
        # Left pixel
        offset_left = y * width_in_bytes + (square_x // 8)
        bit_mask_left = 1 << (7 - (square_x % 8))
        vga.handle_vram_write(VRAM_GRAPHICS_MODE + offset_left, bytes([bit_mask_left])[0], 1)
        # Right pixel
        offset_right = y * width_in_bytes + ((square_x + square_size - 1) // 8)
        bit_mask_right = 1 << (7 - ((square_x + square_size - 1) % 8))
        vga.handle_vram_write(VRAM_GRAPHICS_MODE + offset_right, bytes([bit_mask_right])[0], 1)

    print("--- Low-level drawing instructions sent. ---")
    print("--- VRAM should be modified via handle_vram_write hook. ---")


def main():
    """Main function to run the test."""
    pygame.init()
    
    uc = initialize_emulator()
    vga = VGAEmulator(uc)

    # --- Setup Unicorn Hooks ---
    # This is the most important part. We hook the memory write events
    # in the VGA memory region so they get passed to our handler.
    uc.hook_add(UC_HOOK_MEM_WRITE, 
                lambda uc, type, address, size, value, user_data: vga.handle_vram_write(address, size, value),
                begin=VRAM_GRAPHICS_MODE, 
                end=VRAM_GRAPHICS_MODE + VGA_MEM_SIZE - 1)
    print("Unicorn memory write hook for VRAM is now active.")

    # Run the low-level drawing test
    draw_square_low_level(uc, vga)
    
    # Main Pygame Loop to render the results
    print("\nStarting main display loop. Press ESC or close the window to exit.")
    running = True
    clock = pygame.time.Clock()
    
    while running:
        if not vga.process_input():
            running = False
            
        keys = pygame.key.get_pressed()
        if keys[pygame.K_ESCAPE]:
            running = False

        # ONLY use render_frame to visualize the VRAM state
        vga.render_frame()

        clock.tick(60)

    print("Exiting.")
    pygame.quit()


if __name__ == "__main__":
    main()
