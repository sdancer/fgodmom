# test_vga.py
import pygame
from unicorn import *
from unicorn.x86_const import *

# Import the VGAEmulator class and constants from your bios.py file
try:
    from bios import VGAEmulator, VRAM_GRAPHICS_MODE, VGA_MEM_SIZE, VGA_PALETTE_16_COLORS
except ImportError:
    print("Error: Make sure 'bios.py' is in the same directory as this script.")
    exit()

# --- Unicorn and Memory Setup ---
# Although we are calling the handler directly, the VGAEmulator still needs a
# uc object to initialize, and it's good practice to have the memory mapped.
RAM_BASE = 0x0000
RAM_SIZE = 1024 * 1024

def initialize_emulator():
    """Sets up the Unicorn CPU and memory maps."""
    print("Initializing Unicorn CPU and memory...")
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(RAM_BASE, RAM_SIZE)
    print("Unicorn setup complete.")
    return uc

def draw_palette_test(vga: VGAEmulator):
    """
    Draws 16 squares, one for each color in the VGA palette, to test
    the full range of color drawing logic.
    """
    print("\n--- Running LOW-LEVEL Palette Test ---")
    
    # 1. Set a planar graphics mode to test the complex write logic.
    MODE_640x350 = 0x10
    vga.set_mode(MODE_640x350)
    print(f"Set video mode to {hex(MODE_640x350)} (640x350, 16 colors)")

    # 2. Configure VGA registers for drawing. We will use Write Mode 2.
    print("Configuring VGA for drawing using Write Mode 2...")
    vga.handle_port_write(0x3CE, 5)    # Select GC Mode Register
    vga.handle_port_write(0x3CF, 2)    # Set Write Mode 2
    vga.handle_port_write(0x3CE, 8)    # Select GC Bit Mask Register
    vga.handle_port_write(0x3CF, 0xFF) # Enable all bits for now

    # 3. Define layout for the squares
    grid_cols = 4
    grid_rows = 4
    square_size = 60
    padding = 20
    start_x = 40
    start_y = 20
    width_in_bytes = vga.display_width // 8

    # 4. Loop through all 16 colors and draw a square for each
    for color_index in range(16):
        print(f"Drawing square for Color Index: {color_index}")

        # Set the drawing color using the Set/Reset register
        vga.handle_port_write(0x3CE, 0) # Select GC Set/Reset Register
        vga.handle_port_write(0x3CF, color_index)

        # Calculate the position of this square in the grid
        grid_col = color_index % grid_cols
        grid_row = color_index // grid_cols
        
        square_x = start_x + grid_col * (square_size + padding)
        square_y = start_y + grid_row * (square_size + padding)

        # Draw the square pixel by pixel
        for y in range(square_y, square_y + square_size):
            for x in range(square_x, square_x + square_size):
                # Calculate VRAM address and the bit mask for this specific pixel
                offset = y * width_in_bytes + (x // 8)
                bit_mask = 1 << (7 - (x % 8))

                # Directly call the handler to simulate a VRAM write.
                # In WM2, the 'value' written is the bitmask specifying which pixel(s) to paint.
                # The size argument is 1 for a byte write.
                vga.handle_vram_write(VRAM_GRAPHICS_MODE + offset, 1, bit_mask)

    print("--- Low-level palette drawing instructions sent. ---")

def main():
    """Main function to run the test."""
    pygame.init()
    
    uc = initialize_emulator()
    vga = VGAEmulator(uc)
    
    # Run the low-level palette drawing test
    draw_palette_test(vga)
    
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
