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

def set_game_palette(uc: Uc, vga: VGAEmulator):
    """
    Simulates the specific sequence of palette-setting calls made by the game,
    based on the provided startup log.
    """
    print("\n--- Simulating Game Palette Setup ---")

    # Log: [*] INT 10h, AH=10 AL=00 1678:33C, Set Palette Register 0 to value 0x0
    # This is a standard call to set a single palette register.
    uc.reg_write(UC_X86_REG_AH, 0x10)
    uc.reg_write(UC_X86_REG_AL, 0x00)
    uc.reg_write(UC_X86_REG_BL, 0)    # Palette register index 0
    uc.reg_write(UC_X86_REG_BH, 0)    # Color value 0
    # In a real scenario, we would trigger an interrupt. Here, we can call the handler.
    # For simplicity, we can also just call the underlying vga method.
    vga.palette_16_color[0] = vga._decode_ega_palette_color(0)
    print("Set palette register 0 to 0x0")

    # Log: [*] INT 10h, AH=10 AL=02 1678:11D, Set All Palette Registers from 0x47cf7
    # This call sets all 16 registers from a block of memory.
    palette_data_addr = 0x47CF7
    palette_bytes = bytearray(b'\x00\x01\x00\x00\x04\x07\x00\x00\x00\x01\x00\x00\x04\x07\x00\x00')
    # Write this data into Unicorn's memory so the handler can read it.
    uc.mem_write(palette_data_addr, bytes(palette_bytes))
    # Simulate the INT 10h call
    uc.reg_write(UC_X86_REG_AH, 0x10)
    uc.reg_write(UC_X86_REG_AL, 0x02)
    uc.reg_write(UC_X86_REG_ES, palette_data_addr >> 4)      # Segment part
    uc.reg_write(UC_X86_REG_DX, palette_data_addr & 0x000F)  # Offset part
    # We can call the vga method directly to simulate the handler's action
    for i in range(16):
        vga.palette_16_color[i] = vga._decode_ega_palette_color(palette_bytes[i])
    print(f"Set all palette registers from memory block: {vga.palette_16_color}")

    # Log: A series of individual palette register sets that override the block
    print("Overriding specific palette registers...")
    # Log: [*] INT 10h, AH=10 AL=00 F000:10, Set Palette Register 9 to value 0x27
    vga.palette_16_color[9] = vga._decode_ega_palette_color(0x27)
    print(f"  Set palette register 9 to 0x27 -> {vga.palette_16_color[9]}")

    # Log: [*] INT 10h, AH=10 AL=00 F000:10, Set Palette Register 1 to value 0x9
    vga.palette_16_color[1] = vga._decode_ega_palette_color(0x09)
    print(f"  Set palette register 1 to 0x09 -> {vga.palette_16_color[1]}")
    
    # Log: [*] INT 10h, AH=10 AL=00 F000:10, Set Palette Register 3 to value 0xb
    vga.palette_16_color[3] = vga._decode_ega_palette_color(0x0B)
    print(f"  Set palette register 3 to 0x0B -> {vga.palette_16_color[3]}")
    
    # Log: [*] INT 10h, AH=10 AL=00 1678:11D, Set Palette Register 0 to value 0x0
    vga.palette_16_color[0] = vga._decode_ega_palette_color(0) # This is redundant but in the log
    print(f"  Set palette register 0 to 0x0 -> {vga.palette_16_color[0]}")

    print("--- Game Palette Setup Complete ---")
    print(f"Final Palette State: {vga.palette_16_color}")


def draw_palette_test(vga: VGAEmulator):
    """
    Draws 16 squares, one for each color in the VGA palette, to test
    the full range of color drawing logic.
    """
    print("\n--- Running LOW-LEVEL Palette Test ---")
    
    # 1. Set a planar graphics mode
    MODE_640x350 = 0x10
    vga.set_mode(MODE_640x350)
    print(f"Set video mode to {hex(MODE_640x350)}")

    # 2. Configure VGA registers for drawing.
    print("Configuring VGA for drawing using Write Mode 2...")
    vga.handle_port_write(0x3CE, 5)    # Set Write Mode 2
    vga.handle_port_write(0x3CF, 2)
    vga.handle_port_write(0x3CE, 8) # Enable all bits
    vga.handle_port_write(0x3CF, 0xff)

    # 3. Define layout for the squares
    grid_cols, grid_rows = 4, 4
    square_size, padding = 60, 20
    start_x, start_y = 40, 20
    width_in_bytes = vga.display_width // 8

    # 4. Loop through all 16 colors and draw a square for each
    for color_index in range(16):
        # Set the drawing color using the Set/Reset register
        vga.handle_port_write(0x3CE, 0)
        vga.handle_port_write(0x3CF, color_index)

        # Calculate the position of this square in the grid
        grid_col = color_index % grid_cols
        grid_row = color_index // grid_cols
        square_x = start_x + grid_col * (square_size + padding)
        square_y = start_y + grid_row * (square_size + padding)

        # Draw the square pixel by pixel
        for y in range(square_y, square_y + square_size):
            for x in range(square_x, square_y + square_size):
                offset = y * width_in_bytes + (x // 8)
                bit_mask = 1 << (7 - (x % 8))
                vga.handle_vram_write(VRAM_GRAPHICS_MODE + offset, 1, bit_mask)

    print("--- Low-level palette drawing instructions sent. ---")

def main():
    """Main function to run the test."""
    pygame.init()
    
    uc = initialize_emulator()
    vga = VGAEmulator(uc)
    
    # Set the video mode first
    vga.set_mode(0x10)
    
    # NOW, apply the game's specific palette
    set_game_palette(uc, vga)
    
    # Then draw the test pattern
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
        vga.render_frame()
        clock.tick(60)

    print("Exiting.")
    pygame.quit()

if __name__ == "__main__":
    main()
