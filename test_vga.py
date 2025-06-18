import pygame
import struct

# --- Mock Unicorn Engine for Testing ---
# This class simulates the parts of Unicorn we need: mem_map and mem_read.
class MockUnicorn:
    def __init__(self, mem_size):
        self.memory = bytearray(mem_size)

    def mem_map(self, address, size):
        # In a real scenario, you might check for overlaps, but for this test, it's a no-op.
        pass

    def mem_read(self, address, size):
        # Return a slice of the simulated memory.
        return bytes(self.memory[address : address + size])

    def mem_write(self, address, data):
        # Write data into the simulated memory.
        end = address + len(data)
        self.memory[address:end] = data

# --- Minimal VGA Constants for the Test ---
VRAM_GRAPHICS_MODE = 0xA0000
VGA_MEM_SIZE = 0x20000 # 128KB
VGA_PALETTE_16_COLORS = [
    (0, 0, 0), (0, 0, 170), (0, 170, 0), (0, 170, 170),
    (170, 0, 0), (170, 0, 170), (170, 85, 0), (170, 170, 170),
    (85, 85, 85), (85, 85, 255), (85, 255, 85), (85, 255, 255),
    (255, 85, 85), (255, 85, 255), (255, 255, 85), (255, 255, 255) # 15 = White
]

# --- A simplified VGAEmulator with only the necessary parts for rendering ---
class VGARenderTest:
    def __init__(self, uc_emulator):
        self.uc = uc_emulator
        self.screen = None
        self.current_mode = None
        self.display_width = 0
        self.display_height = 0
        self.vram_base = 0
        self.is_text_mode = False
        # Use the real palette for the test
        self.palette_16_color = list(VGA_PALETTE_16_COLORS)

    def set_mode(self, mode_id):
        self.current_mode = mode_id
        print(f"Setting video mode: {hex(mode_id)}")

        if mode_id == 0x10: # 640x350 16-color graphics mode
            self.display_width = 640
            self.display_height = 350
            self.vram_base = VRAM_GRAPHICS_MODE
            self.is_text_mode = False
        else:
            raise ValueError(f"This test only supports mode 0x10, not {hex(mode_id)}")

        self.screen = pygame.display.set_mode((self.display_width, self.display_height))
        pygame.display.set_caption(f"VGA Render Test (Mode {hex(self.current_mode)})")
        self.screen.fill((0, 0, 0)) # Start with a black screen
        pygame.display.flip()

    def render_frame(self):
        """The exact rendering logic from your main emulator to be tested."""
        if self.screen is None or self.is_text_mode:
            return

        # Simplified VRAM read for the test
        read_size = VGA_MEM_SIZE
        try:
            vram_data = self.uc.mem_read(self.vram_base, read_size)
        except Exception as e:
            print(f"Error reading VRAM: {e}")
            return

        if self.current_mode == 0x10:
            plane_size = 32768 # 32KB per plane in our model
            width_in_bytes = self.display_width // 8

            for y in range(self.display_height):
                for x in range(self.display_width):
                    offset = (y * width_in_bytes) + (x // 8)
                    bit_pos = 7 - (x % 8)
                    
                    # Check bounds to prevent reading past our allocated memory
                    if (offset + 3 * plane_size) >= len(vram_data):
                       continue

                    # Read the byte from each of the four planes
                    byte_p0 = vram_data[offset]
                    byte_p1 = vram_data[offset + plane_size]
                    byte_p2 = vram_data[offset + 2 * plane_size]
                    byte_p3 = vram_data[offset + 3 * plane_size]

                    # Extract the single bit for our pixel from each plane's byte
                    bit0 = (byte_p0 >> bit_pos) & 1
                    bit1 = (byte_p1 >> bit_pos) & 1
                    bit2 = (byte_p2 >> bit_pos) & 1
                    bit3 = (byte_p3 >> bit_pos) & 1

                    color_index = (bit3 << 3) | (bit2 << 2) | (bit1 << 1) | bit0
                    color_rgb = self.palette_16_color[color_index]
                    self.screen.set_at((x, y), color_rgb)
        
        pygame.display.flip()
        print("Render frame complete.")


def run_render_test():
    """Main function to set up and run the rendering test."""
    pygame.init()

    # 1. Create mock instances
    mock_uc = MockUnicorn(1024 * 1024) # 1MB of memory
    vga_test = VGARenderTest(mock_uc)

    # Map the VGA memory region in our mock Unicorn
    mock_uc.mem_map(VRAM_GRAPHICS_MODE, VGA_MEM_SIZE)

    # 2. Set the video mode
    vga_test.set_mode(0x10)

    # 3. Manually write test data to VRAM to draw a white rectangle
    # We want to draw a 100x50 rectangle at position (50, 50) with color 15 (white)
    print("Writing test pattern to mock VRAM...")
    
    # Color 15 is binary 1111. This means we need to set the corresponding
    # pixel bits to 1 in ALL FOUR planes.
    rect_x, rect_y = 50, 50
    rect_w, rect_h = 100, 50
    
    plane_size = 32768
    width_in_bytes = vga_test.display_width // 8

    # To set a bit to 1, we use a bitwise OR.
    # We can pre-calculate the data for all planes.
    plane0_data = bytearray(plane_size)
    plane1_data = bytearray(plane_size)
    plane2_data = bytearray(plane_size)
    plane3_data = bytearray(plane_size)

    for y in range(rect_y, rect_y + rect_h):
        for x in range(rect_x, rect_x + rect_w):
            offset = (y * width_in_bytes) + (x // 8)
            bit_mask = 1 << (7 - (x % 8))
            
            # Since color is 15 (1111b), all plane bits are 1
            plane0_data[offset] |= bit_mask
            plane1_data[offset] |= bit_mask
            plane2_data[offset] |= bit_mask
            plane3_data[offset] |= bit_mask

    # Write the prepared plane data into the mock Unicorn's memory
    mock_uc.mem_write(VRAM_GRAPHICS_MODE, plane0_data)
    mock_uc.mem_write(VRAM_GRAPHICS_MODE + plane_size, plane1_data)
    mock_uc.mem_write(VRAM_GRAPHICS_MODE + 2 * plane_size, plane2_data)
    mock_uc.mem_write(VRAM_GRAPHICS_MODE + 3 * plane_size, plane3_data)
    
    print("Test pattern written. Rendering...")

    # 4. Call render_frame and run the Pygame loop
    vga_test.render_frame()

    running = True
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            if event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE:
                running = False
    
    pygame.quit()

if __name__ == '__main__':
    run_render_test()
