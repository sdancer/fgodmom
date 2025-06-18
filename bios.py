import struct
import time
import collections # For deque, a double-ended queue for keyboard buffer

from unicorn import *
from unicorn.x86_const import *
import pygame
import random

# --- BIOS/DOS Data Areas (common for emulators) ---
BIOS_DATA_AREA = 0x400 # Segment 0x40, physical 0x400

# Keyboard buffer constants (standard 16 entries * 2 bytes/entry = 32 bytes)
KB_BUFFER_START_OFFSET = 0x6C # Offset within segment 0x40
KB_BUFFER_END_OFFSET = KB_BUFFER_START_OFFSET + (16 * 2) # End + 1
KB_BUFFER_HEAD_PTR = 0x1E # Offset for head pointer (word)
KB_BUFFER_TAIL_PTR = 0x20 # Offset for tail pointer (word)
KB_BUFFER_START_ADDR = BIOS_DATA_AREA + KB_BUFFER_START_OFFSET
KB_BUFFER_END_ADDR = BIOS_DATA_AREA + KB_BUFFER_END_OFFSET
KB_BUFFER_HEAD_ADDR = BIOS_DATA_AREA + KB_BUFFER_HEAD_PTR
KB_BUFFER_TAIL_ADDR = BIOS_DATA_AREA + KB_BUFFER_TAIL_PTR


# --- Global VGA Memory Addresses ---
VRAM_TEXT_COLOR_MODE = 0xB8000 # For text modes like 0x03
VRAM_GRAPHICS_MODE = 0xA0000 # For graphics modes like 0x13
VGA_MEM_SIZE = 0x20000 # 128KB, covers A0000-BFFFF

# For now, let's include a minimal printable ASCII set (32-126) for demonstration.
# This part is tedious to type out, but critical for text mode.
# I will use a simplified font generation for common characters if a full font isn't pasted.
# A common trick is to use a TrueType font and render characters as bitmaps.
# For simplicity, let's create a *very* basic ASCII font here.
# For example, 'A' (65):
# 0x00, 0x00, 0x18, 0x24, 0x42, 0x42, 0x7E, 0x00 # A
# This will be replaced with a more robust font loading or a small hardcoded one.
# For now, I'll use a placeholder and warn about it.

# VGA 16-color palette (RGB tuples)
VGA_PALETTE_16_COLORS = [
    (0x00, 0x00, 0x00), # 0 - Black
    (0x00, 0x00, 0xA8), # 1 - Blue
    (0x00, 0xA8, 0x00), # 2 - Green
    (0x00, 0xA8, 0xA8), # 3 - Cyan
    (0xA8, 0x00, 0x00), # 4 - Red
    (0xA8, 0x00, 0xA8), # 5 - Magenta
    (0xA8, 0x54, 0x00), # 6 - Brown/Dark Yellow
    (0xA8, 0xA8, 0xA8), # 7 - Light Gray
    (0x54, 0x54, 0x54), # 8 - Dark Gray
    (0x54, 0x54, 0xFC), # 9 - Light Blue
    (0x54, 0xFC, 0x54), # A - Light Green
    (0x54, 0xFC, 0xFC), # B - Light Cyan
    (0xFC, 0x54, 0x54), # C - Light Red
    (0xFC, 0x54, 0xFC), # D - Light Magenta
    (0xFC, 0xFC, 0x54), # E - Yellow
    (0xFC, 0xFC, 0xFC), # F - White
]

# In a real game, this palette would be loaded.
VGA_PALETTE_256_COLORS = [(i, i, i) for i in range(256)]


class VGAEmulator:
    def _encode_ega_palette_color(self, rgb_tuple):
        """
        Encodes a 24-bit (R,G,B) tuple into the closest matching 6-bit EGA color.
        This is the inverse of _decode_ega_palette_color.
        """
        r, g, b = rgb_tuple
        # This is a simple "closest match" approach.
        # Find the closest 2-bit index (0-3) for each 8-bit color component (0-255).
        r_index = min(range(4), key=lambda i: abs(i * 85 - r))
        g_index = min(range(4), key=lambda i: abs(i * 85 - g))
        b_index = min(range(4), key=lambda i: abs(i * 85 - b))

        # Extract high and low bits from the indices
        r_prime, r_low = (r_index >> 1) & 1, r_index & 1
        g_prime, g_low = (g_index >> 1) & 1, g_index & 1
        b_prime, b_low = (b_index >> 1) & 1, b_index & 1

        # Pack the bits into the R'G'B'RGB format
        ega_color = (r_prime << 5) | (g_prime << 4) | (b_prime << 3) | \
                    (r_low   << 2) | (g_low   << 1) | (b_low   << 0)
        
        return ega_color
    def _decode_ega_palette_color(self, ega_color):
        """
        Decodes a 6-bit EGA palette value (format R'G'B'RGB) into a 24-bit RGB tuple.
        This is a corrected and clearer implementation.
        """
        # Intensity levels for each 2-bit value: 0%, 33%, 66%, 100%
        # A more standard mapping uses 0, 85, 170, 255.
        color_levels = [0, 85, 170, 255]

        # Extract the individual R,G,B and R',G',B' bits.
        r = (ega_color >> 2) & 1
        g = (ega_color >> 1) & 1
        b = (ega_color >> 0) & 1
        
        r_prime = (ega_color >> 5) & 1
        g_prime = (ega_color >> 4) & 1
        b_prime = (ega_color >> 3) & 1

        # Combine the high and low bits to form a 2-bit index for each color.
        # high bit (prime) is the most significant bit.
        r_index = (r_prime << 1) | r
        g_index = (g_prime << 1) | g
        b_index = (b_prime << 1) | b
        
        # Look up the final 8-bit color component from the intensity levels.
        final_r = color_levels[r_index]
        final_g = color_levels[g_index]
        final_b = color_levels[b_index]
        
        return (final_r, final_g, final_b)

    def __init__(self, uc_emulator):
        self.uc = uc_emulator
        self.screen = None
        self.current_mode = None
        self.display_width = 0
        self.display_height = 0
        self.char_width = 8
        self.char_height = 8 # Default for 8x8 font
        self.cursor_row = 0
        self.cursor_col = 0
        self.cursor_start_line = 6 # Default BIOS cursor
        self.cursor_end_line = 7
        self.cursor_visible = True
        self.active_page = 0 # For text modes
        self.palette_16_color = list(VGA_PALETTE_16_COLORS) 

        # Keyboard buffer for Pygame events (this is distinct from the emulated BIOS buffer)
        self.pygame_keyboard_buffer = collections.deque()
        self.waiting_for_key = False # Flag to indicate if we're waiting for a key (from uc.emu_stop)
        self.keyboard_input_func_al = 0x00 # Store which AH=0Ah function is waiting, if any

        # Prepare a simple 8x8 font surface for drawing characters
        self.font_surfaces = {}
        self._load_simple_font()

        # Initialize with a default mode (e.g., 80x25 text mode)
        self.set_mode(0x03)

        # Initialize BIOS Keyboard Buffer pointers (must be done in Unicorn's memory)
        # These are standard addresses in the BIOS Data Area (segment 0x40)
        # 0x40:0x1A = Buffer start offset (word)
        # 0x40:0x1C = Buffer end offset (word)
        # 0x40:0x1E = Head pointer (next key to read) (word)
        # 0x40:0x20 = Tail pointer (next key to write) (word)
        
        # Set buffer start and end addresses in BDA
        self.uc.mem_write(BIOS_DATA_AREA + 0x1A, struct.pack("<H", KB_BUFFER_START_OFFSET))
        self.uc.mem_write(BIOS_DATA_AREA + 0x1C, struct.pack("<H", KB_BUFFER_END_OFFSET)) # End + 1
        
        # Initialize head and tail pointers to the start of the buffer (empty)
        self.uc.mem_write(KB_BUFFER_HEAD_ADDR, struct.pack("<H", KB_BUFFER_START_OFFSET))
        self.uc.mem_write(KB_BUFFER_TAIL_ADDR, struct.pack("<H", KB_BUFFER_START_OFFSET))

        self.gc_index = 0         # The index selected via port 0x3CE
        self.gc_registers = [0] * 9 # GC has 9 registers (0-8)

        # We can add other controllers (Sequencer, Attribute, CRTC) as needed.
        self.sequencer_index = 0
        self.sequencer_registers = [0] * 5 # Sequencer has 5 registers (0-4)

        print(f"    BIOS Keyboard Buffer initialized: Head={hex(KB_BUFFER_START_OFFSET)}, Tail={hex(KB_BUFFER_START_OFFSET)}")

    def _load_simple_font(self):
        """
        Creates Pygame surfaces for a simple 8x8 font.
        Crucially, it handles CP437 to Unicode mapping for better DOS text display.
        """
        # A basic 8x8 font for ASCII 32-126
        _font_data = {
            # space
            32: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            # !
            33: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], # Placeholder
            # A
            65: [0x18, 0x24, 0x42, 0x42, 0x7E, 0x42, 0x42, 0x00],
            # a
            97: [0x00, 0x00, 0x00, 0x38, 0x44, 0x44, 0x3C, 0x00],
            # Minimal digits for testing
            48: [0x3C, 0x42, 0x42, 0x42, 0x42, 0x42, 0x3C, 0x00], # 0
            49: [0x08, 0x18, 0x08, 0x08, 0x08, 0x08, 0x3C, 0x00], # 1
            50: [0x3C, 0x42, 0x02, 0x04, 0x08, 0x10, 0x7E, 0x00], # 2
            51: [0x3C, 0x42, 0x02, 0x1C, 0x02, 0x42, 0x3C, 0x00], # 3
            52: [0x0C, 0x14, 0x24, 0x44, 0x7E, 0x04, 0x04, 0x00], # 4
            53: [0x7E, 0x40, 0x7C, 0x02, 0x02, 0x42, 0x3C, 0x00], # 5
            54: [0x3C, 0x40, 0x7C, 0x44, 0x44, 0x44, 0x3C, 0x00], # 6
            55: [0x7E, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x00], # 7
            56: [0x3C, 0x42, 0x42, 0x3C, 0x42, 0x42, 0x3C, 0x00], # 8
            57: [0x3C, 0x42, 0x42, 0x3E, 0x02, 0x04, 0x38, 0x00], # 9
            # Minimal box-drawing characters for testing
            0xC9: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], # ╔ - placeholder for now
            0xBB: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], # ╗
            0xC8: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], # ╚
            0xBC: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], # ╝
            0xCD: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], # ═
            0xBA: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], # ║
        }

        # Pygame default font fallback for missing chars
        try:
            # Use a slightly larger font for better visibility, and let it scale down
            pygame_font = pygame.font.Font(None, 16) # Increased size for better visibility
            self.char_height = 16 # Adjust cell height to accommodate larger font
            print(f"DEBUG: Using Pygame default font for fallback, size 16.")
        except Exception as e:
            pygame_font = None # Fallback if font init fails
            print(f"DEBUG: Failed to load Pygame font: {e}")
            self.char_height = 8 # Revert to default if font fails

        for char_code in range(256):
            char_data = _font_data.get(char_code)
            if char_data:
                # Create a surface for the hardcoded 8x8 character bitmap
                char_surface = pygame.Surface((8, 8), pygame.SRCALPHA) # Always 8x8 for hardcoded
                char_surface.fill((0,0,0,0)) # Transparent background
                for y in range(8): # Iterate 8 rows for hardcoded font
                    row_pixels = char_data[y]
                    for x in range(8): # Iterate 8 columns
                        if (row_pixels >> (7 - x)) & 1: # Check bit
                            char_surface.set_at((x, y), (255, 255, 255, 255))
                self.font_surfaces[char_code] = char_surface
            elif pygame_font:
                try:
                    # For characters not in _font_data, use Pygame's font.
                    # Convert CP437 char_code to Unicode for pygame.font.render
                    # This is CRUCIAL for correctly displaying extended ASCII (e.g., box-drawing chars).
                    unicode_char = bytes([char_code]).decode('cp437', errors='replace') # 'replace' for unknown glyphs
                    
                    text_surf = pygame_font.render(unicode_char, False, (255, 255, 255))
                    
                    # Scale or center the rendered text within the character cell
                    if text_surf.get_width() > self.char_width or text_surf.get_height() > self.char_height:
                         text_surf = pygame.transform.scale(text_surf, (self.char_width, self.char_height))
                    else: # Center small characters in the cell
                        centered_surf = pygame.Surface((self.char_width, self.char_height), pygame.SRCALPHA)
                        x_offset = (self.char_width - text_surf.get_width()) // 2
                        y_offset = (self.char_height - text_surf.get_height()) // 2
                        centered_surf.blit(text_surf, (x_offset, y_offset))
                        text_surf = centered_surf

                    self.font_surfaces[char_code] = text_surf
                except Exception as e:
                    print(f"DEBUG: Failed to render char {char_code} ({bytes([char_code]).decode('cp437', errors='replace')}) with Pygame font: {e}")
                    # Fallback for characters pygame.font can't render
                    self.font_surfaces[char_code] = pygame.Surface((self.char_width, self.char_height), pygame.SRCALPHA)
            else:
                # Empty surface for unsupported characters without Pygame font
                self.font_surfaces[char_code] = pygame.Surface((self.char_width, self.char_height), pygame.SRCALPHA)

    def set_mode(self, mode_id):
        """Sets the active video mode and configures Pygame display."""
        if self.current_mode == mode_id:
            return

        self.current_mode = mode_id
        print(f"    Setting video mode: {hex(mode_id)}")

        # Crucial: Use self.char_height for text mode dimensions
        if mode_id == 0x00: # 40x25 text mode
            self.display_width = 40 * self.char_width
            self.display_height = 25 * self.char_height # Use self.char_height
            self.vram_base = VRAM_TEXT_COLOR_MODE
            self.is_text_mode = True
            self.chars_per_row = 40
            self.rows = 25
        elif mode_id == 0x03: # 80x25 text mode (common)
            self.display_width = 80 * self.char_width
            self.display_height = 25 * self.char_height # Use self.char_height
            self.vram_base = VRAM_TEXT_COLOR_MODE
            self.is_text_mode = True
            self.chars_per_row = 80
            self.rows = 25
        elif mode_id == 0x10: # 640x350 16-color graphics mode (EGA/VGA)
            self.display_width = 640 
            self.display_height = 350 
            self.vram_base = VRAM_GRAPHICS_MODE # Starts at 0xA0000
            self.is_text_mode = False
            self.reset_vga_registers() 
        elif mode_id == 0x13: # 320x200 256-color graphics mode
            self.display_width = 320
            self.display_height = 200
            self.vram_base = VRAM_GRAPHICS_MODE
            self.is_text_mode = False
            self.reset_vga_registers() 
        else:
            print(f"        Unsupported video mode: {hex(mode_id)}. Defaulting to 80x25 text.")
            self.current_mode = 0x03 # Fallback
            self.display_width = 80 * self.char_width
            self.display_height = 25 * self.char_height # Use self.char_height
            self.vram_base = VRAM_TEXT_COLOR_MODE
            self.is_text_mode = True
            self.chars_per_row = 80
            self.rows = 25

        # Create/resize Pygame screen
        if self.screen is None or \
           self.screen.get_width() != self.display_width or \
           self.screen.get_height() != self.display_height:
            self.screen = pygame.display.set_mode((self.display_width * 2, self.display_height * 2))
            self.logical_screen = pygame.Surface((self.display_width, self.display_height))
            pygame.display.set_caption(f"Unicorn DOS Emulator (Mode {hex(self.current_mode)})")

        # Clear screen on mode change
        self.screen.fill((0, 0, 0))
        pygame.display.flip()

    def set_cursor_shape(self, ch, cl):
        self.cursor_start_line = ch & 0x1F # bits 0-4
        self.cursor_end_line = cl & 0x1F # bits 0-4
        self.cursor_visible = (ch & 0x20) == 0 # bit 5: 0=visible, 1=hidden
        print(f"    Set cursor shape: start={self.cursor_start_line}, end={self.cursor_end_line}, visible={self.cursor_visible}")

    def set_cursor_position(self, row, col, page):
        self.cursor_row = row
        self.cursor_col = col
        self.active_page = page
        print(f"    Set cursor position: row={self.cursor_row}, col={self.cursor_col}, page={self.active_page}")

    def get_cursor_position(self):
        return self.cursor_row, self.cursor_col, self.cursor_start_line, self.cursor_end_line

    def write_char_teletype(self, char_code, attribute=0x07): # default light gray on black
        """Writes a character to current cursor position, advances cursor, scrolls if needed."""
        self.write_char_and_attribute(char_code, attribute, self.cursor_row, self.cursor_col, self.active_page, 1)

        # Advance cursor
        self.cursor_col += 1
        if self.cursor_col >= self.chars_per_row:
            self.cursor_col = 0
            self.cursor_row += 1
            if self.cursor_row >= self.rows:
                # Scroll up the window
                self._scroll_window(1, 0, 0, self.rows - 1, self.chars_per_row - 1, attribute, "up")
                self.cursor_row = self.rows - 1 # Keep cursor at the last row

    def write_char_and_attribute(self, char_code, attribute, row, col, page, count):
        """Writes char+attr to VRAM directly, multiple times."""
        if not self.is_text_mode:
            print(f"    Warning: Tried to write text in graphics mode. Skipping.")
            return

        # Ensure coordinates are within bounds before writing to VRAM
        if not (0 <= row < self.rows and 0 <= col < self.chars_per_row):
            # print(f"    Warning: Tried to write char at out-of-bounds position ({row},{col}). Skipping.")
            return

        # Calculate the starting address for the character and attribute pair
        # Each page is chars_per_row * rows * 2 bytes long.
        page_size = self.chars_per_row * self.rows * 2
        
        # Check if the requested page is valid based on typical VRAM size for text modes
        # A common text VRAM region is 32KB (0xB8000 - 0xBFFFF).
        # With 80x25 (4000 bytes/page), max 8 pages fit. With 40x25 (2000 bytes/page), max 16 pages fit.
        # Let's cap pages to 8 for now.
        max_pages = 8 # A reasonable max for standard 32KB text VRAM
        if not (0 <= page < max_pages):
            print(f"    Warning: Tried to write char to out-of-bounds page {page}. Skipping.")
            return

        vram_addr = self.vram_base + (page * page_size) + (row * self.chars_per_row + col) * 2 # 2 bytes per char (char, attr)
        
        # Ensure the write doesn't exceed the total VGA_MEM_SIZE
        if vram_addr + (count * 2) > (self.vram_base + VGA_MEM_SIZE):
            print(f"    Warning: VRAM write out of total mapped memory range at {hex(vram_addr)}. Truncating.")
            count = (self.vram_base + VGA_MEM_SIZE - vram_addr) // 2
            if count <= 0:
                return

        for _ in range(count):
            try:
                self.uc.mem_write(vram_addr, bytes([char_code, attribute]))
            except UcError as e:
                print(f"    Error writing to VRAM at {hex(vram_addr)}: {e}")
                break
            vram_addr += 2

    def write_pixel(self, x, y, color):
        """Writes a pixel in graphics mode."""
        if self.is_text_mode:
            print(f"    Warning: Tried to write pixel in text mode. Skipping.")
            return
        if not (0 <= x < self.display_width and 0 <= y < self.display_height):
            return # Out of bounds

        # For mode 13h, each pixel is 1 byte in VRAM
        vram_addr = self.vram_base + y * self.display_width + x
        try:
            self.uc.mem_write(vram_addr, bytes([color]))
        except UcError as e:
            print(f"    Error writing pixel to VRAM at {hex(vram_addr)}: {e}")

    def read_pixel(self, x, y):
        """Reads a pixel in graphics mode."""
        if self.is_text_mode:
            print(f"    Warning: Tried to read pixel in text mode. Returning 0.")
            return 0
        if not (0 <= x < self.display_width and 0 <= y < self.display_height):
            return 0 # Out of bounds

        vram_addr = self.vram_base + y * self.display_width + x
        try:
            color = self.vram[vram_addr]
            return color
        except UcError as e:
            print(f"    Error reading pixel from VRAM at {hex(vram_addr)}: {e}")
            return 0

    def read_char_and_attribute(self, row, col, page):
        """Reads char+attr from VRAM."""
        if not self.is_text_mode:
            print(f"    Warning: Tried to read char/attr in graphics mode. Skipping.")
            return 0x20, 0x07 # Space, light gray

        if not (0 <= row < self.rows and 0 <= col < self.chars_per_row):
            # print(f"    Warning: Tried to read char at out-of-bounds position ({row},{col}). Returning default.")
            return 0x20, 0x07

        page_size = self.chars_per_row * self.rows * 2
        max_pages = 8 # A reasonable max for standard 32KB text VRAM
        if not (0 <= page < max_pages):
            print(f"    Warning: Tried to read char from out-of-bounds page {page}. Returning default.")
            return 0x20, 0x07


        vram_addr = self.vram_base + (page * page_size) + (row * self.chars_per_row + col) * 2
        
        # Ensure the read doesn't exceed the total VGA_MEM_SIZE
        if vram_addr + 2 > (self.vram_base + VGA_MEM_SIZE):
            print(f"    Warning: VRAM read out of total mapped memory range at {hex(vram_addr)}. Returning default.")
            return 0x20, 0x07

        try:
            data = self.uc.mem_read(vram_addr, 2)
            char_code = data[0]
            attribute = data[1]
            return char_code, attribute
        except UcError as e:
            print(f"    Error reading from VRAM at {hex(vram_addr)}: {e}")
            return 0x20, 0x07 # Space, light gray

    def _scroll_window(self, num_lines, row_ul, col_ul, row_lr, col_lr, attribute, direction):
        """Simulates window scrolling by moving VRAM content."""
        if not self.is_text_mode:
            print(f"    Warning: Tried to scroll in graphics mode. Skipping.")
            return
        
        # Clamp coordinates to screen dimensions
        row_ul = max(0, min(row_ul, self.rows - 1))
        col_ul = max(0, min(col_ul, self.chars_per_row - 1))
        row_lr = max(0, min(row_lr, self.rows - 1))
        col_lr = max(0, min(col_lr, self.chars_per_row - 1))

        # Ensure UL is indeed Upper-Left and LR is Lower-Right
        row_ul, row_lr = min(row_ul, row_lr), max(row_ul, row_lr)
        col_ul, col_lr = min(col_ul, col_lr), max(col_ul, col_lr)

        if num_lines == 0: # Clear entire window
            for r in range(row_ul, row_lr + 1):
                for c in range(col_ul, col_lr + 1):
                    self.write_char_and_attribute(0x20, attribute, r, c, self.active_page, 1)
            return

        window_height = row_lr - row_ul + 1
        window_width = col_lr - col_ul + 1

        if window_height <= 0 or window_width <= 0:
            return # Invalid window

        bytes_per_row_in_window = window_width * 2
        
        page_offset = self.active_page * self.chars_per_row * self.rows * 2

        if direction == "up":
            # Move lines up
            for r in range(row_ul, row_lr + 1 - num_lines):
                # Copy line (r + num_lines) to line r
                src_vram_start = self.vram_base + page_offset + ((r + num_lines) * self.chars_per_row + col_ul) * 2
                dest_vram_start = self.vram_base + page_offset + (r * self.chars_per_row + col_ul) * 2
                try:
                    # Check if read/write are within mapped memory
                    if src_vram_start + bytes_per_row_in_window <= self.vram_base + VGA_MEM_SIZE and \
                       dest_vram_start + bytes_per_row_in_window <= self.vram_base + VGA_MEM_SIZE:
                        line_data = self.uc.mem_read(src_vram_start, bytes_per_row_in_window)
                        self.uc.mem_write(dest_vram_start, line_data)
                    else:
                        print(f"    Warning: Scroll up VRAM copy out of mapped memory range. Skipping line.")
                except UcError as e:
                    print(f"    Error during scroll-up memory copy: {e}")

            # Clear bottom lines
            for r in range(row_lr + 1 - num_lines, row_lr + 1):
                for c in range(col_ul, col_lr + 1):
                    self.write_char_and_attribute(0x20, attribute, r, c, self.active_page, 1)
        elif direction == "down":
            # Move lines down
            for r in range(row_lr, row_ul + num_lines - 1, -1):
                # Copy line (r - num_lines) to line r
                src_vram_start = self.vram_base + page_offset + ((r - num_lines) * self.chars_per_row + col_ul) * 2
                dest_vram_start = self.vram_base + page_offset + (r * self.chars_per_row + col_ul) * 2
                try:
                    # Check if read/write are within mapped memory
                    if src_vram_start + bytes_per_row_in_window <= self.vram_base + VGA_MEM_SIZE and \
                       dest_vram_start + bytes_per_row_in_window <= self.vram_base + VGA_MEM_SIZE:
                        line_data = self.uc.mem_read(src_vram_start, bytes_per_row_in_window)
                        self.uc.mem_write(dest_vram_start, line_data)
                    else:
                        print(f"    Warning: Scroll down VRAM copy out of mapped memory range. Skipping line.")
                except UcError as e:
                    print(f"    Error during scroll-down memory copy: {e}")

            # Clear top lines
            for r in range(row_ul, row_ul + num_lines):
                for c in range(col_ul, col_lr + 1):
                    self.write_char_and_attribute(0x20, attribute, r, c, self.active_page, 1)


    def render_frame(self):
        """Renders the current VRAM content to the Pygame screen."""
        if self.screen is None:
            return

        if self.is_text_mode:
            pass
            # Text mode rendering (e.g., 80x25, 40x25)
            page_size = self.chars_per_row * self.rows * 2
            vram_page_start_addr = self.vram_base + (self.active_page * page_size)
            vram_page_start_addr = 0xB8000 + 0xFA0 * 4
            
            # Ensure the read does not go beyond mapped memory
            read_size = page_size
            if vram_page_start_addr + read_size > self.vram_base + VGA_MEM_SIZE:
                read_size = self.vram_base + VGA_MEM_SIZE - vram_page_start_addr
                if read_size < 0: read_size = 0

            
            vram_data = self._vram_view(0, read_size)

            self.screen.fill((0, 0, 0)) # Clear screen
            for row in range(self.rows):
                for col in range(self.chars_per_row):
                    offset = (row * self.chars_per_row + col) * 2
                    if offset + 1 >= len(vram_data): # Check bounds
                        break # Out of VRAM data for this page, stop rendering
                    char_code = vram_data[offset]
                    attribute = vram_data[offset + 1]

                    fg_color_idx = attribute & 0x0F
                    bg_color_idx = (attribute >> 4) & 0x0F
                    
                    fg_color = VGA_PALETTE_16_COLORS[fg_color_idx]
                    bg_color = VGA_PALETTE_16_COLORS[bg_color_idx]

                    # Draw background rectangle
                    pygame.draw.rect(self.screen, bg_color, 
                                     (col * self.char_width, row * self.char_height, 
                                      self.char_width, self.char_height))

                    # Draw character
                    char_surface = self.font_surfaces.get(char_code)
                    if char_surface:
                        # Colorize the character surface
                        temp_char_surface = pygame.Surface(char_surface.get_size(), pygame.SRCALPHA)
                        temp_char_surface.fill(fg_color)
                        temp_char_surface.blit(char_surface, (0,0), None, pygame.BLEND_RGBA_MULT) # Apply color
                        self.screen.blit(temp_char_surface, (col * self.char_width, row * self.char_height))

            # Draw cursor if visible and in current position
            if self.cursor_visible and time.time() % 1.0 < 0.5: # Simple blinking
                cursor_rect = pygame.Rect(self.cursor_col * self.char_width, 
                                          self.cursor_row * self.char_height + self.cursor_start_line, 
                                          self.char_width, 
                                          self.cursor_end_line - self.cursor_start_line + 1)
                pygame.draw.rect(self.screen, VGA_PALETTE_16_COLORS[7], cursor_rect) # Light gray cursor
                # DEBUG: Confirm cursor drawing
                # print(f"DEBUG: Drawing cursor at ({self.cursor_col}, {self.cursor_row})")

        else: # Graphics mode rendering (e.g., 320x200, 256 colors)
           self.render_graph() 
        
        scaled_surface = pygame.transform.scale(self.logical_screen, self.screen.get_size())
        self.screen.blit(scaled_surface, (0, 0))
        pygame.display.flip()

    def _vram_view(self, start, length):
        return self.uc.mem_read(self.vram_base + start, length)

    def render_graph(self): 
            # Read the entire graphics VRAM segment (usually 64KB at 0xA0000)
            # For 640x350x16, each plane is 28,000 bytes. All 4 fit in 112KB,
            # so bank switching is needed. We'll assume the relevant part is mapped.
        plane_size = 32768
        vram_data = self._vram_view(0, plane_size*4)

        if self.current_mode == 0x10:
            plane_size = 32768 # 32KB per plane in our model
            width_in_bytes = self.display_width // 8

            for y in range(self.display_height):
                for x in range(self.display_width):
                    offset = (y * width_in_bytes) + (x // 8)
                    bit_pos = 7 - (x % 8)
                    
                    # Check bounds to prevent reading past our allocated memory
                    if (offset + 3 * plane_size) >= len(vram_data):
                        print("error on render_frame")
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
                    self.logical_screen.set_at((x, y), color_rgb)

             # --- Handle Mode 0x13 (Linear Packed-Pixel) ---
        if self.current_mode == 0x13:
                for y in range(self.display_height):
                    for x in range(self.display_width):
                        offset = y * self.display_width + x
                        if offset >= len(vram_data): break
                        color_index = vram_data[offset]
                        color_rgb = VGA_PALETTE_256_COLORS[color_index]
                        self.logical_screen.set_at((x, y), color_rgb)


    def process_input(self):
        """Processes Pygame events for keyboard input and window management."""
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                return False # Signal to quit emulation
            elif event.type == pygame.KEYDOWN:

                # Store ASCII and Scan Code for INT 16h and INT 21h
                # Ensure ASCII value is from CP437, not system default encoding
                ascii_val = event.unicode.encode('cp437', errors='ignore')[0] if event.unicode else 0
                scan_code = event.scancode # Pygame scancodes often map well enough
                
                # Check for special keys if needed (e.g., Enter, Backspace)
                if event.key == pygame.K_RETURN:
                    ascii_val = 0x0D # Carriage Return
                    scan_code = 0x1C # Enter scan code
                elif event.key == pygame.K_BACKSPACE:
                    ascii_val = 0x08 # Backspace
                    scan_code = 0x0E # Backspace scan code
                elif event.key == pygame.K_TAB:
                    ascii_val = 0x09 # Tab
                    scan_code = 0x0F # Tab scan code
                elif event.key == pygame.K_ESCAPE:
                    ascii_val = 0x1B # Escape
                    scan_code = 0x01 # Standard ESC scan code
                elif event.key == pygame.K_UP:
                    ascii_val = 0x00 # Extended key
                    scan_code = 0x48 # Up arrow scan code
                elif event.key == pygame.K_DOWN:
                    ascii_val = 0x00 # Extended key
                    scan_code = 0x50 # Down arrow scan code
                elif event.key == pygame.K_LEFT:
                    ascii_val = 0x00 # Extended key
                    scan_code = 0x4B # Left arrow scan code
                elif event.key == pygame.K_RIGHT:
                    ascii_val = 0x00 # Extended key
                    scan_code = 0x4D # Right arrow scan code
                elif event.key == pygame.K_F1:
                    ascii_val = 0x00
                    scan_code = 0x3B # F1 scan code
                elif event.key == pygame.K_F12: # New debug key for dumping pages
                    self.dump_all_text_pages_to_console()
                    return True # Don't add F12 to keyboard buffer, just use for debug
                # Add more special keys as needed for the game

                print("storing ascii", hex(ascii_val), "scan_code", hex(scan_code))

                # Add to internal Pygame keyboard buffer
                self.pygame_keyboard_buffer.append((ascii_val, scan_code))
                self.waiting_for_key = False # A key was pressed

        return True # Continue emulation

    # --- BIOS Keyboard Buffer Management ---
    def _read_bios_kb_ptr(self, offset):
        """Reads a word (pointer) from the BIOS keyboard data area."""
        try:
            return struct.unpack("<H", self.uc.mem_read(BIOS_DATA_AREA + offset, 2))[0]
        except UcError as e:
            print(f"    Error reading BIOS KB pointer at {hex(BIOS_DATA_AREA + offset)}: {e}")
            return 0 # Fallback

    def _write_bios_kb_ptr(self, offset, value):
        """Writes a word (pointer) to the BIOS keyboard data area."""
        try:
            self.uc.mem_write(BIOS_DATA_AREA + offset, struct.pack("<H", value))
        except UcError as e:
            print(f"    Error writing BIOS KB pointer at {hex(BIOS_DATA_AREA + offset)}: {e}")

    def is_bios_kb_buffer_empty(self):
        head = self._read_bios_kb_ptr(KB_BUFFER_HEAD_PTR)
        tail = self._read_bios_kb_ptr(KB_BUFFER_TAIL_PTR)
        return head == tail

    def push_key_to_bios_buffer(self, ascii_val, scan_code):
        """Pushes a key (ASCII+ScanCode) into the emulated BIOS keyboard buffer."""
        head = self._read_bios_kb_ptr(KB_BUFFER_HEAD_PTR)
        tail = self._read_bios_kb_ptr(KB_BUFFER_TAIL_PTR)
        
        # Calculate next tail position
        next_tail = tail + 2
        if next_tail >= KB_BUFFER_END_OFFSET: # Wrap around if beyond buffer end
            next_tail = KB_BUFFER_START_OFFSET
        
        if next_tail == head: # Buffer is full
            print(f"    BIOS Keyboard buffer full. Key {hex(ascii_val)} ignored.")
            return False
            
        key_word = (ascii_val << 8) | scan_code
        try:
            self.uc.mem_write(BIOS_DATA_AREA + tail, struct.pack("<H", key_word))
            self._write_bios_kb_ptr(KB_BUFFER_TAIL_PTR, next_tail)
            print(f"    Pushed key to BIOS buffer: ASCII={hex(ascii_val)}, ScanCode={hex(scan_code)}")
            return True
        except UcError as e:
            print(f"    Error writing key to BIOS KB buffer at {hex(BIOS_DATA_AREA + tail)}: {e}")
            return False

    def pop_key_from_bios_buffer(self):
        """Pops a key from the emulated BIOS keyboard buffer."""
        head = self._read_bios_kb_ptr(KB_BUFFER_HEAD_PTR)
        tail = self._read_bios_kb_ptr(KB_BUFFER_TAIL_PTR)

        if head == tail: # Buffer empty
            return None # No key available
        
        try:
            key_word = struct.unpack("<H", self.uc.mem_read(BIOS_DATA_AREA + head, 2))[0]
            
            next_head = head + 2
            if next_head >= KB_BUFFER_END_OFFSET: # Wrap around
                next_head = KB_BUFFER_START_OFFSET
            
            self._write_bios_kb_ptr(KB_BUFFER_HEAD_PTR, next_head)
            
            ascii_val = (key_word >> 8) & 0xFF
            scan_code = key_word & 0xFF
            print(f"    Popped key from BIOS buffer: ASCII={hex(ascii_val)}, ScanCode={hex(scan_code)}")
            return ascii_val, scan_code
        except UcError as e:
            print(f"    Error reading key from BIOS KB buffer at {hex(BIOS_DATA_AREA + head)}: {e}")
            return None

    def peek_key_from_bios_buffer(self):
        """Peeks at the next key in the emulated BIOS keyboard buffer without removing it."""
        head = self._read_bios_kb_ptr(KB_BUFFER_HEAD_PTR)
        tail = self._read_bios_kb_ptr(KB_BUFFER_TAIL_PTR)

        if head == tail: # Buffer empty
            return None # No key available
        
        try:
            key_word = struct.unpack("<H", self.uc.mem_read(BIOS_DATA_AREA + head, 2))[0]
            ascii_val = (key_word >> 8) & 0xFF
            scan_code = key_word & 0xFF
            return ascii_val, scan_code
        except UcError as e:
            print(f"    Error peeking key from BIOS KB buffer at {hex(BIOS_DATA_AREA + head)}: {e}")
            return None

    def flush_bios_keyboard_buffer(self):
        """Flushes the emulated BIOS keyboard buffer."""
        self._write_bios_kb_ptr(KB_BUFFER_HEAD_PTR, KB_BUFFER_START_OFFSET)
        self._write_bios_kb_ptr(KB_BUFFER_TAIL_PTR, KB_BUFFER_START_OFFSET)
        print("    BIOS Keyboard buffer flushed.")

    def reset_vga_registers(self):
            # Reset Graphics Controller registers
            self.gc_registers = [0x00]*9
            self.gc_registers[6] = 0x05    # Misc register
            self.gc_registers[8] = 0xFF    # Bit‑mask defaults to all 1s

            # Reset Sequencer registers
            self.sequencer_registers = [0] * 5 
            # Common defaults for graphics modes:
            self.sequencer_registers[1] = 0x01 # Clocking Mode: Normal operation
            self.sequencer_registers[2] = 0x0F # <<<< THE IMPORTANT ONE: Map Mask, all planes enabled
            self.sequencer_registers[4] = 0x06 # Memory Mode: Extended memory, odd/even disabled
            print("    VGA registers reset to default graphics state (Map Mask = 0x0F).")

    def handle_port_write(self, port, value):
        """
        Handles writes to VGA I/O ports to update the internal register state.
        """
        # Graphics Controller Ports
        if port == 0x3CE:
            self.gc_index = value & 0x0F # Index is usually 4 bits
             #print(f"DEBUG: VGA GC Index set to {self.gc_index}")
        elif port == 0x3CF:
            if self.gc_index < len(self.gc_registers):
                print(f"DEBUG: VGA GC Register {self.gc_index} set to 0x{value:02X}")
                self.gc_registers[self.gc_index] = value
        
        # Sequencer Ports (often used for memory mapping and timing)
        elif port == 0x3C4:
            self.sequencer_index = value & 0x07 # Index is usually 3 bits
            print(f"DEBUG: VGA Sequencer Index set to {self.sequencer_index}")
        elif port == 0x3C5:
            if self.sequencer_index < len(self.sequencer_registers):
                print(f"DEBUG: VGA Sequencer Register {self.sequencer_index} set to 0x{value:02X}")
                self.sequencer_registers[self.sequencer_index] = value
            else:
                print(f"DEBUG: ignoring port {port:X}")

        else:
            print(f"DEBUG: ignoring port {port:X}")
        
    def handle_vram_write(self, address, size, value):
        """
        Hook for VRAM writes. If in a planar graphics mode, divert to the planar logic.
        Otherwise, return False to let the default memory write happen.
        """
        # This logic should only apply to planar graphics modes like 0x10 or 0x12.
        if self.is_text_mode or self.current_mode not in (0x10, 0x12):
            return False  # Let Unicorn handle the write for text/linear modes.

        # Handle multi-byte writes by processing each byte individually.
        for i in range(size):
            byte_to_write = (value >> (i * 8)) & 0xFF
            self._write_planar_byte(address + i, byte_to_write)
        
        return True # We have handled the memory write.

    def _write_planar_byte(self, address, value):
        """
        Handles a memory write to VRAM in a planar graphics mode, applying VGA hardware logic.
        This correctly simulates latching, write modes, bit masks, and map masks.
        """
        # --- 1. Get current VGA register states ---
        map_mask = self.sequencer_registers[2]
        write_mode = self.gc_registers[5] & 0x03
        logical_op = (self.gc_registers[3] >> 3) & 0x03
        bit_mask = self.gc_registers[8]
        set_reset_val = self.gc_registers[0]
        enable_set_reset = self.gc_registers[1]

        # --- 2. Latch Phase ---
        # Calculate the offset within the 64KB VRAM window (0x0000 to 0xFFFF)
        offset_in_window = address - self.vram_base
        plane_size = 32768 # The size of one plane in our memory model

        # The CPU address is always within the A0000-AFFFF range for these modes.
        # We only need to handle offsets within a single plane's address space.
        if not (0 <= offset_in_window < plane_size):
            # In a real VGA, this might wrap or be handled by odd/even mode.
            # For this emulator, we'll ignore writes outside the first 32KB per plane.
            return

        try:
            # Latch (read) the byte from all 4 planes at the target offset.
            latched_bytes = [
                self.uc.mem_read(self.vram_base + offset_in_window, 1)[0],
                self.uc.mem_read(self.vram_base + offset_in_window + plane_size, 1)[0],
                self.uc.mem_read(self.vram_base + offset_in_window + 2 * plane_size, 1)[0],
                self.uc.mem_read(self.vram_base + offset_in_window + 3 * plane_size, 1)[0]
            ]
        except UcError as e:
            print(f"ERROR latching VRAM at addr {hex(address)}: {e}")
            return

        # --- 3. Data Processing Phase ---
        # Figure out what data to write to each plane based on the write mode.
        processed_data = [0] * 4

        if write_mode == 0:
            # For each plane, decide if we use CPU data or expanded Set/Reset data.
            for i in range(4):
                if (enable_set_reset >> i) & 1:
                    # Use Set/Reset: expand the i-th bit of the color to a full byte.
                    processed_data[i] = 0xFF if (set_reset_val >> i) & 1 else 0x00
                else:
                    # Use CPU data directly.
                    processed_data[i] = value

        elif write_mode == 1:
            # Write the latched data back (used for VRAM-to-VRAM copies).
            processed_data = latched_bytes

        elif write_mode == 2:
            # --------------------------- ❶ PREPARE CONSTANTS ---------------------------
            cpu_pattern   = value                    # 8‑bit bit mask from the host
            set_reset     = self.gc_registers[0] & 0x0F
            enable_sr     = self.gc_registers[1] & 0x0F
            bit_mask_reg  = bit_mask                 # GC[8] was already read above
            func_select   = logical_op               # 0 = REPL, 1 = AND, 2 = OR, 3 = XOR
        
            # Expand Set/Reset to four bytes (one per plane)
            sr_expanded = [(0xFF if (set_reset >> p) & 1 else 0x00) for p in range(4)]
        
            # --------------------------- ❷ CALCULATE NEW BYTE PER PLANE ---------------
            for p in range(4):
                map_mask = 14 
                if not ((map_mask >> p) & 1):
                    continue      # this plane is write‑protected
        
                # Select SR or old latched data **per bit** according to cpu_pattern
                src = (sr_expanded[p] & cpu_pattern) | (latched_bytes[p] & ~cpu_pattern)
        
                # Apply logical operation with the original latched data
                if   func_select == 1:  src &= latched_bytes[p]   # AND
                elif func_select == 2:  src |= latched_bytes[p]   # OR
                elif func_select == 3:  src ^= latched_bytes[p]   # XOR
                # func_select == 0 ➜ REPL (already satisfied)
        
                # Apply Bit Mask register – only bits that are ‘1’ may change
                final_byte = (latched_bytes[p] & ~bit_mask_reg) | (src & bit_mask_reg)
        
                # ----------------------- ❸ COMMIT TO VRAM -----------------------------
                plane_addr = self.vram_base + offset_in_window + p*plane_size
                #self.uc.mem_write(plane_addr, bytes([final_byte]))
            return

        elif write_mode == 3:
            # Rotate CPU data, then mask it with the Bit Mask register.
            rotate_count = self.gc_registers[3] & 0x07
            rotated_val = ((value >> rotate_count) | (value << (8 - rotate_count))) & 0xFF
            masked_val = rotated_val & bit_mask
            # This result is applied to all planes.
            for i in range(4):
                processed_data[i] = masked_val

        # --- 4. Write Phase ---
        # Combine processed data with latched data and write back to the enabled planes.
        for i in range(4):
            # Check if this plane is enabled for writing by the Map Mask
            if (map_mask >> i) & 1:
                # Apply the specified logical operation
                write_val = processed_data[i]
                if logical_op == 1:   # AND
                    write_val &= latched_bytes[i]
                elif logical_op == 2: # OR
                    write_val |= latched_bytes[i]
                elif logical_op == 3: # XOR
                    write_val ^= latched_bytes[i]
                # Default (op=0) is a direct move.

                # Apply the Bit Mask: New bits come from write_val, old bits from latched_bytes.
                final_byte = (latched_bytes[i] & ~bit_mask) | (write_val & bit_mask)

                # Finally, write the resulting byte to the plane's memory.
                try:
                    plane_addr = self.vram_base + offset_in_window + (i * plane_size)
                    self.uc.mem_write(plane_addr, bytes([final_byte]))
                except UcError as e:
                    print(f"ERROR writing to plane {i} at {hex(plane_addr)}: {e}")



# Define some placeholder addresses and values for demonstration.
# In a real emulator, these would point to actual loaded ROM/RAM data.
FONT_ROM_SEG = 0xC000 # Common segment for video BIOS ROM
FONT_8X14_OFF = 0x1F00 # Example offset for 8x14 font
FONT_8X8_FIRST_OFF = 0x2000 # Example offset for 8x8 font, first 128 chars
FONT_8X8_SECOND_OFF = 0x2100 # Example offset for 8x8 font, second 128 chars
FONT_9X14_ALT_OFF = 0x2200 # Example offset for 9x14 alternate font
FONT_8X16_OFF = 0x2300 # Example offset for 8x16 font
FONT_9X16_ALT_OFF = 0x2400 # Example offset for 9x16 alternate font

INT_1F_VECTOR_SEG = 0x0000 # Interrupt vector table is at 0000:xxxx
INT_1F_VECTOR_OFF = 0x007C # Offset for Int 1F (0x1F * 4)
INT_43_VECTOR_SEG = 0x0000
INT_43_VECTOR_OFF = 0x010C # Offset for Int 43 (0x43 * 4)

# Placeholder values for CX (character height) and DL (number of rows)
# These vary by font and video mode, but we can use common ones for debug info.
DEFAULT_CHAR_HEIGHT = 16 # Typical for text modes
DEFAULT_NUM_ROWS = 25    # Typical for text modes

def handle_int10_11_30(uc: Uc):
    """
    Handles INT 10h, AH=0x11, AL=0x30: Get Font Information.
    Prints debug information about the font/vector requested and
    simulates setting output registers with placeholder values.

    Args:
        uc (Uc): The Unicorn engine instance.
    """
    al = uc.reg_read(UC_X86_REG_AL)
    bh = uc.reg_read(UC_X86_REG_BH)

    print(f"\n--- INT 10h, AH=0x11, AL=0x{al:02X} (Get Font Information) ---")
    print(f"  Attempting to get information for BH=0x{bh:02X}")

    # Default values for output registers (will be overwritten by cases)
    es_val = 0x0000
    bp_val = 0x0000
    cx_val = DEFAULT_CHAR_HEIGHT
    dl_val = DEFAULT_NUM_ROWS

    info_str = "" # String to describe what was requested

    # Simulate the switch(reg_bh) from DOSBox C code
    if bh == 0x00:
        info_str = "Requesting interrupt 0x1F vector (Video Parameters Pointer)"
        es_val = INT_1F_VECTOR_SEG
        bp_val = INT_1F_VECTOR_OFF
    elif bh == 0x01:
        info_str = "Requesting interrupt 0x43 vector (User-defined Graphics Characters)"
        es_val = INT_43_VECTOR_SEG
        bp_val = INT_43_VECTOR_OFF
    elif bh == 0x02:
        info_str = "Requesting 8x14 font (VGA/EGA)"
        es_val = FONT_ROM_SEG
        bp_val = FONT_8X14_OFF
        cx_val = 14 # 8x14 font height
    elif bh == 0x03:
        info_str = "Requesting 8x8 font (first 128 chars)"
        es_val = FONT_ROM_SEG
        bp_val = FONT_8X8_FIRST_OFF
        cx_val = 8 # 8x8 font height
    elif bh == 0x04:
        info_str = "Requesting 8x8 font (second 128 chars)"
        es_val = FONT_ROM_SEG
        bp_val = FONT_8X8_SECOND_OFF
        cx_val = 8 # 8x8 font height
    elif bh == 0x05:
        info_str = "Requesting Alpha Alternate 9x14 font"
        es_val = FONT_ROM_SEG
        bp_val = FONT_9X14_ALT_OFF
        cx_val = 14 # 9x14 font height
    elif bh == 0x06:
        info_str = "Requesting 8x16 font (VGA/MCGA)"
        es_val = FONT_ROM_SEG
        bp_val = FONT_8X16_OFF
        cx_val = 16 # 8x16 font height
    elif bh == 0x07:
        info_str = "Requesting Alpha Alternate 9x16 font (VGA)"
        es_val = FONT_ROM_SEG
        bp_val = FONT_9X16_ALT_OFF
        cx_val = 16 # 9x16 font height
    else:
        info_str = f"Unsupported or unknown font/vector request (BH=0x{bh:02X})"
        # For unknown requests, BIOS often leaves registers untouched or sets to 0
        es_val = 0x0000
        bp_val = 0x0000
        cx_val = 0x0000
        dl_val = 0x0000
        print(f"  WARNING: {info_str}")

    print(f"  Program attempted: {info_str}")
    print(f"  Simulating BIOS response:")
    print(f"    Setting ES:BP = 0x{es_val:04X}:0x{bp_val:04X} (pointer to data)")
    print(f"    Setting CX    = 0x{cx_val:04X} ({cx_val} scan lines per char)")
    print(f"    Setting DL    = 0x{dl_val:02X} ({dl_val} text rows on screen)")

    # Write the values back to the Unicorn registers
    uc.reg_write(UC_X86_REG_ES, es_val)
    uc.reg_write(UC_X86_REG_BP, bp_val)
    uc.reg_write(UC_X86_REG_CX, cx_val)
    uc.reg_write(UC_X86_REG_DL, dl_val)

def _handle_int10_ah00_set_mode(uc, vga_emulator):
    """Handles INT 10h, AH=00h: Set Video Mode."""
    al = uc.reg_read(UC_X86_REG_AL)
    vga_emulator.set_mode(al)
    uc.mem_write(BIOS_DATA_AREA + 0x49, struct.pack("<B", al))
    uc.reg_write(UC_X86_REG_AL, 0x00) # Often returns 0 on success
    return True

def _handle_int10_ah01_set_cursor_type(uc, vga_emulator):
    """Handles INT 10h, AH=01h: Set Cursor Type."""
    ch = uc.reg_read(UC_X86_REG_CH)
    cl = uc.reg_read(UC_X86_REG_CL)
    vga_emulator.set_cursor_shape(ch, cl)
    return True

def _handle_int10_ah02_set_cursor_pos(uc, vga_emulator):
    """Handles INT 10h, AH=02h: Set Cursor Position."""
    bh = uc.reg_read(UC_X86_REG_BH) # Page number
    dh = uc.reg_read(UC_X86_REG_DH) # Row
    dl = uc.reg_read(UC_X86_REG_DL) # Column
    vga_emulator.set_cursor_position(dh, dl, bh)
    return True

def _handle_int10_ah03_get_cursor_pos(uc, vga_emulator):
    """Handles INT 10h, AH=03h: Get Cursor Position and Type."""
    current_row, current_col, start_line, end_line = vga_emulator.get_cursor_position()
    uc.reg_write(UC_X86_REG_DH, current_row)
    uc.reg_write(UC_X86_REG_DL, current_col)
    uc.reg_write(UC_X86_REG_CH, start_line)
    uc.reg_write(UC_X86_REG_CL, end_line)
    print(f"    Returned DH={current_row}, DL={current_col}, CH={start_line}, CL={end_line}")
    return True

def _handle_int10_ah05_select_page(uc, vga_emulator):
    """Handles INT 10h, AH=05h: Select Active Video Page."""
    al = uc.reg_read(UC_X86_REG_AL)
    vga_emulator.active_page = al
    print(f"    Selected active page: {al}")
    return True

def _handle_int10_ah06_scroll_up(uc, vga_emulator):
    """Handles INT 10h, AH=06h: Scroll Up Window."""
    al, bh, ch, cl, dh, dl = map(uc.reg_read, [UC_X86_REG_AL, UC_X86_REG_BH, UC_X86_REG_CH, UC_X86_REG_CL, UC_X86_REG_DH, UC_X86_REG_DL])
    print(f"    Scroll up: {al} lines, attr {hex(bh)}, window ({ch},{cl}) to ({dh},{dl})")
    vga_emulator._scroll_window(al, ch, cl, dh, dl, bh, "up")
    return True

def _handle_int10_ah07_scroll_down(uc, vga_emulator):
    """Handles INT 10h, AH=07h: Scroll Down Window."""
    al, bh, ch, cl, dh, dl = map(uc.reg_read, [UC_X86_REG_AL, UC_X86_REG_BH, UC_X86_REG_CH, UC_X86_REG_CL, UC_X86_REG_DH, UC_X86_REG_DL])
    print(f"    Scroll down: {al} lines, attr {hex(bh)}, window ({ch},{cl}) to ({dh},{dl})")
    vga_emulator._scroll_window(al, ch, cl, dh, dl, bh, "down")
    return True

def _handle_int10_ah08_read_char_attr(uc, vga_emulator):
    """Handles INT 10h, AH=08h: Read Character and Attribute at Cursor."""
    bh = uc.reg_read(UC_X86_REG_BH)
    char_code, attribute = vga_emulator.read_char_and_attribute(vga_emulator.cursor_row, vga_emulator.cursor_col, bh)
    uc.reg_write(UC_X86_REG_AL, char_code)
    uc.reg_write(UC_X86_REG_AH, attribute)
    print(f"    Read char: {hex(char_code)}, attr: {hex(attribute)}")
    return True

def _handle_int10_ah09_write_char_attr(uc, vga_emulator):
    """Handles INT 10h, AH=09h: Write Character and Attribute at Cursor."""
    al, bh, bl, cx = map(uc.reg_read, [UC_X86_REG_AL, UC_X86_REG_BH, UC_X86_REG_BL, UC_X86_REG_CX])
    vga_emulator.write_char_and_attribute(al, bl, vga_emulator.cursor_row, vga_emulator.cursor_col, bh, cx)
    print(f"    Write char: '{chr(al)}' (x{cx}), attr {hex(bl)}")
    return True

def _handle_int10_ah0A_write_char(uc, vga_emulator):
    """Handles INT 10h, AH=0Ah: Write Character Only at Cursor."""
    al, bh, cx = map(uc.reg_read, [UC_X86_REG_AL, UC_X86_REG_BH, UC_X86_REG_CX])
    vga_emulator.write_char_and_attribute(al, 0x07, vga_emulator.cursor_row, vga_emulator.cursor_col, bh, cx)
    print(f"    Write char only: '{chr(al)}' (x{cx})")
    return True

def _handle_int10_ah0C_write_pixel(uc, vga_emulator):
    """Handles INT 10h, AH=0Ch: Write Pixel."""
    al, cx, dx = map(uc.reg_read, [UC_X86_REG_AL, UC_X86_REG_CX, UC_X86_REG_DX])
    vga_emulator.write_pixel(cx, dx, al)
    print(f"    Set pixel at ({cx},{dx}) to color {hex(al)}")
    return True

def _handle_int10_ah0D_read_pixel(uc, vga_emulator):
    """Handles INT 10h, AH=0Dh: Read Pixel."""
    cx, dx = map(uc.reg_read, [UC_X86_REG_CX, UC_X86_REG_DX])
    color = vga_emulator.read_pixel(cx, dx)
    uc.reg_write(UC_X86_REG_AL, color)
    print(f"    Get pixel at ({cx},{dx}): color {hex(color)}")
    return True

def _handle_int10_ah0E_teletype(uc, vga_emulator):
    """Handles INT 10h, AH=0Eh: Teletype Output."""
    al = uc.reg_read(UC_X86_REG_AL)
    vga_emulator.write_char_teletype(al)
    print(f"    Teletype output: '{chr(al)}'")
    return True

def _handle_int10_ah0F_get_mode(uc, vga_emulator):
    """Handles INT 10h, AH=0Fh: Get Current Video Mode."""
    mode_bda = uc.mem_read(BIOS_DATA_AREA + 0x49, 1)[0]
    uc.reg_write(UC_X86_REG_AL, mode_bda if mode_bda != 0 else vga_emulator.current_mode)
    uc.reg_write(UC_X86_REG_AH, vga_emulator.chars_per_row if vga_emulator.is_text_mode else 0)
    uc.reg_write(UC_X86_REG_BH, vga_emulator.active_page)
    print(f"    Returning AL={uc.reg_read(UC_X86_REG_AL):02X}, AH={uc.reg_read(UC_X86_REG_AH):02X}, BH={uc.reg_read(UC_X86_REG_BH):02X}")
    return True

def _handle_int10_ah10_palette(uc, vga_emulator):
    """Handles INT 10h, AH=10h: Palette Functions."""
    al = uc.reg_read(UC_X86_REG_AL)
    
    if al == 0x00: # Set Individual Palette Register
        bl, bh = map(uc.reg_read, [UC_X86_REG_BL, UC_X86_REG_BH])
        new_color_rgb = vga_emulator._decode_ega_palette_color(bh)
        vga_emulator.palette_16_color[bl] = new_color_rgb
        print(f"    Set Palette Register {bl} to value {hex(bh)} -> RGB{new_color_rgb}")
        return True
        
    elif al == 0x01: # Set Border Color
        bl = uc.reg_read(UC_X86_REG_BL)
        print(f"    Set Border Color to {bl}. (Not visually implemented)")
        return True

    elif al == 0x02: # Set All Palette Registers
        es, dx = map(uc.reg_read, [UC_X86_REG_ES, UC_X86_REG_DX])
        addr = es * 16 + dx
        print(f"    Set All Palette Registers from {hex(addr)}.")
        palette_bytes = uc.mem_read(addr, 16)
        for i, val in enumerate(palette_bytes):
            vga_emulator.palette_16_color[i] = vga_emulator._decode_ega_palette_color(val)
            if vga_emulator.palette_16_color[i] == 0:
                vga_emulator.palette_16_color[i] = VGA_PALETTE_16_COLORS[i]
        print("      Palette updated successfully.")
        return True
    
    elif al == 0x09: # Get All 16 Palette Registers
        es, dx = map(uc.reg_read, [UC_X86_REG_ES, UC_X86_REG_DX])
        addr = es * 16 + dx
        print(f"    Get All Palette Registers to buffer {hex(addr)}.")
        palette_bytes = bytes([vga_emulator._encode_ega_palette_color(c) for c in vga_emulator.palette_16_color])
        uc.mem_write(addr, palette_bytes)
        print("      Successfully wrote encoded palette to buffer.")
        return True

    elif al == 0x10: # Set Individual DAC Register
        bx, ch, cl, dh = map(uc.reg_read, [UC_X86_REG_BX, UC_X86_REG_CH, UC_X86_REG_CL, UC_X86_REG_DH])
        r, g, b = dh * 4, ch * 4, cl * 4
        if bx < len(VGA_PALETTE_256_COLORS):
            VGA_PALETTE_256_COLORS[bx] = (r, g, b)
            print(f"    Set DAC Register {bx} to RGB({r},{g},{b}).")
        else:
            print(f"    DAC Register {bx} out of bounds.")
        return True
    
    print(f"    Unhandled INT 10h, AH=10h sub-function AL={al:02X}")
    return False

def _handle_int10_ah11_char_gen(uc, vga_emulator):
    """Handles INT 10h, AH=11h: Character Generator Functions."""
    al = uc.reg_read(UC_X86_REG_AL)
    if al == 0x30:
        handle_int10_11_30(uc)
        return True
    print(f"    Unhandled INT 10h, AH=11h sub-function AL={al:02X}")
    return False

def _handle_int10_ah12_vga_info(uc, vga_emulator):
    """Handles INT 10h, AH=12h: EGA/VGA Specific Functions."""
    bl = uc.reg_read(UC_X86_REG_BL)
    if bl == 0x10: # Get EGA/VGA Information
        print("    INT 10h, AH=12h, BL=10h (Get EGA/VGA Information).")
        uc.reg_write(UC_X86_REG_BH, 0x00) # Color display
        uc.reg_write(UC_X86_REG_BL, 0x00) # 64KB video memory
        uc.reg_write(UC_X86_REG_CH, 0x00)
        uc.reg_write(UC_X86_REG_CL, 0x00)
        return True
    print(f"    Unhandled INT 10h, AH=12h sub-function BL={bl:02X}")
    return False

def _handle_int10_ah13_write_string(uc, vga_emulator):
    """Handles INT 10h, AH=13h: Write String."""
    al, bh, bl, cx, dh, dl, es, bp = map(uc.reg_read, [
        UC_X86_REG_AL, UC_X86_REG_BH, UC_X86_REG_BL, UC_X86_REG_CX, 
        UC_X86_REG_DH, UC_X86_REG_DL, UC_X86_REG_ES, UC_X86_REG_BP
    ])

    addr = es * 16 + bp
    bytes_per_char = 2 if (al & 0x02) else 1
    string_bytes = uc.mem_read(addr, cx * bytes_per_char)
    
    print(f"    Write string: mode {bin(al)}, page {bh}, attr {hex(bl)}, len {cx}, pos ({dh},{dl})")
    
    row, col = dh, dl
    str_idx = 0
    for _ in range(cx):
        char_code = string_bytes[str_idx]
        char_attr = string_bytes[str_idx + 1] if (al & 0x02) else bl
        
        vga_emulator.write_char_and_attribute(char_code, char_attr, row, col, bh, 1)
        
        str_idx += bytes_per_char
        col += 1
        if col >= vga_emulator.chars_per_row:
            col = 0
            row += 1

    if (al & 0x01): # Update cursor
        vga_emulator.set_cursor_position(row, col, bh)
    return True

def _handle_int10_ah1A_display_code(uc, vga_emulator):
    """Handles INT 10h, AH=1Ah: Read/Write Display Combination Code."""
    al = uc.reg_read(UC_X86_REG_AL)
    if al == 0x00:
        uc.reg_write(UC_X86_REG_AL, 0x1A) # Function supported
        uc.reg_write(UC_X86_REG_BH, 0x00) # Analog display (VGA/MCGA)
        uc.reg_write(UC_X86_REG_BL, 0x08) # Color mode
        print("    Get Display Combination Code: AL=1A, BH=00, BL=08 (VGA/MCGA Color).")
        return True
    print(f"    Unhandled INT 10h, AH=1Ah sub-function AL={al:02X}")
    return False

def _handle_int10_ah1C_video_state(uc, vga_emulator):
    """Handles INT 10h, AH=1Ch: Save/Restore Video State."""
    al = uc.reg_read(UC_X86_REG_AL)
    cx = uc.reg_read(UC_X86_REG_CX)

    if al == 0x00: # Get State Buffer Size
        print(f"    INT 10h, AH=1Ch, AL=00h (Get Buffer Size) for mask CX={cx:04X}.")
        buffer_size_in_blocks = 16
        uc.reg_write(UC_X86_REG_AL, 0x1C)
        uc.reg_write(UC_X86_REG_BX, buffer_size_in_blocks)
        print(f"    Returning buffer size of {buffer_size_in_blocks * 64} bytes.")
        return True
    
    elif al in [0x01, 0x02]: # Save or Restore State
        es, bx = map(uc.reg_read, [UC_X86_REG_ES, UC_X86_REG_BX])
        addr = es * 16 + bx
        action = "Save" if al == 0x01 else "Restore"
        print(f"    INT 10h, AH=1Ch, AL={al:02h} ({action} State) to/from {es:04X}:{bx:04X}.")
        
        # Acknowledge the call without actually doing the complex state transfer
        uc.reg_write(UC_X86_REG_AL, 0x1C) # Success
        print(f"    Successfully acknowledged state {action.lower()}.")
        return True

    print(f"    Unhandled INT 10h, AH=1Ch sub-function AL={al:02X}")
    return False


# --- Main Dispatcher Function ---

def handle_int10(uc, vga_emulator):
    """Handles INT 10h (Video Services) calls by dispatching to sub-handlers."""
    ah = uc.reg_read(UC_X86_REG_AH)
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    print(f"[*] INT 10h, AH={ah:02X} at {current_cs:X}:{current_ip:X}")

    ah_handlers = {
        0x00: _handle_int10_ah00_set_mode,
        0x01: _handle_int10_ah01_set_cursor_type,
        0x02: _handle_int10_ah02_set_cursor_pos,
        0x03: _handle_int10_ah03_get_cursor_pos,
        0x05: _handle_int10_ah05_select_page,
        0x06: _handle_int10_ah06_scroll_up,
        0x07: _handle_int10_ah07_scroll_down,
        0x08: _handle_int10_ah08_read_char_attr,
        0x09: _handle_int10_ah09_write_char_attr,
        0x0A: _handle_int10_ah0A_write_char,
        0x0C: _handle_int10_ah0C_write_pixel,
        0x0D: _handle_int10_ah0D_read_pixel,
        0x0E: _handle_int10_ah0E_teletype,
        0x0F: _handle_int10_ah0F_get_mode,
        0x10: _handle_int10_ah10_palette,
        0x11: _handle_int10_ah11_char_gen,
        0x12: _handle_int10_ah12_vga_info,
        0x13: _handle_int10_ah13_write_string,
        0x1A: _handle_int10_ah1A_display_code,
        0x1C: _handle_int10_ah1C_video_state,
    }

    handler = ah_handlers.get(ah)
    handled = False

    if handler:
        try:
            # Call the specific handler function
            handled = handler(uc, vga_emulator)
        except UcError as e:
            print(f"    ERROR executing handler for AH={ah:02X}: {e}")
            # Mark as unhandled to stop emulation
            handled = False
        except Exception as e:
            print(f"    UNEXPECTED PYTHON ERROR in handler for AH={ah:02X}: {e}")
            handled = False

    if handled:
        # Most INT 10h functions clear the Carry Flag on success.
        eflags = uc.reg_read(UC_X86_REG_EFLAGS)
        eflags &= ~0x0001  # Clear Carry Flag (CF)
        uc.reg_write(UC_X86_REG_EFLAGS, eflags)
    else:
        # If the handler was not found, or it returned False (unhandled sub-function)
        print(f"    Unhandled INT 10h function: AH={ah:02X}. Stopping emulation.")
        uc.emu_stop()

def handle_int16(uc, vga_emulator):
    """Handles INT 16h (Keyboard Services) calls."""
    ah = uc.reg_read(UC_X86_REG_AH)
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    print(f"[*] INT 16h, AH={ah:02X} {current_cs:X}:{current_ip:X} ")

    if ah == 0x00: # Read Character from Keyboard
        key_data = vga_emulator.pop_key_from_bios_buffer()
        if key_data:
            ascii_val, scan_code = key_data
            uc.reg_write(UC_X86_REG_AL, ascii_val)
            uc.reg_write(UC_X86_REG_AH, scan_code)
            eflags = uc.reg_read(UC_X86_REG_EFLAGS)
            eflags &= ~0x0040 # Clear ZF (Zero Flag) - key was read
            uc.reg_write(UC_X86_REG_EFLAGS, eflags)
        else:
            # No key available, set waiting flag and stop emulation
            print(f"    Waiting for key (INT 16h AH=00h)...")
            vga_emulator.waiting_for_key = True
            uc.emu_stop()
    
    elif ah == 0x01: # Check Keyboard Status
        key_data = vga_emulator.peek_key_from_bios_buffer()
        if key_data:
            ascii_val, scan_code = key_data
            uc.reg_write(UC_X86_REG_AL, ascii_val)
            uc.reg_write(UC_X86_REG_AH, scan_code)
            eflags = uc.reg_read(UC_X86_REG_EFLAGS)
            eflags &= ~0x0040 # Clear ZF - key is available
            uc.reg_write(UC_X86_REG_EFLAGS, eflags)
            print(f"    Key available (INT 16h AH=01h): ASCII={ascii_val:02X}, ScanCode={scan_code:02X}")
        else:
            uc.reg_write(UC_X86_REG_AX, 0x0000) # AX = 0, no key
            eflags = uc.reg_read(UC_X86_REG_EFLAGS)
            eflags |= 0x0040 # Set ZF - no key
            uc.reg_write(UC_X86_REG_EFLAGS, eflags)
            print(f"    No key available (INT 16h AH=01h).")

    elif ah == 0x02: # Get Shift Status
        # Shift status byte at 0x40:0x17 (physical 0x417)
        # Bit 0: Right SHIFT, Bit 1: Left SHIFT, Bit 2: CTRL, Bit 3: ALT
        # Bit 4: SCROLL LOCK, Bit 5: NUM LOCK, Bit 6: CAPS LOCK, Bit 7: INS
        # We can simulate a basic status, or leave it at 0 for now.
        # For a full emulator, you'd update this byte from Pygame modifier keys.
        shift_status = uc.mem_read(BIOS_DATA_AREA + 0x17, 1)[0] # Read current status
        uc.reg_write(UC_X86_REG_AL, shift_status)
        print(f"    Get Shift Status (INT 16h AH=02h): AL={shift_status:02X}")

    elif ah == 0x05: # Keyboard Write (push key to buffer) - not usually called by programs
        # This function is used by keyboard drivers (e.g., INT 09h handler) to push keys.
        # AX = ASCII+ScanCode
        key_word = uc.reg_read(UC_X86_REG_AX)
        ascii_val = (key_word >> 8) & 0xFF
        scan_code = key_word & 0xFF
        success = vga_emulator.push_key_to_bios_buffer(ascii_val, scan_code)
        if success:
            uc.reg_write(UC_X86_REG_AL, 0x01) # Success
        else:
            uc.reg_write(UC_X86_REG_AL, 0x00) # Buffer full
        print(f"    Keyboard Write (INT 16h AH=05h): AX={key_word:04X}, Success={success}")

    else:
        print(f"    Unhandled INT 16h function: AH={ah:02X}. Stopping emulation.")
        uc.emu_stop()

    # No specific flags to set/clear by default for INT 16h after execution.
    # ZF for 01h is handled.
