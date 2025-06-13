# --- START OF FILE bios.py ---

import struct
import time
import collections # For deque, a double-ended queue for keyboard buffer

from unicorn import *
from unicorn.x86_const import *
import pygame

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

# --- VGA/Text Mode Font Data ---
# A very basic 8x8 font. In a real emulator, this would come from BIOS ROM.
# This is a placeholder for standard ASCII characters 0-127.
# Each character is 8 bytes (8 rows), each bit representing a pixel.
# Source: Public domain character definitions or simple creation.
BIOS_FONT_8X8 = [
    # Char 0-15 (examples)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 00 NUL
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 01 SOH (blank for now)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 02 STX
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 03 ETX
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 04 EOT
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 05 ENQ
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 06 ACK
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 07 BEL
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 08 BS
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 09 TAB
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 0A LF
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 0B VT
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 0C FF
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 0D CR
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 0E SO
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # 0F SI
    # ... more characters ... (filled in for common ASCII range)
    # Placeholder for more characters, extending up to 255.
    # For a full implementation, you'd need the full CP437 font.
]

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
    (0xFC, 0x54, 0xFC), # E - Yellow
    (0xFC, 0xFC, 0xFC), # F - White
]

# Mode 13h (320x200, 256 colors) default palette for now.
# In a real scenario, this would be set by INT 10h subfunctions.
# For simplicity, we'll use a simple grayscale or fixed palette if mode 13h is used.
# Let's define a simple 256-color palette for mode 13h, e.g., a grayscale.
# In a real game, this palette would be loaded.
VGA_PALETTE_256_COLORS = [(i, i, i) for i in range(256)]


class VGAEmulator:
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
        elif mode_id == 0x13: # 320x200 256-color graphics mode
            self.display_width = 320
            self.display_height = 200
            self.vram_base = VRAM_GRAPHICS_MODE
            self.is_text_mode = False
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
            self.screen = pygame.display.set_mode((self.display_width, self.display_height))
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

        vram_addr = self.vram_base + (row * self.chars_per_row + col) * 2 # 2 bytes per char (char, attr)
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
            color = self.uc.mem_read(vram_addr, 1)[0]
            return color
        except UcError as e:
            print(f"    Error reading pixel from VRAM at {hex(vram_addr)}: {e}")
            return 0

    def read_char_and_attribute(self, row, col, page):
        """Reads char+attr from VRAM."""
        if not self.is_text_mode:
            print(f"    Warning: Tried to read char/attr in graphics mode. Skipping.")
            return 0x20, 0x07 # Space, light gray

        vram_addr = self.vram_base + (row * self.chars_per_row + col) * 2
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
        
        if num_lines == 0: # Clear entire window
            for r in range(row_ul, row_lr + 1):
                for c in range(col_ul, col_lr + 1):
                    self.write_char_and_attribute(0x20, attribute, r, c, self.active_page, 1)
            return

        window_height = row_lr - row_ul + 1
        window_width = col_lr - col_ul + 1

        if direction == "up":
            # Move lines up
            for r in range(row_ul, row_lr + 1 - num_lines):
                # Copy line (r + num_lines) to line r
                src_vram_start = self.vram_base + ((r + num_lines) * self.chars_per_row + col_ul) * 2
                dest_vram_start = self.vram_base + (r * self.chars_per_row + col_ul) * 2
                try:
                    line_data = self.uc.mem_read(src_vram_start, window_width * 2)
                    self.uc.mem_write(dest_vram_start, line_data)
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
                src_vram_start = self.vram_base + ((r - num_lines) * self.chars_per_row + col_ul) * 2
                dest_vram_start = self.vram_base + (r * self.chars_per_row + col_ul) * 2
                try:
                    line_data = self.uc.mem_read(src_vram_start, window_width * 2)
                    self.uc.mem_write(dest_vram_start, line_data)
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
            # Text mode rendering (e.g., 80x25, 40x25)
            try:
                # Read the entire visible VRAM area for the active page
                # For 80x25, it's 80 * 25 * 2 bytes = 4000 bytes.
                vram_data = self.uc.mem_read(self.vram_base + (self.active_page * self.chars_per_row * self.rows * 2),
                                             self.chars_per_row * self.rows * 2)
                # DEBUG: Print a small chunk of VRAM to see if data is there
                # if vram_data[0] != 0x00 or vram_data[1] != 0x00: # Only print if first char is not blank
                #     print(f"DEBUG: VRAM start ({hex(self.vram_base)}): Char {vram_data[0]:X}, Attr {vram_data[1]:X}")

            except UcError as e:
                print(f"    Error reading VRAM for rendering: {e}. Skipping render.")
                return

            self.screen.fill((0, 0, 0)) # Clear screen
            for row in range(self.rows):
                for col in range(self.chars_per_row):
                    offset = (row * self.chars_per_row + col) * 2
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
            try:
                # Read the entire graphics VRAM area
                vram_data = self.uc.mem_read(self.vram_base, self.display_width * self.display_height)
            except UcError as e:
                print(f"    Error reading VRAM for rendering: {e}. Skipping render.")
                return

            # Create a Pygame surface from the VRAM data
            # This is an efficient way to blit pixel data if it's in a compatible format.
            # Mode 13h is 8-bit palettized, so we need to map colors.
            # Directly manipulate pixels on screen for now for simplicity.
            for y in range(self.display_height):
                for x in range(self.display_width):
                    offset = y * self.display_width + x
                    color_index = vram_data[offset]
                    color_rgb = VGA_PALETTE_256_COLORS[color_index]
                    self.screen.set_at((x, y), color_rgb)
        
        pygame.display.flip()
        # DEBUG: Confirm screen flip
        # print(f"DEBUG: Pygame screen flipped for mode {hex(self.current_mode)}")


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


# --- Interrupt Handlers Refactored ---

def handle_int10(uc, vga_emulator):
    """Handles INT 10h (Video Services) calls."""
    ah = uc.reg_read(UC_X86_REG_AH)
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    print(f"[*] INT 10h, AH={hex(ah)} {current_cs:X}:{current_ip:X} ")

    if ah == 0x00: # Set Video Mode
        al = uc.reg_read(UC_X86_REG_AL)
        vga_emulator.set_mode(al)
        # Update BIOS Data Area (BDA) at 0x40:0x49 for active video mode
        # This is where BIOS usually stores the current video mode.
        uc.mem_write(BIOS_DATA_AREA + 0x49, struct.pack("<B", al))
        uc.reg_write(UC_X86_REG_AL, 0x00) # Often returns 0 on success
        
    elif ah == 0x01: # Set Cursor Type
        ch = uc.reg_read(UC_X86_REG_CH)
        cl = uc.reg_read(UC_X86_REG_CL)
        vga_emulator.set_cursor_shape(ch, cl)

    elif ah == 0x02: # Set Cursor Position
        bh = uc.reg_read(UC_X86_REG_BH) # Page number
        dh = uc.reg_read(UC_X86_REG_DH) # Row
        dl = uc.reg_read(UC_X86_REG_DL) # Column
        vga_emulator.set_cursor_position(dh, dl, bh)

    elif ah == 0x03: # Get Cursor Position and Type
        # BH (page number) is input, DH, DL, CH, CL are outputs
        current_row, current_col, start_line, end_line = vga_emulator.get_cursor_position()
        uc.reg_write(UC_X86_REG_DH, current_row)
        uc.reg_write(UC_X86_REG_DL, current_col)
        uc.reg_write(UC_X86_REG_CH, start_line)
        uc.reg_write(UC_X86_REG_CL, end_line)
        # BH (active page) is typically not written back, but could be.
        # It's an input register, here, so no need to write.
        print(f"    Returned DH={current_row}, DL={current_col}, CH={start_line}, CL={end_line}")

    elif ah == 0x05: # Select Active Video Page
        al = uc.reg_read(UC_X86_REG_AL)
        vga_emulator.active_page = al
        print(f"    Selected active page: {al}")

    elif ah == 0x06: # Scroll Up Window
        al = uc.reg_read(UC_X86_REG_AL) # Number of lines to scroll (00h = clear)
        bh = uc.reg_read(UC_X86_REG_BH) # Attribute for blank lines
        ch = uc.reg_read(UC_X86_REG_CH) # Row UL
        cl = uc.reg_read(UC_X86_REG_CL) # Col UL
        dh = uc.reg_read(UC_X86_REG_DH) # Row LR
        dl = uc.reg_read(UC_X86_REG_DL) # Col LR
        print(f"    Scroll up: {al} lines, attr {hex(bh)}, window ({ch},{cl}) to ({dh},{dl})")
        vga_emulator._scroll_window(al, ch, cl, dh, dl, bh, "up")

    elif ah == 0x07: # Scroll Down Window
        al = uc.reg_read(UC_X86_REG_AL) # Number of lines to scroll (00h = clear)
        bh = uc.reg_read(UC_X86_REG_BH) # Attribute for blank lines
        ch = uc.reg_read(UC_X86_REG_CH) # Row UL
        cl = uc.reg_read(UC_X86_REG_CL) # Col UL
        dh = uc.reg_read(UC_X86_REG_DH) # Row LR
        dl = uc.reg_read(UC_X86_REG_DL) # Col LR
        print(f"    Scroll down: {al} lines, attr {hex(bh)}, window ({ch},{cl}) to ({dh},{dl})")
        vga_emulator._scroll_window(al, ch, cl, dh, dl, bh, "down")

    elif ah == 0x08: # Read Character and Attribute at Cursor Position
        bh = uc.reg_read(UC_X86_REG_BH) # Page number
        char_code, attribute = vga_emulator.read_char_and_attribute(vga_emulator.cursor_row, vga_emulator.cursor_col, bh)
        uc.reg_write(UC_X86_REG_AL, char_code)
        uc.reg_write(UC_X86_REG_AH, attribute)
        print(f"    Read char: {hex(char_code)}, attr: {hex(attribute)}")

    elif ah == 0x09: # Write Character and Attribute at Cursor Position
        al = uc.reg_read(UC_X86_REG_AL) # Character to display
        bh = uc.reg_read(UC_X86_REG_BH) # Page number
        bl = uc.reg_read(UC_X86_REG_BL) # Attribute
        cx = uc.reg_read(UC_X86_REG_CX) # Number of times to write
        vga_emulator.write_char_and_attribute(al, bl, vga_emulator.cursor_row, vga_emulator.cursor_col, bh, cx)
        print(f"    Write char: '{chr(al)}' (x{cx}), attr {hex(bl)}")

    elif ah == 0x0A: # Write Character Only at Cursor Position
        al = uc.reg_read(UC_X86_REG_AL) # Character to display
        bh = uc.reg_read(UC_X86_REG_BH) # Page number
        cx = uc.reg_read(UC_X86_REG_CX) # Number of times to write
        # Default attribute (light gray on black) or read current attribute for the cell?
        # Typically, this function uses the attribute already at the location, or a default.
        # For simplicity, using a default attribute.
        vga_emulator.write_char_and_attribute(al, 0x07, vga_emulator.cursor_row, vga_emulator.cursor_col, bh, cx)
        print(f"    Write char only: '{chr(al)}' (x{cx})")

    elif ah == 0x0C: # Change color for a single pixel (graphics mode)
        al = uc.reg_read(UC_X86_REG_AL) # Pixel color
        cx = uc.reg_read(UC_X86_REG_CX) # Column (X)
        dx = uc.reg_read(UC_X86_REG_DX) # Row (Y)
        vga_emulator.write_pixel(cx, dx, al)
        print(f"    Set pixel at ({cx},{dx}) to color {hex(al)}")

    elif ah == 0x0D: # Get color of a single pixel (graphics mode)
        cx = uc.reg_read(UC_X86_REG_CX) # Column (X)
        dx = uc.reg_read(UC_X86_REG_DX) # Row (Y)
        color = vga_emulator.read_pixel(cx, dx)
        uc.reg_write(UC_X86_REG_AL, color)
        print(f"    Get pixel at ({cx},{dx}): color {hex(color)}")

    elif ah == 0x0E: # Teletype output
        al = uc.reg_read(UC_X86_REG_AL) # Character to write
        # BL (foreground color) can be an input here, but often ignored for simplicity.
        # Use default attribute or the one for the current active page.
        vga_emulator.write_char_teletype(al)
        print(f"    Teletype output: '{chr(al)}'")

    elif ah == 0x0F: # Get Current Video Mode
        # AL = mode, AH = columns, BH = active display page
        # In a real BIOS, this would read from BDA (0x40:0x49 for mode)
        current_mode_bda = vga_emulator.uc.mem_read(BIOS_DATA_AREA + 0x49, 1)[0] # Read from BDA
        uc.reg_write(UC_X86_REG_AL, current_mode_bda if current_mode_bda != 0 else vga_emulator.current_mode)
        uc.reg_write(UC_X86_REG_AH, vga_emulator.chars_per_row if vga_emulator.is_text_mode else 0) # Columns
        uc.reg_write(UC_X86_REG_BH, vga_emulator.active_page) # Display page
        print(f"    Returning AL={hex(uc.reg_read(UC_X86_REG_AL))}, AH={hex(uc.reg_read(UC_X86_REG_AH))}, BH={hex(uc.reg_read(UC_X86_REG_BH))}")

    elif ah == 0x13: # Write string
        al = uc.reg_read(UC_X86_REG_AL) # Write mode (bit 0: update cursor, bit 1: string contains attributes)
        bh = uc.reg_read(UC_X86_REG_BH) # Page number
        bl = uc.reg_read(UC_X86_REG_BL) # Attribute (if bit 1 of AL is zero)
        cx = uc.reg_read(UC_X86_REG_CX) # Number of characters in string
        dl = uc.reg_read(UC_X86_REG_DL) # Column
        dh = uc.reg_read(UC_X86_REG_DH) # Row
        es = uc.reg_read(UC_X86_REG_ES)
        bp = uc.reg_read(UC_X86_REG_BP)
        
        start_addr = es * 16 + bp
        string_bytes = uc.mem_read(start_addr, cx * (2 if (al & 0x02) else 1)) # Read string bytes
        
        current_row, current_col = dh, dl
        
        print(f"    Write string: mode {bin(al)}, page {bh}, attr {hex(bl)}, len {cx}, pos ({dh},{dl})")

        str_idx = 0
        for i in range(cx):
            char_code = string_bytes[str_idx]
            char_attr = bl # Default attribute
            if (al & 0x02): # String contains attributes
                str_idx += 1
                char_attr = string_bytes[str_idx]
            
            vga_emulator.write_char_and_attribute(char_code, char_attr, current_row, current_col, bh, 1)
            
            str_idx += 1
            current_col += 1
            if current_col >= vga_emulator.chars_per_row:
                current_col = 0
                current_row += 1

        if (al & 0x01): # Update cursor after writing
            vga_emulator.set_cursor_position(current_row, current_col, bh)

    elif ah == 0x11: # Character Generator Functions (Load Fonts)
        al = uc.reg_read(UC_X86_REG_AL)
        print(f"    Character Generator Function AL={hex(al)}. Acknowledged, no specific action.")
        # No specific return values needed. Clear CF to signal success.
        eflags = uc.reg_read(UC_X86_REG_EFLAGS)
        eflags &= ~0x0001 # Clear Carry Flag (CF)
        uc.reg_write(UC_X86_REG_EFLAGS, eflags)

    elif ah == 0x12: # EGA/VGA - specific functions
        bl = uc.reg_read(UC_X86_REG_BL)
        if bl == 0x10: # Get EGA/VGA Information
            print(f"    INT 10h, AH=12h, BL=10h (Get EGA/VGA Information).")
            # Return values:
            # BH = 0 (color), BL = 0 (64KB), CH = 0 (switch active disp), CL = 0 (switch inactive disp)
            # DX = 0 (monitor type)
            uc.reg_write(UC_X86_REG_BH, 0x00) # Color display
            uc.reg_write(UC_X86_REG_BL, 0x00) # 64KB video memory (common for basic VGA)
            uc.reg_write(UC_X86_REG_CH, 0x00) # Switch active display
            uc.reg_write(UC_X86_REG_CL, 0x00) # Switch inactive display
            uc.reg_write(UC_X86_REG_DX, 0x00) # Monitor type (0=mono, 1=color) - often ignored by games.
        elif bl == 0x20: # Select default palette loading (VGA)
            print(f"    INT 10h, AH=12h, BL=20h (Select default palette loading). Acknowledged.")
            # No return values.
        else:
            print(f"    Unhandled INT 10h function: AH={hex(ah)}, BL={hex(bl)}. Stopping emulation.")
            uc.emu_stop()
    elif ah == 0x1A: # Read/Write Display Combination Code
        al = uc.reg_read(UC_X86_REG_AL)
        if al == 0x00: # Get display combination code
            uc.reg_write(UC_X86_REG_AL, 0x1A) # Function supported
            uc.reg_write(UC_X86_REG_BH, 0x00) # Analog display (VGA/MCGA)
            uc.reg_write(UC_X86_REG_BL, 0x08) # Color mode
            print(f"    Get Display Combination Code: AL=1A, BH=00, BL=08 (VGA/MCGA Color).")
        else:
             print(f"    Unhandled INT 10h, AH=1A, AL={hex(al)}. Stopping emulation.")
             uc.emu_stop()

    elif ah == 0x10: # Palette/Color Register Functions
        al = uc.reg_read(UC_X86_REG_AL)
        if al == 0x00: # Set Individual Palette Register
            bl = uc.reg_read(UC_X86_REG_BL) # Palette register index
            bh = uc.reg_read(UC_X86_REG_BH) # Color value
            print(f"    Set Palette Register {bl} to {bh}. (16 color mode only, not fully implemented for rendering)")
            # For 16-color modes, this changes the 16-color palette.
            # In our simple emulator, the 16-color palette is fixed.
            # Could update VGA_PALETTE_16_COLORS here if we had more complex needs.
        elif al == 0x01: # Set Border Color
            bl = uc.reg_read(UC_X86_REG_BL) # Border color index
            print(f"    Set Border Color to {bl}. (Not visually implemented)")
        elif al == 0x02: # Set All Palette Registers
            dx = uc.reg_read(UC_X86_REG_DX) # Pointer to 16-byte palette array
            es = uc.reg_read(UC_X86_REG_ES)
            palette_data_addr = es * 16 + dx
            print(f"    Set All Palette Registers from {hex(palette_data_addr)}. (Not fully implemented for rendering)")
        elif al == 0x03: # Toggle Intensity/Blinking
            bl = uc.reg_read(UC_X86_REG_BL) # 0=enable intensive, 1=enable blinking
            print(f"    Toggle Intensity/Blinking: {bl}. (Not fully implemented)")
        elif al == 0x10: # Set Individual DAC Register (256-color palette)
            bx = uc.reg_read(UC_X86_REG_BX) # Color register index
            dh = uc.reg_read(UC_X86_REG_DH) # Red value (0-63)
            ch = uc.reg_read(UC_X86_REG_CH) # Green value (0-63)
            cl = uc.reg_read(UC_X86_REG_CL) # Blue value (0-63)
            
            # Scale 0-63 to 0-255 for Pygame
            r, g, b = dh * 4, ch * 4, cl * 4
            if bx < len(VGA_PALETTE_256_COLORS):
                VGA_PALETTE_256_COLORS[bx] = (r, g, b)
                print(f"    Set DAC Register {bx} to RGB({r},{g},{b}).")
            else:
                print(f"    DAC Register {bx} out of bounds. Max {len(VGA_PALETTE_256_COLORS)-1}.")
        # ... more INT 10h AH=10h subfunctions as needed ...
        else:
            print(f"    Unhandled INT 10h function: AH={hex(ah)}, AL={hex(al)}. Stopping emulation.")
            uc.emu_stop()

    else:
        print(f"    Unhandled INT 10h function: AH={hex(ah)}. Stopping emulation.")
        uc.emu_stop()

    # Ensure Carry Flag is cleared for success, set for error (if not already handled)
    # Most INT 10h functions clear CF on success.
    eflags = uc.reg_read(UC_X86_REG_EFLAGS)
    eflags &= ~0x0001 # Clear Carry Flag (CF)
    uc.reg_write(UC_X86_REG_EFLAGS, eflags)


def handle_int16(uc, vga_emulator):
    """Handles INT 16h (Keyboard Services) calls."""
    ah = uc.reg_read(UC_X86_REG_AH)
    current_cs = uc.reg_read(UC_X86_REG_CS)
    current_ip = uc.reg_read(UC_X86_REG_IP)
    print(f"[*] INT 16h, AH={hex(ah)} {current_cs:X}:{current_ip:X} ")

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
            print(f"    Key available (INT 16h AH=01h): ASCII={hex(ascii_val)}, ScanCode={hex(scan_code)}")
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
        print(f"    Get Shift Status (INT 16h AH=02h): AL={hex(shift_status)}")

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
        print(f"    Keyboard Write (INT 16h AH=05h): AX={hex(key_word)}, Success={success}")

    else:
        print(f"    Unhandled INT 16h function: AH={hex(ah)}. Stopping emulation.")
        uc.emu_stop()

    # No specific flags to set/clear by default for INT 16h after execution.
    # ZF for 01h is handled.

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
        eflags = uc.reg_read(UC_X86_REG_EFLAGS)
        eflags &= ~0x0001 # Clear Carry Flag (CF)
        uc.reg_write(UC_X86_REG_EFLAGS, eflags)
        
    else:
        print(f"    Unhandled INT 21h function: AH={hex(ah)}. Stopping emulation.")
        uc.emu_stop()
