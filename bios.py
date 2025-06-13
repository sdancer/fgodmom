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
        
        if al == 0x30: # Load 8x8 font (double dot)
            handle_int10_11_30(uc)

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


