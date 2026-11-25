from __future__ import annotations

import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parent
NAVY = (16, 24, 32)
PANEL = (23, 35, 45)
CYAN = (97, 184, 197)
MINT = (82, 196, 154)
WHITE = (231, 237, 242)
FONT = {
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "F": ("11111", "10000", "10000", "11110", "10000", "10000", "10000"),
    "I": ("111", "010", "010", "010", "010", "010", "111"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "V": ("10001", "10001", "10001", "10001", "01010", "01010", "00100"),
    "W": ("10001", "10001", "10001", "10101", "10101", "11011", "10001"),
    "Z": ("11111", "00001", "00010", "00100", "01000", "10000", "11111"),
}

Color = tuple[int, int, int]
Canvas = list[list[Color]]


def new_canvas(width: int, height: int, color: Color) -> Canvas:
    return [[color for _ in range(width)] for _ in range(height)]


def set_pixel(canvas: Canvas, x: int, y: int, color: Color) -> None:
    if 0 <= y < len(canvas) and 0 <= x < len(canvas[0]):
        canvas[y][x] = color


def polygon(canvas: Canvas, points: list[tuple[int, int]], color: Color) -> None:
    height, width = len(canvas), len(canvas[0])
    min_x = max(0, min(x for x, _ in points))
    max_x = min(width - 1, max(x for x, _ in points))
    min_y = max(0, min(y for _, y in points))
    max_y = min(height - 1, max(y for _, y in points))
    for y in range(min_y, max_y + 1):
        for x in range(min_x, max_x + 1):
            inside = False
            previous = points[-1]
            for current in points:
                x1, y1 = previous
                x2, y2 = current
                if (y1 > y) != (y2 > y):
                    crossing = (x2 - x1) * (y - y1) / (y2 - y1) + x1
                    if x < crossing:
                        inside = not inside
                previous = current
            if inside:
                set_pixel(canvas, x, y, color)


def line(
    canvas: Canvas,
    start: tuple[int, int],
    end: tuple[int, int],
    color: Color,
    thickness: int,
) -> None:
    x0, y0 = start
    x1, y1 = end
    dx, dy = abs(x1 - x0), abs(y1 - y0)
    step_x = 1 if x0 < x1 else -1
    step_y = 1 if y0 < y1 else -1
    error = dx - dy
    radius = thickness // 2
    while True:
        for offset_y in range(-radius, radius + 1):
            for offset_x in range(-radius, radius + 1):
                set_pixel(canvas, x0 + offset_x, y0 + offset_y, color)
        if x0 == x1 and y0 == y1:
            break
        doubled_error = 2 * error
        if doubled_error > -dy:
            error -= dy
            x0 += step_x
        if doubled_error < dx:
            error += dx
            y0 += step_y


def draw_shield(canvas: Canvas, center_x: int, center_y: int, size: int) -> None:
    outer = [
        (center_x - size * 38 // 100, center_y - size * 42 // 100),
        (center_x + size * 38 // 100, center_y - size * 42 // 100),
        (center_x + size * 34 // 100, center_y + size * 8 // 100),
        (center_x + size * 20 // 100, center_y + size * 32 // 100),
        (center_x, center_y + size * 46 // 100),
        (center_x - size * 20 // 100, center_y + size * 32 // 100),
        (center_x - size * 34 // 100, center_y + size * 8 // 100),
    ]
    inner = [
        (
            center_x + (x - center_x) * 78 // 100,
            center_y + (y - center_y) * 78 // 100,
        )
        for x, y in outer
    ]
    polygon(canvas, outer, CYAN)
    polygon(canvas, inner, PANEL)
    points = [
        (center_x - size * 22 // 100, center_y - size * 3 // 100),
        (center_x - size * 11 // 100, center_y + size * 21 // 100),
        (center_x, center_y - size * 14 // 100),
        (center_x + size * 11 // 100, center_y + size * 21 // 100),
        (center_x + size * 22 // 100, center_y - size * 3 // 100),
    ]
    thickness = max(1, size * 5 // 100)
    for start, end in zip(points, points[1:]):
        line(canvas, start, end, MINT, thickness)


def draw_text(
    canvas: Canvas,
    text: str,
    top: int,
    scale: int,
    color: Color,
) -> None:
    glyph_width = 5
    spacing = 2
    text_width = (len(text) * (glyph_width + spacing) - spacing) * scale
    left = (len(canvas[0]) - text_width) // 2
    for character in text:
        glyph = FONT[character]
        for row, pattern in enumerate(glyph):
            for column, bit in enumerate(pattern):
                if bit == "1":
                    for dy in range(scale):
                        for dx in range(scale):
                            set_pixel(
                                canvas,
                                left + column * scale + dx,
                                top + row * scale + dy,
                                color,
                            )
        left += (glyph_width + spacing) * scale


def bitmap_bytes(canvas: Canvas) -> bytes:
    height, width = len(canvas), len(canvas[0])
    row_size = (width * 3 + 3) & ~3
    pixels = bytearray()
    for row in reversed(canvas):
        for red, green, blue in row:
            pixels.extend((blue, green, red))
        pixels.extend(b"\0" * (row_size - width * 3))
    file_size = 14 + 40 + len(pixels)
    header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)
    info = struct.pack(
        "<IIIHHIIIIII",
        40,
        width,
        height,
        1,
        24,
        0,
        len(pixels),
        2835,
        2835,
        0,
        0,
    )
    return header + info + pixels


def write_bmp(path: Path, canvas: Canvas) -> None:
    path.write_bytes(bitmap_bytes(canvas))


def icon_image(size: int) -> bytes:
    canvas = new_canvas(size, size, NAVY)
    draw_shield(canvas, size // 2, size // 2, size * 94 // 100)
    height, width = size, size
    pixels = bytearray()
    for row in reversed(canvas):
        for red, green, blue in row:
            pixels.extend((blue, green, red, 255))
    mask = b"\0" * (((width + 31) // 32) * 4 * height)
    info = struct.pack(
        "<IIIHHIIIIII",
        40,
        width,
        height * 2,
        1,
        32,
        0,
        len(pixels),
        0,
        0,
        0,
        0,
    )
    return info + pixels + mask


def write_icon(path: Path) -> None:
    images = [(16, icon_image(16)), (32, icon_image(32)), (48, icon_image(48)), (64, icon_image(64))]
    directory_size = 6 + 16 * len(images)
    offset = directory_size
    entries = bytearray()
    payload = bytearray()
    for size, data in images:
        entries.extend(
            struct.pack(
                "<BBBBHHII",
                size if size < 256 else 0,
                size if size < 256 else 0,
                0,
                0,
                1,
                32,
                len(data),
                offset,
            )
        )
        payload.extend(data)
        offset += len(data)
    path.write_bytes(
        struct.pack("<HHH", 0, 1, len(images)) + entries + payload
    )


def main() -> None:
    banner = new_canvas(164, 314, NAVY)
    for y in range(314):
        blend = y * 12 // 313
        color = (
            NAVY[0] + blend,
            NAVY[1] + blend,
            NAVY[2] + blend,
        )
        for x in range(164):
            set_pixel(banner, x, y, color)
    draw_shield(banner, 82, 104, 112)
    draw_text(banner, "RIZVI", 205, 4, WHITE)
    draw_text(banner, "WAF", 244, 4, CYAN)

    small = new_canvas(55, 55, PANEL)
    draw_shield(small, 27, 27, 50)

    write_bmp(ROOT / "wizard.bmp", banner)
    write_bmp(ROOT / "wizard-small.bmp", small)
    write_icon(ROOT / "RIZVI-WAF.ico")


if __name__ == "__main__":
    main()
