"""Builds the DIDA identity as SVG. Run: python assets/logo/build_logo.py

Mark: five nested D-shaped walls (one per defense layer) on a shared arc centre.
Every wall has one opening and the openings are staggered, so the way to the
core winds through every layer: defense in depth, drawn as a labyrinth.
Wordmark: D, I, D, A drawn from the same stroke and the same half-circle module.
"""
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))

INK = '#121212'
BONE = '#EFEBE3'
SIGNAL = '#FF4F1F'

STROKE = 9          # wall thickness
STEP = 16           # distance between walls
OUTER_R = 80        # outer D: half-height == straight top length
CX = CY = 100       # arc centre (shared by all five walls)
GAP = 17            # opening width in px, same for every wall

# Where each wall opens, as a fraction of its own perimeter. The path starts at
# the middle of the left side and runs up -> top -> arc -> bottom -> back down.
# 0.21 top, 0.50 right (3 o'clock), 0.79 bottom, 0.93 left, 0.39 upper-right.
OPENINGS = [0.21, 0.50, 0.79, 0.93, 0.385]


def d_path(r, cx=CX, cy=CY):
    """D shape whose straight top/bottom are r long and whose arc has radius r."""
    x0 = cx - r
    return (f'M{x0:.2f},{cy:.2f} V{cy - r:.2f} H{cx:.2f} '
            f'A{r:.2f},{r:.2f} 0 0 1 {cx:.2f},{cy + r:.2f} H{x0:.2f} Z')


def wall(r, opening, color):
    per = r * (4 + math.pi)               # 2r left + r top + pi r arc + r bottom
    g = GAP / per * 100                   # opening as % of pathLength=100
    p = opening * 100 - g / 2             # opening starts here
    offset = (100 - g - p) % 100
    return (f'<path d="{d_path(r)}" pathLength="100" stroke="{color}" '
            f'stroke-dasharray="{100 - g:.3f} {g:.3f}" stroke-dashoffset="{offset:.3f}"/>')


def mark(color, accent, tx=0, ty=0):
    walls = [wall(OUTER_R - k * STEP, OPENINGS[k], color) for k in range(5)]
    return (f'<g transform="translate({tx} {ty})">'
            f'<g fill="none" stroke-width="{STROKE}" stroke-linejoin="miter" stroke-linecap="butt">'
            + ''.join(walls) +
            f'</g><rect x="{CX - 6}" y="{CY - 6}" width="12" height="12" fill="{accent}"/></g>')


def wordmark(color, x, top, h):
    """D I D A on one cap height; all curves are half-circles of radius h/2."""
    r = h / 2
    bot = top + h
    gap = 0.42 * h
    parts = []

    def letter_d(x0):
        parts.append(f'<path d="M{x0:.2f},{top:.2f} H{x0 + r:.2f} '
                     f'A{r:.2f},{r:.2f} 0 0 1 {x0 + r:.2f},{bot:.2f} H{x0:.2f} Z"/>')
        return x0 + 2 * r

    def letter_i(x0):
        parts.append(f'<path d="M{x0:.2f},{top:.2f} V{bot:.2f}"/>')
        return x0

    def letter_a(x0):
        parts.append(f'<path d="M{x0:.2f},{bot + STROKE / 2:.2f} V{top + r:.2f} '
                     f'A{r:.2f},{r:.2f} 0 0 1 {x0 + 2 * r:.2f},{top + r:.2f} V{bot + STROKE / 2:.2f}"/>')
        parts.append(f'<path d="M{x0:.2f},{top + r + 0.22 * h:.2f} H{x0 + 2 * r:.2f}"/>')
        return x0 + 2 * r

    cur = x + STROKE / 2
    cur = letter_d(cur) + gap
    cur = letter_i(cur) + gap
    cur = letter_d(cur) + gap
    end = letter_a(cur) + STROKE / 2
    svg = (f'<g fill="none" stroke="{color}" stroke-width="{STROKE}" '
           f'stroke-linejoin="miter" stroke-linecap="butt">' + ''.join(parts) + '</g>')
    return svg, end


def lockup(color, accent, bg=None):
    top, h = 56, 64
    wx = 248
    words, wend = wordmark(color, wx, top, h)
    width = math.ceil(wend + 24)
    tag = (f'<text x="{wx}" y="{top + h + 40}" textLength="{wend - wx:.1f}" lengthAdjust="spacing" '
           f'font-family="\'Helvetica Neue\', Helvetica, Arial, sans-serif" font-size="11.5" '
           f'font-weight="700" fill="{color}">DEFENSE-IN-DEPTH ARCHITECTURE</text>')
    back = f'<rect width="{width}" height="200" fill="{bg}"/>' if bg else ''
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} 200" width="{width}" height="200" '
            f'role="img" aria-label="DIDA: Defense-in-Depth Architecture"><title>DIDA</title>'
            + back + mark(color, accent) + words + tag + '</svg>\n')


def icon():
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="200" height="200" '
            'role="img" aria-label="DIDA"><title>DIDA</title>'
            f'<rect width="200" height="200" fill="{INK}"/>' + mark(BONE, SIGNAL) + '</svg>\n')


def write(name, svg):
    with open(os.path.join(HERE, name), 'w', encoding='utf-8', newline='\n') as f:
        f.write(svg)
    print('wrote', name)


write('dida-logo-light.svg', lockup(INK, SIGNAL))        # for light backgrounds
write('dida-logo-dark.svg', lockup(BONE, SIGNAL))        # for dark backgrounds
write('dida-mark.svg', icon())                           # square icon / avatar
