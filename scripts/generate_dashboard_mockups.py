"""Render dashboard mockups as vector SVG frames.

The generated files intentionally avoid raster/binary assets so downstream
contributors can diff the markup and keep the mockups lightweight.  Each SVG
sticks to the brand tokens referenced in BRAND.md and preserves the
layout/annotation requirements described in the original request.
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import List, Sequence, Tuple

import svgwrite

OUTPUT_DIR = Path('docs/ui/dashboard_mockups')
WIDTH, HEIGHT = 1600, 900
MARGIN = 48
GRID_GAP = 32
NAV_WIDTH = 220

COLORS = {
    'background_dark': '#0E1C36',
    'background_light': '#F4F7FB',
    'card_border': '#A5B3C6',
    'card_surface': '#E1E6EE',
    'deep_surface': '#1A2A4A',
    'accent': '#1BE7FF',
    'secondary': '#F5A623',
    'success': '#19B37E',
    'failure': '#FF4E4E',
    'text_dark': '#152238',
    'text_light': '#F5F7FA',
    'warning': '#F5A623',
}

FONT_HEADLINE = ('Space Grotesk', 28)
FONT_TITLE = ('Space Grotesk', 22)
FONT_BODY = ('Inter', 18)
FONT_META = ('Inter', 16)
FONT_CAPTION = ('Inter', 14)
FONT_MONO = ('JetBrains Mono', 16)

def ensure_output_dir() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def create_canvas(name: str, background: str) -> svgwrite.Drawing:
    dwg = svgwrite.Drawing(str(OUTPUT_DIR / name), size=(WIDTH, HEIGHT))
    dwg.add(dwg.rect(insert=(0, 0), size=(WIDTH, HEIGHT), fill=background))
    return dwg


def add_text(
    dwg: svgwrite.Drawing,
    text: str,
    insert: Tuple[int, int],
    font: Tuple[str, int],
    fill: str,
    weight: str | None = None,
    **extra: str,
) -> None:
    family, size = font
    attrs = {
        'font_family': family,
        'font_size': size,
        'fill': fill,
        'dominant_baseline': 'hanging',
    }
    if weight:
        attrs['font_weight'] = weight
    attrs.update(extra)
    dwg.add(dwg.text(text, insert=insert, **attrs))


def rounded_rect(
    dwg: svgwrite.Drawing,
    bbox: Tuple[int, int, int, int],
    fill: str,
    stroke: str,
    stroke_width: int = 2,
    radius: int = 20,
    opacity: float = 1.0,
) -> svgwrite.shapes.Rect:
    x0, y0, x1, y1 = bbox
    rect = dwg.rect(
        insert=(x0, y0),
        size=(x1 - x0, y1 - y0),
        rx=radius,
        ry=radius,
        fill=fill,
        stroke=stroke,
        stroke_width=stroke_width,
        opacity=opacity,
    )
    dwg.add(rect)
    return rect


def draw_shimmer(dwg: svgwrite.Drawing, bbox: Tuple[int, int, int, int]) -> None:
    x0, y0, x1, y1 = bbox
    width = x1 - x0
    stripe_width = width // 12
    for i in range(12):
        shade = 225 - i * 6
        color = f'rgb({shade},{shade},{shade})'
        dwg.add(
            dwg.rect(
                insert=(x0 + i * stripe_width, y0),
                size=(stripe_width - 2, y1 - y0),
                rx=6,
                ry=6,
                fill=color,
                opacity=0.5,
            )
        )


def draw_line_chart(
    dwg: svgwrite.Drawing,
    bbox: Tuple[int, int, int, int],
    line_color: str,
    shadow_color: str,
) -> None:
    x0, y0, x1, y1 = bbox
    points: List[Tuple[float, float]] = []
    for i in range(8):
        t = i / 7
        x = x0 + t * (x1 - x0)
        wave = math.sin(t * math.pi * 1.5) * 0.35
        y = y1 - (y1 - y0) * (0.4 + wave)
        points.append((x, y))

    shadow = dwg.polyline(points=points, stroke=shadow_color, fill='none', stroke_width=12, opacity=0.35)
    shadow.update({'stroke_linecap': 'round', 'stroke_linejoin': 'round'})
    dwg.add(shadow)
    line = dwg.polyline(points=points, stroke=line_color, fill='none', stroke_width=6)
    line.update({'stroke_linecap': 'round', 'stroke_linejoin': 'round'})
    dwg.add(line)


def add_header(
    dwg: svgwrite.Drawing,
    title: str,
    subtitle: str | None,
    insert: Tuple[int, int],
    color: str,
) -> None:
    add_text(dwg, title, insert=insert, font=FONT_HEADLINE, fill=color)
    if subtitle:
        add_text(
            dwg,
            subtitle,
            insert=(insert[0], insert[1] + 40),
            font=FONT_META,
            fill=color,
        )


def draw_lowfi_grid(dwg: svgwrite.Drawing, cards: Sequence[Tuple[Tuple[int, int, int, int], str]]) -> None:
    for bbox, label in cards:
        rounded_rect(dwg, bbox, fill='#FFFFFF', stroke=COLORS['card_border'])
        add_text(dwg, label, insert=(bbox[0] + 24, bbox[1] + 24), font=FONT_BODY, fill=COLORS['text_dark'])
        dwg.add(
            dwg.line(
                start=(bbox[0] + 24, bbox[1] + 90),
                end=(bbox[2] - 24, bbox[1] + 90),
                stroke=COLORS['card_border'],
                stroke_width=2,
            )
        )


def create_low_fi_home() -> None:
    dwg = create_canvas('lowfi_home.svg', COLORS['background_light'])
    add_header(
        dwg,
        'Home overview wireframe',
        'Critical metrics anchored top-left',
        (MARGIN, MARGIN - 40),
        COLORS['text_dark'],
    )
    card_height = 220
    cards = [
        ((MARGIN, MARGIN, MARGIN + 520, MARGIN + card_height), 'Validator health'),
        ((MARGIN + 540, MARGIN, MARGIN + 1040, MARGIN + card_height), 'Supply pressure'),
        ((MARGIN, MARGIN + card_height + GRID_GAP, MARGIN + 1040, MARGIN + card_height * 2 + GRID_GAP), 'Action queue'),
        (
            (MARGIN, MARGIN + (card_height + GRID_GAP) * 2, MARGIN + 1040, MARGIN + (card_height + GRID_GAP) * 2 + card_height),
            'Live logs',
        ),
    ]
    draw_lowfi_grid(dwg, cards)
    dwg.save()


def create_low_fi_action_detail() -> None:
    dwg = create_canvas('lowfi_action_detail.svg', COLORS['background_light'])
    add_header(
        dwg,
        'Action detail wireframe',
        'Timeline + risk summary left-aligned',
        (MARGIN, MARGIN - 40),
        COLORS['text_dark'],
    )
    meta_card = (MARGIN, MARGIN, WIDTH // 2 - GRID_GAP, HEIGHT - MARGIN)
    timeline_card = (WIDTH // 2 + GRID_GAP, MARGIN, WIDTH - MARGIN, HEIGHT - 240)
    log_card = (WIDTH // 2 + GRID_GAP, HEIGHT - 220, WIDTH - MARGIN, HEIGHT - MARGIN)
    draw_lowfi_grid(
        dwg,
        [
            (meta_card, 'Action metadata'),
            (timeline_card, 'Execution timeline'),
            (log_card, 'Inline log stream'),
        ],
    )
    dwg.save()


def create_low_fi_log_stream() -> None:
    dwg = create_canvas('lowfi_log_stream.svg', COLORS['background_light'])
    add_header(
        dwg,
        'Log streaming wireframe',
        'JetBrains Mono body for alignment',
        (MARGIN, MARGIN - 40),
        COLORS['text_dark'],
    )
    control_card = (MARGIN, MARGIN, WIDTH - MARGIN, MARGIN + 120)
    log_card = (MARGIN, MARGIN + 140, WIDTH - MARGIN, HEIGHT - 160)
    action_card = (MARGIN, HEIGHT - 140, WIDTH - MARGIN, HEIGHT - MARGIN)
    draw_lowfi_grid(
        dwg,
        [
            (control_card, 'Filter bar'),
            (log_card, 'Streaming log buffer <80% height'),
            (action_card, 'Ack + export controls'),
        ],
    )
    dwg.save()


def create_low_fi_states() -> None:
    dwg = create_canvas('lowfi_states.svg', COLORS['background_light'])
    add_header(
        dwg,
        'Outcome states wireframe',
        'Success / warning / failure tiles',
        (MARGIN, MARGIN - 40),
        COLORS['text_dark'],
    )
    card_w = (WIDTH - MARGIN * 2 - GRID_GAP * 2) // 3
    cards = []
    for i in range(3):
        x0 = MARGIN + i * (card_w + GRID_GAP)
        cards.append(((x0, MARGIN, x0 + card_w, HEIGHT - MARGIN), ['Success confirmation', 'Warning resolution', 'Failure diagnostics'][i]))
    draw_lowfi_grid(dwg, cards)
    for bbox, label in cards:
        dwg.add(
            dwg.rect(
                insert=(bbox[0] + 24, bbox[1] + 120),
                size=(bbox[2] - bbox[0] - 48, 100),
                stroke=COLORS['card_border'],
                fill='none',
                rx=12,
                ry=12,
            )
        )
    dwg.save()


def draw_nav(dwg: svgwrite.Drawing) -> None:
    rounded_rect(
        dwg,
        (MARGIN, MARGIN, MARGIN + NAV_WIDTH, HEIGHT - MARGIN),
        fill=COLORS['deep_surface'],
        stroke=COLORS['accent'],
        radius=24,
        stroke_width=2,
    )
    add_text(dwg, 'Ops console', (MARGIN + 32, MARGIN + 32), FONT_TITLE, COLORS['text_light'])
    menu_items = ['Home', 'Actions', 'Logs', 'Alerts', 'Settings']
    for i, item in enumerate(menu_items):
        color = COLORS['accent'] if i == 0 else COLORS['text_light']
        add_text(dwg, item, (MARGIN + 32, MARGIN + 96 + i * 44), FONT_META, color)


def create_home_highfi() -> None:
    dwg = create_canvas('highfi_home.svg', COLORS['background_dark'])
    draw_nav(dwg)
    top_left = (MARGIN + NAV_WIDTH + 40, MARGIN)
    hero_card = (top_left[0], top_left[1], top_left[0] + 480, top_left[1] + 260)
    rounded_rect(dwg, hero_card, fill=COLORS['card_surface'], stroke=COLORS['accent'])
    add_text(dwg, 'Net Liquidity', (hero_card[0] + 24, hero_card[1] + 24), FONT_TITLE, COLORS['text_dark'])
    add_text(dwg, '$182.3M', (hero_card[0] + 24, hero_card[1] + 84), FONT_HEADLINE, COLORS['text_dark'])
    add_text(dwg, '+2.4% vs last hour', (hero_card[0] + 24, hero_card[1] + 144), FONT_META, COLORS['success'])
    dwg.add(
        dwg.line(
            start=(hero_card[0] + 24, hero_card[1] + 190),
            end=(hero_card[2] - 24, hero_card[1] + 190),
            stroke=COLORS['accent'],
            stroke_width=4,
        )
    )

    supply_card = (hero_card[2] + GRID_GAP, top_left[1], hero_card[2] + GRID_GAP + 520, top_left[1] + 260)
    rounded_rect(dwg, supply_card, fill=COLORS['card_surface'], stroke=COLORS['secondary'])
    add_text(dwg, 'Supply pressure', (supply_card[0] + 24, supply_card[1] + 24), FONT_TITLE, COLORS['text_dark'])
    draw_line_chart(
        dwg,
        (supply_card[0] + 24, supply_card[1] + 100, supply_card[2] - 24, supply_card[1] + 220),
        COLORS['accent'],
        COLORS['secondary'],
    )

    queue_card = (hero_card[0], hero_card[3] + GRID_GAP, hero_card[0] + 780, hero_card[3] + GRID_GAP + 220)
    rounded_rect(dwg, queue_card, fill=COLORS['card_surface'], stroke=COLORS['card_border'])
    add_text(dwg, 'Queued actions', (queue_card[0] + 24, queue_card[1] + 24), FONT_TITLE, COLORS['text_dark'])
    draw_shimmer(dwg, (queue_card[0] + 24, queue_card[1] + 90, queue_card[2] - 24, queue_card[1] + 130))
    add_text(
        dwg,
        'Shimmer loader communicates 150–200ms ease-out transitions',
        (queue_card[0] + 24, queue_card[1] + 150),
        FONT_META,
        COLORS['text_dark'],
    )

    log_card = (queue_card[0], queue_card[3] + GRID_GAP, queue_card[0] + 780, queue_card[3] + GRID_GAP + 220)
    rounded_rect(dwg, log_card, fill='#FFFFFF', stroke=COLORS['card_border'])
    add_text(dwg, 'Recent signals', (log_card[0] + 24, log_card[1] + 24), FONT_TITLE, COLORS['text_dark'])
    log_lines = [
        '08:34:21 miner/03 synced in 182 ms',
        '08:34:24 swap-router defused guard rail limit',
        '08:34:28 streaming proof window recalculated',
    ]
    for i, line in enumerate(log_lines):
        add_text(dwg, line, (log_card[0] + 24, log_card[1] + 90 + i * 32), FONT_MONO, COLORS['text_dark'])
    dwg.save()


def create_action_highfi() -> None:
    dwg = create_canvas('highfi_action_detail.svg', COLORS['background_dark'])
    draw_nav(dwg)
    meta_card = (MARGIN + NAV_WIDTH + 40, MARGIN, WIDTH - MARGIN, HEIGHT - MARGIN)
    rounded_rect(dwg, meta_card, fill=COLORS['card_surface'], stroke=COLORS['accent'])

    left_col = (meta_card[0] + 24, meta_card[1] + 24, meta_card[0] + 360, meta_card[3] - 24)
    rounded_rect(dwg, left_col, fill='#FFFFFF', stroke=COLORS['card_border'])
    add_text(dwg, 'Action metadata', (left_col[0] + 16, left_col[1] + 16), FONT_TITLE, COLORS['text_dark'])
    meta_rows = [
        ('Action ID', '#6742-HEG-0342'),
        ('Priority', 'High (auto)'),
        ('Submitted', '08:24:11 UTC'),
        ('Operator', 'auto-signer-02'),
    ]
    for i, (label, value) in enumerate(meta_rows):
        y = left_col[1] + 80 + i * 72
        add_text(dwg, label, (left_col[0] + 8, y), FONT_CAPTION, COLORS['text_dark'])
        add_text(dwg, value, (left_col[0] + 8, y + 24), FONT_BODY, COLORS['text_dark'])

    timeline_card = (left_col[2] + GRID_GAP, meta_card[1] + 24, meta_card[2] - 24, meta_card[1] + 380)
    rounded_rect(dwg, timeline_card, fill='#FFFFFF', stroke=COLORS['card_border'])
    add_text(dwg, 'Execution timeline', (timeline_card[0] + 24, timeline_card[1] + 24), FONT_TITLE, COLORS['text_dark'])
    timeline_steps = ['Validate inputs', 'Simulate swap path', 'Multisig approval', 'Broadcast tx', 'Confirm finality']
    for i, step in enumerate(timeline_steps):
        y = timeline_card[1] + 90 + i * 48
        dwg.add(
            dwg.line(
                start=(timeline_card[0] + 24, y + 20),
                end=(timeline_card[0] + 24, y + 60),
                stroke=COLORS['accent'],
                stroke_width=4,
            )
        )
        dwg.add(
            dwg.circle(
                center=(timeline_card[0] + 24, y + 20),
                r=8,
                fill=COLORS['accent'],
            )
        )
        add_text(dwg, step, (timeline_card[0] + 48, y + 10), FONT_BODY, COLORS['text_dark'])

    result_card = (left_col[2] + GRID_GAP, timeline_card[3] + GRID_GAP, meta_card[2] - 24, meta_card[3] - 24)
    rounded_rect(dwg, result_card, fill='#FFFFFF', stroke=COLORS['card_border'])
    add_text(dwg, 'Risk summary & logs', (result_card[0] + 24, result_card[1] + 24), FONT_TITLE, COLORS['text_dark'])
    add_text(
        dwg,
        'Guard Rail triggered on price impact > 2.5%',
        (result_card[0] + 24, result_card[1] + 80),
        FONT_BODY,
        COLORS['failure'],
    )
    log_lines = [
        '08:25:02 WARN slippage_estimate=2.8%',
        '08:25:05 INFO quorum_signatures=7/7',
        '08:25:08 INFO broadcast_txid=0x9821…',
    ]
    for i, line in enumerate(log_lines):
        add_text(dwg, line, (result_card[0] + 24, result_card[1] + 140 + i * 34), FONT_MONO, COLORS['text_dark'])
    dwg.save()


def create_log_highfi() -> None:
    dwg = create_canvas('highfi_log_stream.svg', COLORS['background_dark'])
    draw_nav(dwg)
    header = (MARGIN + NAV_WIDTH + 40, MARGIN, WIDTH - MARGIN, MARGIN + 120)
    rounded_rect(dwg, header, fill=COLORS['card_surface'], stroke=COLORS['accent'])
    add_text(dwg, 'Live log stream', (header[0] + 24, header[1] + 24), FONT_TITLE, COLORS['text_dark'])
    add_text(
        dwg,
        'Filtering on severity >= warn | 150ms transitions',
        (header[0] + 24, header[1] + 72),
        FONT_META,
        COLORS['text_dark'],
    )

    log_card = (MARGIN + NAV_WIDTH + 40, header[3] + GRID_GAP, WIDTH - MARGIN, HEIGHT - 180)
    rounded_rect(dwg, log_card, fill='#050B18', stroke=COLORS['accent'])
    log_lines = [
        '08:30:41 [INFO] heartbeat ok latency=121ms',
        '08:30:42 [WARN] feed drift detected delta=0.87bps',
        '08:30:43 [WARN] rerouting liquidity chunk=3.2M',
        '08:30:44 [INFO] guard rail restored window=4m',
        '08:30:45 [FAIL] signer quorum timeout >200ms',
    ]
    colors = [COLORS['text_light'], COLORS['warning'], COLORS['warning'], COLORS['text_light'], COLORS['failure']]
    for i, line in enumerate(log_lines):
        add_text(dwg, line, (log_card[0] + 32, log_card[1] + 32 + i * 36), FONT_MONO, colors[i])

    controls = (MARGIN + NAV_WIDTH + 40, log_card[3] + GRID_GAP, WIDTH - MARGIN, HEIGHT - MARGIN)
    rounded_rect(dwg, controls, fill=COLORS['card_surface'], stroke=COLORS['card_border'])
    add_text(
        dwg,
        'Ack warnings • Export CSV • Follow action detail →',
        (controls[0] + 24, controls[1] + 24),
        FONT_BODY,
        COLORS['text_dark'],
    )
    dwg.save()


def create_states_highfi() -> None:
    dwg = create_canvas('highfi_states.svg', COLORS['background_dark'])
    draw_nav(dwg)
    card_w = (WIDTH - (MARGIN + NAV_WIDTH + 40) - MARGIN - GRID_GAP * 2) // 3
    base_x = MARGIN + NAV_WIDTH + 40
    statuses = [
        ('Success', COLORS['success'], 'Proof Green'),
        ('Warning', COLORS['warning'], 'Molten Amber'),
        ('Failure', COLORS['failure'], 'Guard Rail'),
    ]
    for i, (label, color, token) in enumerate(statuses):
        x0 = base_x + i * (card_w + GRID_GAP)
        bbox = (x0, MARGIN, x0 + card_w, HEIGHT - MARGIN)
        rounded_rect(dwg, bbox, fill=COLORS['card_surface'], stroke=color, stroke_width=4)
        add_text(dwg, f'{label} state', (bbox[0] + 24, bbox[1] + 24), FONT_TITLE, COLORS['text_dark'])
        add_text(dwg, f'Annotation color: {token}', (bbox[0] + 24, bbox[1] + 70), FONT_META, color)
        chart_box = (bbox[0] + 24, bbox[1] + 120, bbox[2] - 24, bbox[1] + 260)
        draw_line_chart(
            dwg,
            chart_box,
            COLORS['secondary'] if label == 'Warning' else color,
            COLORS['accent'],
        )
        add_text(
            dwg,
            'Charts use Ion + Amber lines with Guard Rail thresholds',
            (bbox[0] + 24, bbox[1] + 280),
            FONT_CAPTION,
            COLORS['text_dark'],
        )
        status_copy = {
            'Success': 'Validator proofs sealed +1.2% capacity',
            'Warning': 'Liquidity pocket delayed 90s • review soon',
            'Failure': 'Guard Rail tripped by 3.1% variance',
        }
        add_text(dwg, status_copy[label], (bbox[0] + 24, bbox[1] + 330), FONT_BODY, color)
        add_text(dwg, 'CTA: Review details →', (bbox[0] + 24, bbox[1] + 380), FONT_META, COLORS['accent'])
    dwg.save()


def main() -> None:
    ensure_output_dir()
    create_low_fi_home()
    create_low_fi_action_detail()
    create_low_fi_log_stream()
    create_low_fi_states()
    create_home_highfi()
    create_action_highfi()
    create_log_highfi()
    create_states_highfi()


if __name__ == '__main__':
    main()
