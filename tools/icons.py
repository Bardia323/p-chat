"""Draws the Home Screen icons (web/icon-180.png, web/icon-512.png) with a
headless Chrome: the p-chat wordmark (its dash the tape's five stripes) on
the black sleeve, the stripes again along the bottom. An iPhone takes no
SVG icon, and the Home Screen rounds the corners itself.

    python tools/icons.py <chrome-headless-shell>
"""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STRIPES = ('#ffc21a', '#ff8f1f', '#ff4f2b', '#d81f8a', '#5b2bd8')


def page(size):
    fonts = (ROOT / 'web' / 'fonts').as_uri()
    u = size / 180
    dash = ''.join(f'<i style="background:{c}"></i>' for c in STRIPES)
    band = ''.join(f'<i style="background:{c}"></i>' for c in STRIPES)
    return f'''<!doctype html><style>
@font-face {{ font-family: Righteous; src: url({fonts}/righteous-latin.woff2) format('woff2'); }}
html, body {{ margin: 0; width: {size}px; height: {size}px; background: #141414; overflow: hidden; }}
.mark {{ position: absolute; left: 0; right: 0; top: {52 * u}px; display: flex; justify-content: center; align-items: center;
  font: 400 {38 * u}px/1 Righteous; color: #f3e8cf; letter-spacing: -.01em;
  text-shadow: {1.6 * u}px 0 rgba(255,79,43,.55), -{1.6 * u}px 0 rgba(91,43,216,.6); }}
.dash {{ display: inline-flex; flex-direction: column; width: {23 * u}px; height: {14 * u}px; margin: {5 * u}px {2 * u}px 0 {4 * u}px;
  transform: skewX(-24deg); }}
.dash i, .band i {{ flex: 1; display: block; }}
.band {{ position: absolute; left: 0; right: 0; bottom: 0; height: {34 * u}px; display: flex; flex-direction: column; }}
</style><div class="mark">p<span class="dash">{dash}</span>chat</div><div class="band">{band}</div>'''


def main():
    chrome = sys.argv[1]
    for size in (180, 512):
        with tempfile.TemporaryDirectory() as d:
            html = Path(d) / 'icon.html'
            html.write_text(page(size))
            out = ROOT / 'web' / f'icon-{size}.png'
            subprocess.run([chrome, '--headless', '--disable-gpu', '--hide-scrollbars', '--allow-file-access-from-files',
                            f'--window-size={size},{size}', '--virtual-time-budget=2000', f'--screenshot={out}', html.as_uri()],
                           check=True, capture_output=True)
            print('wrote', out)


if __name__ == '__main__':
    main()
