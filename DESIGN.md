# DESIGN.md — Hermes Vault v0.6.0 Launch

## Style Prompt
CRT terminal, green phosphor on black, glitch-core. Old-school hacker aesthetic meets modern CLI tool. Flicker, scanlines, slight chromatic aberration at edges. Monospace everything. The vibe is "you just gained root."

## Colors
- `#000000` — canvas (true black, the void)
- `#00FF41` — primary phosphor green (bright, active text/accents)
- `#008F11` — dim phosphor (secondary text, inactive elements)
- `#003B00` — trace phosphor (background elements, faint grids)
- `#FFFFFF` — white flash (glitch spikes, cursor blink only)

## Typography
- Primary: `"Courier New", "Fira Code", monospace` — terminal monospace for all text
- Weight: regular (400) only — no bold. Terminal fonts don't do bold.
- Kerning: tight, use letter-spacing sparingly (only for titles)

## Motion Character
- Jittery, glitchy, typewriter-style reveals
- Text appears character-by-character or in rapid bursts
- Occasional horizontal tear / scanline flash
- Eases: `steps()` for typewriter, `power4.in` for glitch exits, `none` for scanline slides
- No smooth fades — everything snaps or tears

## Visual Language
- Scanline overlay (thin horizontal lines at 2-3px spacing, 10-15% opacity)
- Corner brackets framing key text (like a terminal UI)
- Blinking block cursor as a visual anchor element
- Status indicators: `[ OK ]`, `[....]`, `>>>` prompts
- Glitch distortion on key transitions (horizontal slice displacement)

## What NOT to Do
- NO gradients, shadows, rounded corners, or soft edges
- NO colors other than green palette + black + white
- NO bold, italic, or uppercase (monospace all-caps is fine, but no CSS font-weight tricks)
- NO smooth fades or crossfades between scenes — cuts only, or glitch teardown
- NO modern glassmorphism, blur effects, or material design
- NO font sizes below 16px — must be legible through CRT degradation

## Scene Structure (single composition, ~55s)
1. `[0-5s]` — Hermes Vault logo/name reveal, flickering cursor
2. `[5-12s]` — Tagline: "local-first credential broker" — typewriter reveal
3. `[12-22s]` — v0.6.0 headline: OAuth PKCE — glitch-in text
4. `[22-35s]` — Feature bullets: PKCE login, auto-refresh, MCP tools — typewriter list
5. `[35-45s]` — Terminal mock: `hermes-vault oauth login google` demo sequence
6. `[45-52s]` — CTA: install command + GitHub URL
7. `[52-55s]` — Fade to black with cursor blink ending
