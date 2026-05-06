# DESIGN.md — Hermes Vault v0.6.0 Launch

## Style Prompt
Cinematic SaaS product launch. Dark depth, particle energy, high contrast. Think Stripe Sessions, Apple keynote title cards, but for developer tools. Deep space with electric accents. Motion IS the message — every word slams in with weight.

## Colors
- `#06060E` — deep void background
- `#0A0A18` — elevated dark surface
- `#00E5FF` — electric cyan (primary accent, headlines, particles)
- `#FF5722` — energy orange (secondary accent, CTA, sparks)
- `#7C4DFF` — deep purple (tertiary, depth layers, ambient particles)
- `#FFFFFF` — pure white (short bursts only, flash frames)

## Typography
- Display: `"Inter", system-ui, sans-serif` — bold (700) for headlines, extra-bold (800) for hero
- Code: `"Fira Code", "JetBrains Mono", monospace` — for terminal snippets
- No light weights. Nothing below 500. Everything has presence.

## Motion Character
- **Slam.** Elements don't fade in — they scale in from 0.8→1.0 or 1.15→1.0 with overshoot.
- **Stagger.** Parallel entrances at 0.05-0.1s offsets. Never sequential one-at-a-time.
- **Particles.** Every major beat triggers a burst of CSS particles (small circles, 2-8px, scattering outward).
- **Speed.** 0.2-0.4s per entrance tween. Nothing takes longer than 0.5s except particle trails.
- **Flash frames.** 2-3 frame white flash between major sections. Not a transition — an event.
- **Parallax depth.** Background gradient shifts, particles float at different z-depths.

## Eases
- Entrances: `back.out(2.0)`, `power4.out`, `expo.out`
- Exits/slams: `power3.in`, `expo.in`
- Particles: `power3.out` for outward scatter, `none` for linear drift

## Visual Language
- Deep radial gradient background (centered glow)
- Floating particle field — 3 layers (far/slow, mid, near/fast)
- Large typography fills 40-60% of frame width
- Code snippets in translucent dark panels with subtle border glow
- White flash frames (2-3 frames) between major beats
- Subtle chromatic aberration on hero text (text-shadow offsets)

## What NOT to Do
- NO CRT, terminal green, scanlines, or retro aesthetic
- NO typewriter effects or slow text reveals
- NO sequential single-element reveals — everything staggers in parallel
- NO flat black backgrounds — always gradient with depth
- NO elements sitting still for more than 1.5s without particle movement
- NO font sizes below 28px (except code at 20px)
- NO smooth crossfades between sections — cuts or flash frames only

## Scene Structure (single composition, 15s)
1. `[0-1.5s]` — Particle burst + "HERMES VAULT" hero slam, "v0.6.0" badge
2. `[1.5-4.5s]` — "OAuth PKCE" / "Auto-Refresh" / "MCP Native" staggered slam + particle field
3. `[4.5-8.0s]` — Terminal mock panels slide in, code fragments appear
4. `[8.0-11.5s]` — "LOCAL-FIRST" / "ENCRYPTED" / "OPEN SOURCE" badges slam, particle intensity peaks
5. `[11.5-15.0s]` — CTA: install command, GitHub URL, final particle burst + fade to black
