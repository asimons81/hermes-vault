"""
Hermes Vault UI — ASCII art banners, status callouts, and color helpers.

Uses ANSI True Color (24-bit). Color is injected at render time.
HERMES_VAULT_NO_COLOR=1 disables all color output.
"""
from __future__ import annotations

import os
import sys
import typing

# ── Terminal detection ──────────────────────────────────────────────────────
_FORCE_COLOR = os.getenv("HERMES_VAULT_NO_COLOR", "0") != "1"
_SUPPORTS_256 = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_ANSI_ESC = "\033"
_RESET_STR = "\033[0m"

# ── Color helpers ────────────────────────────────────────────────────────────
def _c(r: int, g: int, b: int) -> str:
    if not _FORCE_COLOR:
        return ""
    return f"{_ANSI_ESC}[38;2;{r};{g};{b}m"

def _cb(r: int, g: int, b: int) -> str:
    if not _FORCE_COLOR:
        return ""
    return f"{_ANSI_ESC}[1;38;2;{r};{g};{b}m"

_RESET = _RESET_STR if _FORCE_COLOR else ""

# ── Palette ─────────────────────────────────────────────────────────────────
GOLD   = (255, 190,  30)
AMBER  = (255, 140,   0)
CYAN   = (  0, 210, 210)
TEAL   = (  0, 180, 160)
GREEN  = (  0, 220, 100)
RED    = (220,  50,  50)
SILVER = (180, 190, 200)
DIM    = ( 40,  40,  60)
DK     = ( 15,  15,  25)

# Warm-only splash palette (active variant: "ember-crown")
SPLASH_GOLD    = (255, 186,  48)
SPLASH_AMBER   = (232, 126,  22)
SPLASH_BURNT   = (173,  72,  18)
SPLASH_COPPER  = (104,  48,  18)
SPLASH_TAGLINE = (235, 200, 150)

def c(text: str, rgb: tuple[int, int, int]) -> str:
    """Colorize text with an RGB tuple."""
    return f"{_c(*rgb)}{text}{_RESET}"

def cb(text: str, rgb: tuple[int, int, int]) -> str:
    """Bold colorize text."""
    return f"{_cb(*rgb)}{text}{_RESET}"

def rule(char: str = "─", rgb: tuple[int, int, int] = DIM) -> str:
    """Return a horizontal rule string."""
    return f"{_c(*rgb)}{char * 72}{_RESET}"

# ── USER-PROVIDED SPLASH ──────────────────────────────────────────────────────
# User-provided art. All lines validated at 79 chars.
# PRIMARY: Unicode box-drawing + FULL BLOCK (█)
# FALLBACK: Pure ASCII 0x20-0x7E
#
# Character sets:
#   PRIMARY  → ╔ ╗ ║ ╚ ═ │ █  (box-drawing + full block)
#   FALLBACK → + = |     #  (ASCII only)

_W = 79  # target width

# PRIMARY art lines — plain strings, no ANSI
_PRIMARY_ART: list[str] = [
    "╔═════════════════════════════════════════════════════════════════════════════╗",
    "║                                                                             ║",
    "║                                                                             ║",
    "║   ██╗  ██╗███████╗██████╗ ███╗   ███╗███████╗███████╗                       ║",
    "║   ██║  ██║██╔════╝██╔══██╗████╗ ████║██╔════╝██╔════╝                       ║",
    "║   ███████║█████╗  ██████╔╝██╔████╔██║█████╗  ███████╗                       ║",
    "║   ██╔══██║██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══╝  ╚════██║                       ║",
    "║   ██║  ██║███████╗██║  ██║██║ ╚═╝ ██║███████╗███████║                       ║",
    "║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝                       ║",
    "║                                                                             ║",
    "║                         ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗            ║",
    "║                         ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝            ║",
    "║                         ██║   ██║███████║██║   ██║██║     ██║               ║",
    "║                         ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║               ║",
    "║                          ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║               ║",
    "║                           ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝               ║",
    "║                                                                             ║",
    "║                  secure credential vault \u2022 broker \u2022 scanner                 ║",
    "║                                                                             ║",
    "╚═════════════════════════════════════════════════════════════════════════════╝",
]

# FALLBACK art lines — plain ASCII
_FALLBACK_ART: list[str] = [
    "+=============================================================================+",
    "|                                                                             |",
    "|                                                                             |",
    "|   |   | ##### ####  #   # #####  ####                                       |",
    "|   |   | |     |   | ## ## |     |                                           |",
    "|   ##### ####  ####  # # # ####   ####                                       |",
    "|   |   | |     |  |  |   | |         |                                       |",
    "|   |   | ##### |   | |   | ##### ####                                        |",
    "|                                                                             |",
    "|                    #   #  ###  #   # #   #####                              |",
    "|                    #   # #   # #   # #     |                                |",
    "|                    #   # ##### #   # #     |                                |",
    "|                     # #  #   # #   # #     |                                |",
    "|                      #   #   #  ###  ##### |                                |",
    "|                                                                             |",
    "|                  secure credential vault | broker | scanner                 |",
    "|                                                                             |",
    "+=============================================================================+",
]

# Per-line color roles: None = no color, str = warm color role.
# HERMES rows: gold → amber → burnt → copper.
# VAULT rows: amber into copper for forged depth.
_PRIMARY_COLORS: list[str | None] = [
    None, None, None,
    "gold", "gold", "amber", "amber", "burnt", "copper",
    None,
    "amber", "amber", "burnt", "burnt", "copper", "copper",
    None,
    "tagline", None,
    None,
]

_FALLBACK_COLORS: list[str | None] = [
    None, None, None,
    "gold", "gold", "amber", "burnt", "copper", None,
    "amber", "burnt", "burnt", "copper", "copper",
    None,
    "tagline", None,
    None,
]

_SPLASH_ROLE_RGB: dict[str, tuple[int, int, int]] = {
    "gold": SPLASH_GOLD,
    "amber": SPLASH_AMBER,
    "burnt": SPLASH_BURNT,
    "copper": SPLASH_COPPER,
    "tagline": SPLASH_TAGLINE,
}

assert len(_PRIMARY_ART) == len(_PRIMARY_COLORS), "PRIMARY art/color mismatch"
assert len(_FALLBACK_ART) == len(_FALLBACK_COLORS), "FALLBACK art/color mismatch"


def _render_splash_art(art_lines: list[str], color_roles: list[str | None]) -> str:
    """Render splash art lines with ANSI coloring applied."""
    out_lines: list[str] = []
    for raw, role in zip(art_lines, color_roles):
        if role is None:
            out_lines.append(raw)
        else:
            rgb = _SPLASH_ROLE_RGB.get(role)
            if rgb is None:
                out_lines.append(raw)
            else:
                out_lines.append(raw[0] + _c(*rgb) + raw[1:-1] + _RESET + raw[-1])
    return "\n".join(out_lines)


def render_splash_primary() -> str:
    """Render the PRIMARY vault splash (Unicode box-drawing)."""
    return _render_splash_art(_PRIMARY_ART, _PRIMARY_COLORS)


def render_splash_fallback() -> str:
    """Render the FALLBACK vault splash (pure ASCII)."""
    return _render_splash_art(_FALLBACK_ART, _FALLBACK_COLORS)


def render_splash() -> str:
    """Render the vault splash, auto-selecting PRIMARY or FALLBACK."""
    # Auto-detect: use FALLBACK if stdout is not a TTY or NO_COLOR is set
    if not _FORCE_COLOR or not _SUPPORTS_256:
        return render_splash_fallback()
    return render_splash_primary()


# ── Legacy aliases for backward compat ─────────────────────────────────────────
GRILLE = render_splash_primary()
CYBER_LOCK = ""
VAULT_DOOR = ""
SPLASH = render_splash()


# ── CYBER LOCK (legacy stub — kept for compat, returns empty) ───────────────────
def get_cyber_lock() -> str:
    """Legacy stub. Returns empty string."""
    return ""


# ── STATUS BANNERS ───────────────────────────────────────────────────────────

# ── MINi STATUS BANNERS ─────────────────────────────────────────────────────
# Inline feedback for command results. Compact, color-coded.

def banner_added(service: str) -> str:
    return f"""
{c('  ╔═══════════════════════════════════════╗', CYAN)}
{c('  ║  ', CYAN)}{cb('+', GREEN)}{c('  A D D E D', CYAN)}{c('                          ║', CYAN)}
{c('  ║       ', CYAN)}{c(service, GOLD)}{c('                      ║', CYAN)}
{c('  ╚═══════════════════════════════════════╝', CYAN)}
"""

def banner_verified(service: str, status: str = "OK") -> str:
    col = GREEN if status == "OK" else RED
    return f"""
{c('  ╔═══════════════════════════════════════╗', col)}
{c('  ║  ', col)}{cb('✓', GREEN)}{c('  V E R I F I E D', col)}{c('                      ║', col)}
{c('  ║       ', col)}{c(service, GOLD)}{c(' — ', col)}{c(status, col)}{c('              ║', col)}
{c('  ╚═══════════════════════════════════════╝', col)}
"""

def banner_rotated(service: str) -> str:
    return f"""
{c('  ┌───────────────────────────────────────┐', AMBER)}
{c('  │  ', AMBER)}{cb('↻', AMBER)}{c('  R O T A T E D', AMBER)}{c('                        │', AMBER)}
{c('  │       ', AMBER)}{c(service, GOLD)}{c('                  │', AMBER)}
{c('  └───────────────────────────────────────┘', AMBER)}
"""

def banner_denied(reason: str) -> str:
    return f"""
{c('  ╔═══════════════════════════════════════╗', RED)}
{c('  ║  ', RED)}{cb('✕', RED)}{c('  A C C E S S   D E N I E D', RED)}{c('             ║', RED)}
{c('  ║       ', RED)}{c(reason, RED)}{c('              ║', RED)}
{c('  ╚═══════════════════════════════════════╝', RED)}
"""

def banner_scanned(count: int) -> str:
    return f"""
{c('  ┌───────────────────────────────────────────┐', TEAL)}
{c('  │  ', TEAL)}{cb('◇', TEAL)}{c('  S C A N   C O M P L E T E', TEAL)}{c('              │', TEAL)}
{c('  │       ', TEAL)}{c(f'{count} secret(s) scanned', SILVER)}{c('          │', TEAL)}
{c('  └───────────────────────────────────────────┘', TEAL)}
"""

def banner_backup(path: str, count: int) -> str:
    return f"""
{c('  ╔═══════════════════════════════════════╗', SILVER)}
{c('  ║  ', SILVER)}{cb('⎙', SILVER)}{c('  B A C K U P   C R E A T E D', SILVER)}{c('          ║', SILVER)}
{c('  ║       ', SILVER)}{c(f'{count} credential(s) → {path}', DIM)}{c('  ║', SILVER)}
{c('  ╚═══════════════════════════════════════╝', SILVER)}
"""

def banner_restored(count: int) -> str:
    return f"""
{c('  ╔═══════════════════════════════════════╗', GREEN)}
{c('  ║  ', GREEN)}{cb('↻', GREEN)}{c('  R E S T O R E D', GREEN)}{c('                        ║', GREEN)}
{c('  ║       ', GREEN)}{c(f'{count} credential(s) restored', SILVER)}{c('      ║', GREEN)}
{c('  ╚═══════════════════════════════════════╝', GREEN)}
"""

def banner_deleted(service: str) -> str:
    return f"""
{c('  ┌───────────────────────────────────────┐', RED)}
{c('  │  ', RED)}{cb('✕', RED)}{c('  D E L E T E D', RED)}{c('                          │', RED)}
{c('  │       ', RED)}{c(service, DIM)}{c('                  │', RED)}
{c('  └───────────────────────────────────────┘', RED)}
"""

def banner_imported(count: int) -> str:
    return f"""
{c('  ╔═══════════════════════════════════════╗', CYAN)}
{c('  ║  ', CYAN)}{cb('⇑', CYAN)}{c('  I M P O R T E D', CYAN)}{c('                         ║', CYAN)}
{c('  ║       ', CYAN)}{c(f'{count} credential(s) imported', SILVER)}{c('     ║', CYAN)}
{c('  ╚═══════════════════════════════════════╝', CYAN)}
"""

def banner_health(healthy: bool) -> str:
    col = GREEN if healthy else AMBER
    status_text = "ALL HEALTHY" if healthy else "WARNINGS FOUND"
    icon = "✓" if healthy else "!"
    return f"""
{c('  ╔═══════════════════════════════════════╗', col)}
{c('  ║  ', col)}{cb(icon, col)}{c('  H E A L T H   R E P O R T', col)}{c('              ║', col)}
{c('  ║       ', col)}{c(status_text, col)}{c('                         ║', col)}
{c('  ╚═══════════════════════════════════════╝', col)}
"""


def render_health_report_markdown(report) -> str:
    """Render a HealthReport as a Markdown string (no secrets)."""
    lines = [
        "# Hermes Vault Health",
        f"Generated: {report.generated_at}",
        f"Version: {report.version}",
        "",
        f"**Status**: {'All Healthy' if report.healthy else 'Warnings Found'}",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total credentials | {report.total_credentials} |",
        f"| Healthy | {report.healthy_count} |",
        f"| Stale | {report.stale_count} |",
        f"| Invalid | {report.invalid_count} |",
        f"| Expired | {report.expired_count} |",
        f"| Expiring | {report.expiring_count} |",
        f"| Never verified | {report.never_verified_count} |",
    ]
    if report.days_since_last_backup is not None:
        lines.append(f"| Days since last backup | {report.days_since_last_backup} |")
    else:
        lines.append("| Days since last backup | never |")
    lines.append("")
    lines.append(f"Stale threshold: {report.stale_threshold_days}d  "
                  f"Expiring threshold: {report.expiring_threshold_days}d  "
                  f"Backup threshold: {report.backup_threshold_days}d")
    lines.append("")

    if report.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Level | Kind | Service | Alias | Detail |")
        lines.append("|-------|------|---------|-------|--------|")
        for f in report.findings:
            lines.append(
                f"| {f.level} | {f.kind} | {f.service} | {f.alias} | {f.detail} |"
            )
    else:
        lines.append("No findings.")
    lines.append("")
    return "\n".join(lines)
