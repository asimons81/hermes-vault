"""Interactive setup wizard for Hermes Vault.

Guides a new operator through first-time vault initialization.
"""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel



console = Console()


def run_setup_wizard() -> int:
    """Walk through first-time vault setup interactively.
    Returns 0 on success, 1 on abort.
    """
    console.print(Panel.fit(
        "[bold]Hermes Vault Setup[/bold]\n"
        "This wizard will help you create your first encrypted vault.",
        border_style="blue",
    ))

    # Step 1: Vault location
    default_home = os.environ.get("HERMES_VAULT_HOME",
                                    os.path.expanduser("~/.hermes/hermes-vault-data"))
    console.print("\n[bold]Step 1: Vault Location[/bold]")
    console.print(f"Default: {default_home}")
    vault_home = typer.prompt("Vault directory (press Enter for default)",
                               default=default_home, show_default=False)
    vault_path = Path(vault_home).expanduser()
    console.print(f"[green]Vault will be created at: {vault_path}[/green]")

    # Step 2: Passphrase
    console.print("\n[bold]Step 2: Vault Passphrase[/bold]")
    console.print("Choose a strong passphrase. You'll need this every time you access the vault.")
    passphrase = typer.prompt("Passphrase", hide_input=True, confirmation_prompt=True)
    if not passphrase:
        console.print("[red]Passphrase cannot be empty. Aborting.[/red]")
        return 1

    # Step 3: Import from .env
    console.print("\n[bold]Step 3: Import Secrets[/bold]")
    env_candidates = [
        Path.home() / ".hermes" / ".env",
        Path.home() / ".env",
        Path.home() / ".config" / "hermes" / ".env",
    ]
    env_paths = [p for p in env_candidates if p.exists()]
    if env_paths:
        console.print("Found existing .env files:")
        for i, p in enumerate(env_paths, 1):
            console.print(f"  {i}. {p}")
        import_choice = typer.prompt("Import one of these? (number or 'n' to skip)",
                                      default="n", show_default=False)
        if import_choice.isdigit() and 1 <= int(import_choice) <= len(env_paths):
            chosen = env_paths[int(import_choice) - 1]
            console.print(f"[yellow]Run: hermes-vault import --from-env {chosen}[/yellow]")
            console.print("[yellow]Run this after setup completes.[/yellow]")
    else:
        console.print("No .env files detected. Add credentials with:")
        console.print("[yellow]  hermes-vault add <service> --secret <value>[/yellow]")

    # Step 4: Bootstrap policy
    console.print("\n[bold]Step 4: Bootstrap Policy[/bold]")
    policy_path = vault_path / "policy.yaml"
    if policy_path.exists():
        console.print(f"[yellow]Policy already exists at {policy_path}[/yellow]")
    else:
        console.print("Run: [yellow]hermes-vault bootstrap[/yellow]")
        console.print("This creates a default policy with deny-by-default rules.")

    # Step 5: Schedule verification
    console.print("\n[bold]Step 5: Schedule Verification[/bold]")
    console.print("Automated verification keeps your vault healthy. Default: daily at midnight.")
    cron_line = "0 0 * * * hermes-vault verify --all --format json --report ~/vault-last-verify.json"
    console.print(f"[yellow]  {cron_line}[/yellow]")
    console.print("Add this to your crontab with: [yellow]crontab -e[/yellow]")
    console.print("Or generate a systemd unit: [yellow]hermes-vault schedule-verify --print-unit[/yellow]")

    # Step 6: Enable Secret Source / MCP
    console.print("\n[bold]Step 6: Enable Integrations[/bold]")
    console.print("Hermes Vault integrates with Hermes Agent via Secret Source and MCP.")
    console.print("See: [yellow]hermes-vault secret-source --help[/yellow]")
    console.print("     [yellow]hermes-vault mcp --help[/yellow]")

    # Done
    console.print("\n[bold green]Setup Complete![/bold green]")
    console.print(f"Vault location: {vault_path}")
    console.print("\nNext steps:")
    console.print("  1. Import credentials: [yellow]hermes-vault import --from-env <path>[/yellow]")
    console.print("  2. Check health: [yellow]hermes-vault health[/yellow]")
    console.print("  3. List credentials: [yellow]hermes-vault list[/yellow]")
    console.print("  4. Start dashboard: [yellow]hermes-vault dashboard[/yellow]")
    console.print("\n[dim]Run `hermes-vault --help` to see all commands.[/dim]")

    return 0
