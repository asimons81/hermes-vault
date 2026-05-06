from __future__ import annotations

import json
import os
import sys
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
import typer
import typer.main as typer_main
from rich.console import Console
from rich.table import Table

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.config import get_settings
from hermes_vault.crypto import MissingPassphraseError, resolve_passphrase
from hermes_vault.detectors import detect_matches, guess_from_env_name
from hermes_vault.diff import diff_backups
from hermes_vault.health import run_health
from hermes_vault.models import CredentialStatus
from hermes_vault.mutations import VaultMutations, OPERATOR_AGENT_ID
from hermes_vault.policy import PolicyEngine
from hermes_vault.scanner import Scanner
from hermes_vault.service_ids import is_canonical, normalize
from hermes_vault.skillgen import SkillGenerator
from hermes_vault.update import UpdateError, UpdatePlan, perform_update, resolve_update_plan
from hermes_vault.verifier import Verifier
from hermes_vault.vault import AmbiguousTargetError, Vault

# ── Banner helpers ──────────────────────────────────────────────────────────────

def _show_banner() -> None:
    """Write the splash to stdout. Swallows all exceptions."""
    from hermes_vault.ui import render_splash
    try:
        sys.stdout.write(render_splash() + "\n")
        sys.stdout.flush()
    except Exception:
        pass


def _should_show_banner() -> bool:
    """Return True if the banner should be displayed.

    Suppressed when:
    - HERMES_VAULT_NO_BANNER=1 env var is set, OR
    - stdout is not a TTY (scripted / non-interactive use)
    """
    if os.environ.get("HERMES_VAULT_NO_BANNER", "0") == "1":
        return False
    return sys.stdout.isatty()


def _targets_root_command(argv: list[str]) -> bool:
    """Return True when argv does not target a subcommand."""
    return not any(not arg.startswith("-") for arg in argv)


# ── Typer app ────────────────────────────────────────────────────────────────────
_typer_app = typer.Typer(
    help="Hermes-native local-first credential vault, scanner, and broker.",
)
broker_app = typer.Typer(help="Broker operations.")
_typer_app.add_typer(broker_app, name="broker")
console = Console()


def _print_update_plan(plan: UpdatePlan) -> None:
    table = Table(title="Hermes Vault Update")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Current version", plan.current_version)
    table.add_row("Latest version", plan.latest_release.version)
    table.add_row("Release source", plan.latest_release.url)
    table.add_row("Install method", plan.installation.method.value)
    table.add_row("Detected state", plan.installation.detail)
    table.add_row(
        "Auto-update supported",
        "yes" if plan.installation.auto_update_supported else "no",
    )
    if plan.needs_update:
        action = (
            "Run " + " ".join(plan.installation.auto_update_command)
            if plan.installation.auto_update_supported and plan.installation.auto_update_command
            else plan.installation.manual_command
        )
    else:
        action = "Already up to date. No changes required."
    table.add_row("Planned action", action)
    console.print(table)


# ── HermesGroup — Click Group with add_typer + banner invoke ───────────────────────
# HermesGroup IS the app. Click Group gives add_typer.
# Typer gives beautiful @decorator commands. Click Group gives invoke() pre-dispatch.
class HermesGroup(click.Group, typer.Typer):
    def __init__(self, *args, **kwargs):
        # params is a Click concept — pass only to Click Group, not Typer
        _params = kwargs.pop("params", None)
        click.Group.__init__(self, *args, params=_params, **kwargs)
        typer.Typer.__init__(self, *args, **kwargs)


    def invoke(self, ctx: click.Context) -> None:
        """Fire the banner before every command dispatch. Also resolve Typer groups."""
        self._resolve_typer_groups(ctx)
        # Skip banner for Click's internal recursive main() call (--help / --version):
        # in that call ctx.obj is already set (inherited from parent context).
        if (
            not ctx.params.get("no_banner", False)
            and _should_show_banner()
            and not getattr(ctx, "obj", None)
        ):
            _show_banner()
        super().invoke(ctx)

    def _resolve_typer_groups(self, ctx: click.Context) -> None:
        """Resolve Typer sub-groups into Click commands on first use."""
        if hasattr(self, "_typer_groups_resolved"):
            return
        # Build TyperGroup objects for each registered sub-Typer and add them
        # so Click's list_commands / get_command can find them.
        if hasattr(self, "registered_groups"):
            for info in list(self.registered_groups):
                typer_instance = info.typer_instance
                group_name = info.name or ""
                try:
                    typer_group = typer_main.get_command(typer_instance)
                    self.commands[group_name] = typer_group
                except Exception:
                    pass  # Sub-Typer with no commands — skip
        self._typer_groups_resolved = True

    # ── get_command — bridge Click and Typer command namespaces ─────────────
    # Cache the TyperGroup built from _typer_app so we don't rebuild each call.
    _typer_group_cache: click.Command | None = None

    def list_commands(self, ctx: click.Context) -> list[str]:
        """Include Typer-registered commands when Click renders root help."""
        commands = list(click.Group.list_commands(self, ctx))
        if HermesGroup._typer_group_cache is None:
            HermesGroup._typer_group_cache = typer_main.get_command(_typer_app)
        for name in HermesGroup._typer_group_cache.list_commands(ctx):
            if name not in commands:
                commands.append(name)
        return commands

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        """First check Click-registered commands, then delegate to the TyperGroup."""
        # 1. Click-native commands (added via add_command)
        cmd = click.Group.get_command(self, ctx, cmd_name)
        if cmd is not None:
            return cmd
        # 2. Typer commands — lazily build and cache the TyperGroup
        if HermesGroup._typer_group_cache is None:
            HermesGroup._typer_group_cache = typer_main.get_command(_typer_app)
        return HermesGroup._typer_group_cache.get_command(ctx, cmd_name)


_hermes_group = HermesGroup(
    params=[
        click.Option(
            ["--no-banner"],
            is_flag=True,
            is_eager=True,
            help="Suppress the vault splash banner.",
        ),
    ],
    help="Hermes-native local-first credential vault, scanner, and broker.",
)
_hermes_group.add_typer(_typer_app)


def build_services(prompt: bool = False) -> tuple[Vault, PolicyEngine, Broker, VaultMutations]:
    settings = get_settings()
    policy = PolicyEngine.from_yaml(settings.effective_policy_path)
    policy.write_default(settings.effective_policy_path)
    passphrase = resolve_passphrase(prompt=prompt)
    vault = Vault(settings.db_path, settings.salt_path, passphrase)
    audit = AuditLogger(settings.db_path)
    verifier = Verifier()
    broker = Broker(vault=vault, policy=policy, verifier=verifier, audit=audit)
    mutations = VaultMutations(vault=vault, policy=policy, audit=audit)
    return vault, policy, broker, mutations


def _handle_mutation_error(result, success_msg: str | None = None) -> None:
    """Handle a MutationResult: print error and exit on deny, otherwise print success."""
    if not result.allowed:
        console.print(f"[red]Denied: {result.reason}[/red]")
        raise typer.Exit(code=1)
    if success_msg:
        console.print(success_msg)


# ── Selector help text ───────────────────────────────────────────────────────────
SELECTOR_HELP = (
    "Target a credential by:\n"
    "  • credential ID (UUID) — exact match\n"
    "  • service + --alias — exact match\n"
    "  • service only — allowed only when exactly one credential exists for that service\n"
    "Service names are normalized to canonical IDs (e.g. 'open_ai' → 'openai')."
)


@_typer_app.command()
def scan(
    ctx: typer.Context,
    path: list[Path] = typer.Option(None, "--path", help="Paths to scan. Defaults to managed paths from policy."),
    format: str = typer.Option("table", "--format", help="Output format: table or json."),
) -> None:
    """Scan the filesystem for plaintext secrets.

    \b
    Examples:
      hermes-vault scan --path ~/.hermes
      hermes-vault scan --path ~/.config --format json
    """
    settings = get_settings()
    policy = PolicyEngine.from_yaml(settings.effective_policy_path)
    scanner = Scanner(settings, policy=policy)
    findings = scanner.scan(paths=path or None)
    if format == "json":
        console.print_json(data=json.dumps([item.model_dump(mode="json") for item in findings]))
        return
    table = Table(title="Hermes Vault Scan Findings")
    table.add_column("Severity")
    table.add_column("Kind")
    table.add_column("Service")
    table.add_column("Path")
    table.add_column("Recommendation")
    for finding in findings:
        table.add_row(
            finding.severity.value,
            finding.kind,
            finding.service or "-",
            finding.path,
            finding.recommendation,
        )
    console.print(table)


@_typer_app.command("import")
def import_credentials(
    ctx: typer.Context,
    from_env: Path | None = typer.Option(None, "--from-env", help="Import from a .env file (KEY=value format)."),
    from_file: Path | None = typer.Option(None, "--from-file", help="Import from a JSON file (auto-detects secrets)."),
    redact_source: bool = typer.Option(False, "--redact-source", help="Comment out imported lines in the source file after successful import."),
) -> None:
    """Import credentials from env files or JSON.

    Service names are normalized to canonical IDs automatically.

    \b
    Examples:
      hermes-vault import --from-env ~/.hermes/.env
      hermes-vault import --from-file secrets.json --redact-source
    """
    if not from_env and not from_file:
        console.print("[red]Provide --from-env or --from-file[/red]")
        raise typer.Exit(code=1)
    vault, _, _, mutations = build_services(prompt=True)
    imported_names: list[str] = []
    source = from_env or from_file
    assert source is not None
    original_content = source.read_text(encoding="utf-8", errors="ignore")
    lines = original_content.splitlines()
    imported_lines: set[int] = set()

    if from_env:
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            guessed = guess_from_env_name(name.strip())
            if not guessed:
                continue
            service, credential_type = guessed
            result = mutations.add_credential(
                agent_id=OPERATOR_AGENT_ID,
                service=service,
                secret=value.strip().strip("'\""),
                credential_type=credential_type,
                alias=name.strip().lower(),
                imported_from=str(source),
            )
            if not result.allowed:
                console.print(f"[red]Denied importing '{name.strip()}': {result.reason}[/red]")
                raise typer.Exit(code=1)
            imported_names.append(name.strip())
            imported_lines.add(i)
    else:
        parsed = json.loads(original_content)
        for key, value in parsed.items():
            if not isinstance(value, str):
                continue
            matches = detect_matches(value)
            if not matches:
                continue
            detector, secret = matches[0]
            result = mutations.add_credential(
                agent_id=OPERATOR_AGENT_ID,
                service=detector.service,
                secret=secret,
                credential_type=detector.credential_type,
                alias=key.lower(),
                imported_from=str(source),
            )
            if not result.allowed:
                console.print(f"[red]Denied importing '{key}': {result.reason}[/red]")
                raise typer.Exit(code=1)
            imported_names.append(key)

    console.print(f"[green]Imported {len(imported_names)} credential(s).[/green]")
    if redact_source and imported_lines and from_env:
        redacted_lines = []
        for i, line in enumerate(lines):
            if i in imported_lines:
                redacted_lines.append(f"# REDACTED by hermes-vault import: {line}")
            else:
                redacted_lines.append(line)
        source.write_text("\n".join(redacted_lines) + "\n", encoding="utf-8")
        source.chmod(0o600)
        console.print(f"[green]Source file redacted: {source}[/green] ({len(imported_lines)} line(s) commented out)")
    elif redact_source and from_file:
        console.print("[yellow]--redact-source only applies to --from-env files.[/yellow]")
    else:
        console.print("Review plaintext source removal separately.")


@_typer_app.command()
def add(
    ctx: typer.Context,
    service: str = typer.Argument(help="Service name (normalized to canonical ID, e.g. 'open_ai' → 'openai')."),
    alias: str = typer.Option("default", "--alias", help="Alias for this credential. Required when adding a second credential for the same service."),
    credential_type: str = typer.Option("api_key", "--credential-type", help="Credential type (api_key, personal_access_token, oauth_access_token, etc.)."),
    secret: str | None = typer.Option(None, "--secret", help="The secret value. Prompts interactively if omitted."),
) -> None:
    """Add a credential to the vault.

    Service names are normalized to canonical IDs automatically.
    Use --alias to distinguish multiple credentials for the same service.

    \b
    Examples:
      hermes-vault add openai --secret sk-...
      hermes-vault add github --alias work --credential-type personal_access_token
      hermes-vault add open_ai          # normalizes to 'openai'
    """
    vault, _, _, mutations = build_services(prompt=True)
    canonical = normalize(service)
    secret_value = secret or typer.prompt("Secret", hide_input=True)
    result = mutations.add_credential(
        agent_id=OPERATOR_AGENT_ID,
        service=canonical,
        secret=secret_value,
        credential_type=credential_type,
        alias=alias,
    )
    if not result.allowed:
        console.print(f"[red]Denied: {result.reason}[/red]")
        raise typer.Exit(code=1)
    assert result.record is not None
    console.print(
        f"Stored credential [cyan]{result.record.id}[/cyan] "
        f"for service [bold]{result.record.service}[/bold] alias '{result.record.alias}'."
    )


@_typer_app.command(name="list")
def list_credentials_cmd(ctx: typer.Context) -> None:
    """List all credentials in the vault.

    Shows canonical service IDs, aliases, and credential status.
    """
    vault, _, _, _ = build_services(prompt=True)
    records = vault.list_credentials()
    table = Table(title="Vault Credentials")
    table.add_column("ID")
    table.add_column("Service")
    table.add_column("Alias")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Last Verified")
    for record in records:
        table.add_row(
            record.id,
            record.service,
            record.alias,
            record.credential_type,
            record.status.value,
            record.last_verified_at.isoformat() if record.last_verified_at else "-",
        )
    console.print(table)


@_typer_app.command("show-metadata")
def show_metadata(
    ctx: typer.Context,
    service_or_id: str = typer.Argument(help=SELECTOR_HELP),
    alias: str | None = typer.Option(None, "--alias", help="Target a specific alias when multiple credentials exist for a service."),
) -> None:
    """Show credential metadata (no raw secret).

    \b
    Examples:
      hermes-vault show-metadata openai
      hermes-vault show-metadata github --alias work
      hermes-vault show-metadata a1b2c3d4-...   # by credential ID
    """
    vault, _, _, mutations = build_services(prompt=True)
    try:
        result = mutations.get_metadata(
            agent_id=OPERATOR_AGENT_ID,
            service_or_id=service_or_id,
            alias=alias,
        )
    except AmbiguousTargetError as exc:
        console.print(f"[red]Ambiguous: {exc}[/red]")
        console.print("[yellow]Use --alias or provide the credential ID.[/yellow]")
        raise typer.Exit(code=1)
    except KeyError as exc:
        console.print(f"[red]Not found: {exc}[/red]")
        raise typer.Exit(code=1)
    _handle_mutation_error(result)
    assert result.record is not None
    console.print_json(data=result.record.model_dump_json(exclude={"encrypted_payload"}))


@_typer_app.command()
def rotate(
    ctx: typer.Context,
    service_or_id: str = typer.Argument(help=SELECTOR_HELP),
    alias: str | None = typer.Option(None, "--alias", help="Target a specific alias when multiple credentials exist for a service."),
    secret: str | None = typer.Option(None, "--secret", help="The new secret value. Prompts interactively if omitted."),
) -> None:
    """Rotate a credential's secret.

    \b
    Examples:
      hermes-vault rotate openai --secret sk-new-...
      hermes-vault rotate github --alias work --secret ghp_new-...
      hermes-vault rotate a1b2c3d4-... --secret sk-new-...
    """
    vault, _, _, mutations = build_services(prompt=True)
    secret_value = secret or typer.prompt("New secret", hide_input=True)
    try:
        result = mutations.rotate_credential(
            agent_id=OPERATOR_AGENT_ID,
            service_or_id=service_or_id,
            new_secret=secret_value,
            alias=alias,
        )
    except AmbiguousTargetError as exc:
        console.print(f"[red]Ambiguous: {exc}[/red]")
        console.print("[yellow]Use --alias or provide the credential ID.[/yellow]")
        raise typer.Exit(code=1)
    except KeyError as exc:
        console.print(f"[red]Not found: {exc}[/red]")
        raise typer.Exit(code=1)
    _handle_mutation_error(result)
    assert result.record is not None
    console.print(
        f"Rotated credential [cyan]{result.record.id}[/cyan] "
        f"for service [bold]{result.record.service}[/bold] alias '{result.record.alias}'."
    )


@_typer_app.command()
def delete(
    ctx: typer.Context,
    service_or_id: str = typer.Argument(help=SELECTOR_HELP),
    alias: str | None = typer.Option(None, "--alias", help="Target a specific alias when multiple credentials exist for a service."),
    yes: bool = typer.Option(False, "--yes", help="Confirm deletion without prompting."),
) -> None:
    """Delete a credential from the vault.

    Requires --yes to confirm. Destructive and irreversible.

    \b
    Examples:
      hermes-vault delete openai --yes
      hermes-vault delete github --alias work --yes
      hermes-vault delete a1b2c3d4-... --yes
    """
    if not yes:
        console.print("[red]Deletion requires --yes[/red]")
        raise typer.Exit(code=1)
    vault, _, _, mutations = build_services(prompt=True)
    try:
        result = mutations.delete_credential(
            agent_id=OPERATOR_AGENT_ID,
            service_or_id=service_or_id,
            alias=alias,
        )
    except AmbiguousTargetError as exc:
        console.print(f"[red]Ambiguous: {exc}[/red]")
        console.print("[yellow]Use --alias or provide the credential ID.[/yellow]")
        raise typer.Exit(code=1)
    except KeyError as exc:
        console.print(f"[red]Not found: {exc}[/red]")
        raise typer.Exit(code=1)
    _handle_mutation_error(
        result,
        success_msg=f"[green]Deleted credential [cyan]{result.metadata.get('credential_id', service_or_id)}[/cyan].[/green]",
    )


@_typer_app.command()
def audit(
    ctx: typer.Context,
    agent: str | None = typer.Option(None, "--agent", help="Filter by agent ID."),
    service: str | None = typer.Option(None, "--service", help="Filter by service name."),
    action: str | None = typer.Option(None, "--action", help="Filter by action."),
    decision: str | None = typer.Option(None, "--decision", help="Filter by decision (allow|deny)."),
    since: str | None = typer.Option(None, "--since", help="Filter since timestamp. Use '7d' for 7 days ago, or 'YYYY-MM-DD' for a specific date."),
    until: str | None = typer.Option(None, "--until", help="Filter until timestamp. Use 'YYYY-MM-DD' for a specific date."),
    format: str = typer.Option("table", "--format", help="Output format: table or json."),
    limit: int = typer.Option(100, "--limit", help="Maximum number of entries to return."),
) -> None:
    """Query the audit log.

    \b
    Examples:
      hermes-vault audit
      hermes-vault audit --agent hermes --limit 50
      hermes-vault audit --since 7d --format json
      hermes-vault audit --decision deny --since 2026-03-01
    """
    def parse_since(value: str | None) -> datetime | None:
        if value is None:
            return None
        m = re.match(r"^(\d+)d$", value)
        if m:
            return datetime.now(timezone.utc) - timedelta(days=int(m.group(1)))
        try:
            parsed = datetime.strptime(value, "%Y-%m-%d")
            if parsed.strftime("%Y-%m-%d") != value:
                raise ValueError()
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def parse_until(value: str | None) -> datetime | None:
        if value is None:
            return None
        try:
            parsed = datetime.strptime(value, "%Y-%m-%d")
            if parsed.strftime("%Y-%m-%d") != value:
                raise ValueError()
            return parsed.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
        except ValueError:
            return None

    if limit < 1:
        console.print("[red]--limit must be a positive integer[/red]")
        raise typer.Exit(code=1)

    if format not in ("table", "json"):
        console.print("[red]--format must be 'table' or 'json'[/red]")
        raise typer.Exit(code=1)

    since_dt = parse_since(since)
    until_dt = parse_until(until)

    if since is not None and since_dt is None:
        console.print(f"[red]Invalid --since value: {since!r} (use '7d' or 'YYYY-MM-DD')[/red]")
        raise typer.Exit(code=1)
    if until is not None and until_dt is None:
        console.print(f"[red]Invalid --until value: {until!r} (use 'YYYY-MM-DD')[/red]")
        raise typer.Exit(code=1)

    if decision is not None and decision not in ("allow", "deny"):
        console.print("[red]--decision must be 'allow' or 'deny'[/red]")
        raise typer.Exit(code=1)

    # Build services without prompt (audit is read-only, no passphrase needed)
    settings = get_settings()
    audit = AuditLogger(settings.db_path)
    results = audit.list_recent(
        limit=limit,
        agent_id=agent,
        service=service,
        action=action,
        decision=decision,
        since=since_dt,
        until=until_dt,
    )

    if not results:
        raise typer.Exit(code=0)

    if format == "json":
        console.print_json(data=results)
        return

    table = Table(title="Audit Log")
    table.add_column("TIMESTAMP")
    table.add_column("AGENT")
    table.add_column("SERVICE")
    table.add_column("ACTION")
    table.add_column("DECISION")
    table.add_column("REASON")
    table.add_column("TTL")
    table.add_column("VERIFICATION")
    for row in results:
        table.add_row(
            row.get("timestamp", "-"),
            row.get("agent_id", "-"),
            row.get("service", "-"),
            row.get("action", "-"),
            row.get("decision", "-"),
            row.get("reason", "-"),
            str(row.get("ttl_seconds", "-")),
            row.get("verification_result", "-"),
        )
    console.print(table)


@_typer_app.command("status")
def status(
    ctx: typer.Context,
    target: str | None = typer.Argument(None, help="Optional credential target (service name or credential ID)."),
    alias: str | None = typer.Option(None, "--alias", help="Target a specific alias when multiple credentials exist for a service."),
    stale: str | None = typer.Option(None, "--stale", help="Show credentials not verified in Nd (e.g. 7d, 30d)."),
    invalid: bool = typer.Option(False, "--invalid", help="Show credentials with invalid or expired status."),
    expiring: str | None = typer.Option(None, "--expiring", help="Show credentials expiring within Nd (e.g. 30d, 90d)."),
    format: str = typer.Option("table", "--format", help="Output format: table or json."),
) -> None:
    """Show credential status and health.

    Displays the status, verification timestamps, and expiry information
    for vault credentials. Supports filtering by staleness, invalid/expired
    status, and upcoming expiry.

    \b
    Examples:
      hermes-vault status
      hermes-vault status --stale 7d
      hermes-vault status --invalid
      hermes-vault status --expiring 30d
      hermes-vault status openai --alias primary --format json
    """
    # ── Parse stale/expiring thresholds ───────────────────────────────────────
    stale_days: int | None = None
    if stale is not None:
        m = re.match(r"^(\d+)d$", stale)
        if not m:
            console.print(f"[red]Invalid --stale value: {stale!r} (use 'Nd' format, e.g. '7d', '30d')[/red]")
            raise typer.Exit(code=1)
        stale_days = int(m.group(1))

    expiring_days: int | None = None
    if expiring is not None:
        m = re.match(r"^(\d+)d$", expiring)
        if not m:
            console.print(f"[red]Invalid --expiring value: {expiring!r} (use 'Nd' format, e.g. '30d', '90d')[/red]")
            raise typer.Exit(code=1)
        expiring_days = int(m.group(1))

    if format not in ("table", "json"):
        console.print("[red]--format must be 'table' or 'json'[/red]")
        raise typer.Exit(code=1)

    # ── Build services ─────────────────────────────────────────────────────────
    vault, _, _, _ = build_services(prompt=True)

    # ── Resolve target ─────────────────────────────────────────────────────────
    if target is not None:
        try:
            records = [vault.resolve_credential(target, alias=alias)]
        except AmbiguousTargetError as exc:
            console.print(f"[red]Ambiguous: {exc}[/red]")
            console.print("[yellow]Use --alias or provide the credential ID.[/yellow]")
            raise typer.Exit(code=1)
        except KeyError:
            console.print(f"[red]Not found: {target}[/red]")
            raise typer.Exit(code=1)
    else:
        records = vault.list_credentials()

    # ── Compute staleness / expiry ─────────────────────────────────────────────
    now = datetime.now(timezone.utc)
    enriched: list[dict] = []
    for rec in records:
        last_verified = rec.last_verified_at
        expiry = rec.expiry

        # days_since_verified
        if last_verified is not None:
            delta = now - last_verified.replace(tzinfo=timezone.utc) if last_verified.tzinfo is None else now - last_verified
            days_since_verified = delta.days
        else:
            days_since_verified = None  # Never verified = always stale

        # is_stale — always computed (default 30-day threshold for display)
        stale_threshold = stale_days if stale_days is not None else 30
        is_stale = (days_since_verified is None) or (days_since_verified >= stale_threshold)

        # days_until_expiry
        if expiry is not None:
            expiry_dt = expiry.replace(tzinfo=timezone.utc) if expiry.tzinfo is None else expiry
            delta_exp = expiry_dt - now
            days_until_expiry = delta_exp.days
        else:
            days_until_expiry = None

        # is_expiring
        if expiring_days is not None:
            is_expiring = (days_until_expiry is not None) and (days_until_expiry <= expiring_days)
        else:
            is_expiring = False

        # is_invalid
        is_invalid = rec.status in (CredentialStatus.invalid, CredentialStatus.expired)

        # ── Apply filters ──────────────────────────────────────────────────────
        if stale_days is not None and not is_stale:
            continue
        if invalid and not is_invalid:
            continue
        if expiring_days is not None and not is_expiring:
            continue

        enriched.append({
            "service": rec.service,
            "alias": rec.alias,
            "credential_type": rec.credential_type,
            "status": rec.status.value,
            "last_verified_at": last_verified.isoformat() if last_verified else None,
            "expiry": expiry.isoformat() if expiry else None,
            "is_stale": is_stale,
            "is_expiring": is_expiring,
            "days_since_verified": days_since_verified,
            "days_until_expiry": days_until_expiry,
        })

    # ── Output ─────────────────────────────────────────────────────────────────
    if not enriched:
        return

    if format == "json":
        console.print_json(data=json.dumps(enriched, sort_keys=True))
        return

    table = Table(title="Credential Status")
    table.add_column("SERVICE")
    table.add_column("ALIAS")
    table.add_column("TYPE")
    table.add_column("STATUS")
    table.add_column("LAST VERIFIED")
    table.add_column("EXPIRY")
    table.add_column("STALE")
    table.add_column("ACTIONS")
    for row in enriched:
        last_verified_str = row["last_verified_at"][:19].replace("T", " ") if row["last_verified_at"] else "-"
        expiry_str = row["expiry"][:10] if row["expiry"] else "-"
        stale_str = "YES" if row["is_stale"] else "-"
        table.add_row(
            row["service"],
            row["alias"],
            row["credential_type"],
            row["status"],
            last_verified_str,
            expiry_str,
            stale_str,
            "-",
        )
    console.print(table)


@_typer_app.command("set-expiry")
def set_expiry(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Credential target (service name or credential ID)."),
    alias: str | None = typer.Option(None, "--alias", help="Target a specific alias when multiple credentials exist for a service."),
    days: int | None = typer.Option(None, "--days", help="Set expiry to N days from now (must be > 0)."),
    date: str | None = typer.Option(None, "--date", help="Set expiry to a specific date (YYYY-MM-DD, valid through end of that date)."),
) -> None:
    """Set the expiry datetime for a credential.

    Exactly one of --days or --date must be provided.
    --days N sets expiry to N days from now.
    --date YYYY-MM-DD sets expiry to 23:59:59 on that date (UTC).

    \b
    Examples:
      hermes-vault set-expiry openai --days 90
      hermes-vault set-expiry github --alias work --date 2026-12-31
      hermes-vault set-expiry a1b2c3d4-... --days 30
    """
    from hermes_vault.models import AccessLogRecord, Decision

    # Validate mutual exclusion of --days and --date
    if days is None and date is None:
        console.print("[red]--days or --date is required[/red]")
        raise typer.Exit(code=1)
    if days is not None and date is not None:
        console.print("[red]--days and --date are mutually exclusive; provide exactly one[/red]")
        raise typer.Exit(code=1)
    if days is not None and days <= 0:
        console.print("[red]--days must be a positive integer[/red]")
        raise typer.Exit(code=1)

    # Compute expiry
    if days is not None:
        expiry = datetime.now(timezone.utc) + timedelta(days=days)
    else:
        # date is not None here
        try:
            parsed = datetime.strptime(date, "%Y-%m-%d")
            if parsed.strftime("%Y-%m-%d") != date:
                raise ValueError()
            expiry = parsed.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
        except (ValueError, OverflowError):
            console.print(f"[red]Invalid --date format: {date!r} (use YYYY-MM-DD)[/red]")
            raise typer.Exit(code=1)

    vault, policy, broker, mutations = build_services(prompt=True)
    settings = get_settings()
    audit = AuditLogger(settings.db_path)

    # Resolve target to get canonical service name
    try:
        record = vault.resolve_credential(target, alias=alias)
        normalized_service = record.service
    except AmbiguousTargetError as exc:
        console.print(f"[red]Ambiguous: {exc}[/red]")
        console.print("[yellow]Use --alias or provide the credential ID.[/yellow]")
        raise typer.Exit(code=1)
    except KeyError:
        console.print(f"[red]Not found: {target}[/red]")
        raise typer.Exit(code=1)

    try:
        result = vault.set_expiry(target, expiry, alias=alias)
    except AmbiguousTargetError as exc:
        console.print(f"[red]Ambiguous: {exc}[/red]")
        console.print("[yellow]Use --alias or provide the credential ID.[/yellow]")
        raise typer.Exit(code=1)
    except KeyError as exc:
        console.print(f"[red]Not found: {exc}[/red]")
        raise typer.Exit(code=1)

    # Audit entry
    audit.record(AccessLogRecord(
        agent_id=OPERATOR_AGENT_ID,
        service=normalized_service,
        action="set_expiry",
        decision=Decision.allow,
        reason=f"expiry set to {expiry.isoformat()}",
    ))

    console.print(f"Expiry set for {normalized_service}/{result.alias} → {result.expiry.isoformat()}")


@_typer_app.command("clear-expiry")
def clear_expiry(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Credential target (service name or credential ID)."),
    alias: str | None = typer.Option(None, "--alias", help="Target a specific alias when multiple credentials exist for a service."),
) -> None:
    """Clear the expiry for a credential.

    \b
    Examples:
      hermes-vault clear-expiry openai
      hermes-vault clear-expiry github --alias work
      hermes-vault clear-expiry a1b2c3d4-...
    """
    from hermes_vault.models import AccessLogRecord, Decision

    vault, policy, broker, mutations = build_services(prompt=True)
    settings = get_settings()
    audit = AuditLogger(settings.db_path)

    # Resolve target to get canonical service name
    try:
        record = vault.resolve_credential(target, alias=alias)
        normalized_service = record.service
    except AmbiguousTargetError as exc:
        console.print(f"[red]Ambiguous: {exc}[/red]")
        console.print("[yellow]Use --alias or provide the credential ID.[/yellow]")
        raise typer.Exit(code=1)
    except KeyError:
        console.print(f"[red]Not found: {target}[/red]")
        raise typer.Exit(code=1)

    try:
        cleared = vault.clear_expiry(target, alias=alias)
    except AmbiguousTargetError as exc:
        console.print(f"[red]Ambiguous: {exc}[/red]")
        console.print("[yellow]Use --alias or provide the credential ID.[/yellow]")
        raise typer.Exit(code=1)
    except KeyError as exc:
        console.print(f"[red]Not found: {exc}[/red]")
        raise typer.Exit(code=1)

    # Audit entry
    audit.record(AccessLogRecord(
        agent_id=OPERATOR_AGENT_ID,
        service=normalized_service,
        action="clear_expiry",
        decision=Decision.allow,
        reason="expiry cleared",
    ))

    console.print(f"Expiry cleared for {normalized_service}/{record.alias}.")


@_typer_app.command()
def verify(
    ctx: typer.Context,
    target: str | None = typer.Argument(None, help=SELECTOR_HELP),
    alias: str | None = typer.Option(None, "--alias", help="Target a specific alias when multiple credentials exist for a service."),
    all: bool = typer.Option(False, "--all", help="Verify all credentials in the vault."),
    format: str = typer.Option("json", "--format", help="Output format: table or json."),
    report: Path | None = typer.Option(None, "--report", help="Write JSON report to this path."),
) -> None:
    """Verify credential(s) against provider endpoints.

    Target a single credential or use --all to verify everything.

    \b
    Examples:
      hermes-vault verify openai
      hermes-vault verify github --alias work
      hermes-vault verify a1b2c3d4-...
      hermes-vault verify --all
      hermes-vault verify --all --format table
      hermes-vault verify --all --report ~/verify.json
    """
    def _table_alias_for(result) -> str:
        metadata = getattr(result, "metadata", {})
        if isinstance(metadata, dict):
            alias_value = metadata.get("alias")
            if alias_value:
                return str(alias_value)
        return alias or "default"

    def _verification_payload(result) -> tuple[bool, str, str, str | None, str]:
        metadata = getattr(result, "metadata", {})
        verification = metadata.get("verification_result") if isinstance(metadata, dict) else None
        if isinstance(verification, dict):
            success = bool(verification.get("success", getattr(result, "allowed", False)))
            category = str(verification.get("category", "-"))
            reason = str(verification.get("reason", getattr(result, "reason", "-")))
            status_code = verification.get("status_code")
            checked_at = str(verification.get("checked_at", "-"))
            return success, category, reason, status_code, checked_at

        category_value = getattr(result, "category", "-")
        category = category_value.value if hasattr(category_value, "value") else str(category_value)
        checked_at_value = getattr(result, "checked_at", "-")
        checked_at = checked_at_value.isoformat() if hasattr(checked_at_value, "isoformat") else str(checked_at_value)
        return (
            bool(getattr(result, "success", getattr(result, "allowed", False))),
            category,
            str(getattr(result, "reason", "-")),
            getattr(result, "status_code", None),
            checked_at,
        )

    if format not in ("table", "json"):
        console.print("[red]--format must be 'table' or 'json'[/red]")
        raise typer.Exit(code=1)

    vault, _, broker, _ = build_services(prompt=True)
    if all:
        targets = [(record.service, record.alias) for record in vault.list_credentials()]
    elif target:
        # Resolve the canonical service name for the display
        normalized = normalize(target)
        targets = [(normalized, alias)]
    else:
        console.print("[red]Provide a credential target or use --all[/red]")
        console.print("[yellow]Examples:[/yellow]")
        console.print("  hermes-vault verify openai")
        console.print("  hermes-vault verify github --alias work")
        console.print("  hermes-vault verify --all")
        raise typer.Exit(code=1)
    results = []
    for svc, als in targets:
        try:
            results.append(broker.verify_credential(svc, alias=als))
        except AmbiguousTargetError as exc:
            console.print(f"[red]Ambiguous: {exc}[/red]")
            console.print("[yellow]Use --alias or provide the credential ID.[/yellow]")
            raise typer.Exit(code=1)
        except KeyError as exc:
            console.print(f"[red]Not found: {exc}[/red]")
            raise typer.Exit(code=1)

    # Determine what to print to stdout
    output_results = [r.model_dump(mode="json") for r in results]

    if format == "json":
        console.print_json(data=json.dumps(output_results))
    else:
        table = Table(title="Verification Results")
        table.add_column("SERVICE")
        table.add_column("ALIAS")
        table.add_column("RESULT")
        table.add_column("CATEGORY")
        table.add_column("REASON")
        table.add_column("STATUS CODE")
        table.add_column("CHECKED AT")
        for r in results:
            success, category, reason_text, status_code, checked_at = _verification_payload(r)
            reason = r.reason[:40] if len(r.reason) > 40 else r.reason
            if reason_text:
                reason = reason_text[:40] if len(reason_text) > 40 else reason_text
            status_code_str = str(status_code) if status_code is not None else "-"
            result_str = "✓ valid" if success else "✗ invalid"
            table.add_row(
                r.service,
                _table_alias_for(r),
                result_str,
                category,
                reason,
                status_code_str,
                checked_at,
            )
        console.print(table)

    # Write report file if requested
    if report:
        report_path = Path(report).expanduser().resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(output_results, indent=2, sort_keys=True), encoding="utf-8")
        report_path.chmod(0o600)


@_typer_app.command()
def health(
    ctx: typer.Context,
    format: str = typer.Option("markdown", "--format", help="Output format: markdown or json."),
    verify_live: bool = typer.Option(False, "--verify-live", help="Run live provider verification (not implemented yet — reserved)."),
    stale_days: int = typer.Option(30, "--stale-days", help="Flag credentials not verified within this many days."),
    expiring_days: int = typer.Option(7, "--expiring-days", help="Flag credentials expiring within this many days."),
    backup_days: int = typer.Option(30, "--backup-days", help="Warn if last backup exceeds this many days."),
) -> None:
    """Run a read-only vault health check.

    Inspects credential staleness, expiry, invalid status, and backup age.
    Does NOT call provider APIs unless --verify-live is passed.

    Exit codes:
      0 = all healthy
      1 = warnings (stale, invalid, expiring, backup overdue)
      2 = execution/config/runtime error

    Examples:
      hermes-vault health
      hermes-vault health --format json
      hermes-vault health --stale-days 7 --expiring-days 14
    """
    if format not in ("markdown", "json"):
        console.print("[red]--format must be 'markdown' or 'json'[/red]")
        raise typer.Exit(code=2)

    if stale_days < 1 or expiring_days < 1 or backup_days < 1:
        console.print("[red]Thresholds must be positive integers[/red]")
        raise typer.Exit(code=2)

    vault, _, _, _ = build_services(prompt=True)
    settings = get_settings()
    audit = AuditLogger(settings.db_path)

    report = run_health(
        vault,
        audit=audit,
        verify_live=verify_live,
        stale_days=stale_days,
        expiring_days=expiring_days,
        backup_days=backup_days,
    )

    from hermes_vault.ui import banner_health, render_health_report_markdown
    console.print(banner_health(report.healthy))

    if format == "json":
        console.print_json(data=json.dumps(report.as_dict(exclude_none=False), sort_keys=True))
    else:
        console.print(render_health_report_markdown(report))

    if report.healthy:
        raise typer.Exit(code=0)
    else:
        raise typer.Exit(code=1)


@broker_app.command("get")
def broker_get(
    ctx: typer.Context,
    service: str = typer.Argument(help="Service name (normalized to canonical ID)."),
    agent: str = typer.Option(..., "--agent", help="Agent ID requesting the credential."),
    purpose: str = typer.Option("task", "--purpose", help="Purpose of the credential access."),
) -> None:
    """Get a raw credential secret for an agent.

    \b
    Examples:
      hermes-vault broker get openai --agent hermes --purpose "api-calls"
      hermes-vault broker get github --agent deploy-bot
    """
    _, _, broker, _ = build_services(prompt=True)
    canonical = normalize(service)
    decision = broker.get_credential(service=canonical, purpose=purpose, agent_id=agent)
    if not decision.allowed:
        console.print_json(data=decision.model_dump_json())
        raise typer.Exit(code=1)
    console.print_json(data=json.dumps(decision.model_dump(mode="json")))


@broker_app.command("env")
def broker_env(
    ctx: typer.Context,
    service: str = typer.Argument(help="Service name (normalized to canonical ID)."),
    agent: str = typer.Option(..., "--agent", help="Agent ID requesting ephemeral env."),
    ttl: int = typer.Option(900, "--ttl", help="Time-to-live in seconds for the ephemeral env."),
) -> None:
    """Materialize ephemeral environment variables for an agent.

    \b
    Examples:
      hermes-vault broker env openai --agent hermes
      hermes-vault broker env github --agent deploy-bot --ttl 300
    """
    _, _, broker, _ = build_services(prompt=True)
    canonical = normalize(service)
    decision = broker.get_ephemeral_env(service=canonical, agent_id=agent, ttl=ttl)
    if not decision.allowed:
        console.print_json(data=decision.model_dump_json())
        raise typer.Exit(code=1)
    console.print_json(data=json.dumps(decision.model_dump(mode="json")))


@broker_app.command("list")
def broker_list(
    ctx: typer.Context,
    agent: str = typer.Option(..., "--agent", help="Agent ID to list available credentials for."),
) -> None:
    """List credentials available to an agent (filtered by policy).

    Example:
      hermes-vault broker list --agent hermes
    """
    _, _, broker, _ = build_services(prompt=True)
    console.print_json(data=json.dumps(broker.list_available_credentials(agent)))


@_typer_app.command("rotate-master-key")
def rotate_master_key(
    ctx: typer.Context,
    skip_backup_dangerous: bool = typer.Option(False, "--skip-backup-dangerous", help="Skip the pre-rotation encrypted backup. DANGEROUS — you will not have a rollback point."),
) -> None:
    """Rotate the vault master key (re-encrypt all credentials).

    Derives a new master key from a new passphrase, re-encrypts every
    credential in the vault, and writes a new salt file.

    By default, creates an encrypted pre-rotation backup before rotating.
    Use --skip-backup-dangerous only if you have an existing verified backup.

    Requires the old passphrase first, then the new passphrase (twice to confirm).

    Example:
      hermes-vault rotate-master-key
    """
    import getpass as gp_local

    settings = get_settings()
    vault, _, _, _ = build_services(prompt=True)
    audit = AuditLogger(settings.db_path)

    console.print("[bold]Master Key Rotation[/bold]")
    console.print(f"  Vault: {settings.db_path}")
    console.print(f"  Credentials: {len(vault.list_credentials())}")

    old_passphrase = gp_local.getpass("Old vault passphrase: ")
    if not old_passphrase:
        console.print("[red]Old passphrase is required.[/red]")
        raise typer.Exit(code=2)

    new_pass = gp_local.getpass("New vault passphrase: ")
    if not new_pass:
        console.print("[red]New passphrase cannot be empty.[/red]")
        raise typer.Exit(code=2)
    confirm = gp_local.getpass("Confirm new passphrase: ")
    if new_pass != confirm:
        console.print("[red]New passphrases do not match. Rotation aborted.[/red]")
        raise typer.Exit(code=2)

    backup_path_obj = None
    if not skip_backup_dangerous:
        backup_stem = f"pre-rotate-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        backup_path_obj = settings.runtime_home / f"{backup_stem}.json"
        backup_content = json.dumps(vault.export_backup(), indent=2, sort_keys=True)
        backup_path_obj.write_text(backup_content, encoding="utf-8")
        backup_path_obj.chmod(0o600)
        console.print(f"[green]Pre-rotation backup:[/green] {backup_path_obj}")
        console.print(f"[yellow]  Keep your salt file to restore this backup.[/yellow]")
    else:
        console.print("[yellow]WARNING: Skipping pre-rotation backup (--skip-backup-dangerous).[/yellow]")
        console.print("[yellow]  No rollback point will exist.[/yellow]")

    try:
        result = vault.rotate_master_key(
            old_passphrase=old_passphrase,
            new_passphrase=new_pass,
            backup_path=None,  # backup already written above
        )
    except ValueError as exc:
        console.print(f"[red]Rotation failed: {exc}[/red]")
        raise typer.Exit(code=2)

    audit.record(AccessLogRecord(
        agent_id="operator",
        service="*",
        action="rotate_master_key",
        decision=Decision.allow,
        reason=f"master key rotated, {result['re_encrypted']} credential(s) re-encrypted",
    ))

    console.print(f"[green]Master key rotated successfully.[/green] {result['re_encrypted']} credential(s) re-encrypted.")
    console.print("[yellow]Update HERMES_VAULT_PASSPHRASE to your new passphrase for future vault access.[/yellow]")


@_typer_app.command("generate-skill")
def generate_skill(
    ctx: typer.Context,
    agent: str | None = typer.Option(None, "--agent"),
    all_agents: bool = typer.Option(False, "--all-agents"),
) -> None:
    _, policy, _, _ = build_services(prompt=True)
    settings = get_settings()
    generator = SkillGenerator(policy=policy, output_dir=settings.generated_skills_dir)
    paths = generator.generate_all() if all_agents else [generator.generate_for_agent(agent or "hermes")]
    console.print_json(data=json.dumps([str(path) for path in paths]))


@_typer_app.command("sync-skill")
def sync_skill(
    ctx: typer.Context,
    check: bool = typer.Option(False, "--check", help="Exit 0 if skill is current, 1 if stale."),
    write: bool = typer.Option(False, "--write", help="Regenerate the skill from current policy."),
    print_result: bool = typer.Option(False, "--print", help="Print the skill to stdout."),
    agent: str = typer.Option("hermes", "--agent", help="Agent ID to sync the skill for."),
) -> None:
    """Check or sync the hermes-vault-access SKILL.md against current policy.

    Generated skills embed a SHA-256 hash of the policy so stale detection
    is deterministic.

    Exit codes for --check: 0 = current, 1 = stale, 2 = error.

    Examples:
      hermes-vault sync-skill --check
      hermes-vault sync-skill --write
      hermes-vault sync-skill --print --agent hermes
    """
    mode_count = sum([check, write, print_result])
    if mode_count == 0:
        console.print("[red]Provide one of --check, --write, or --print[/red]")
        raise typer.Exit(code=2)
    if mode_count > 1:
        console.print("[red]--check, --write, and --print are mutually exclusive[/red]")
        raise typer.Exit(code=2)

    _, policy, _, _ = build_services(prompt=True)
    settings = get_settings()
    generator = SkillGenerator(policy=policy, output_dir=settings.generated_skills_dir)

    if print_result:
        path = generator.generate_for_agent(agent)
        content = path.read_text(encoding="utf-8")
        console.print(content)
        return

    result = generator.sync_skill(agent, check=check, write=write)
    if check:
        if result["current"]:
            console.print(f"[green]Skill for '{agent}' is current.[/green]")
            raise typer.Exit(code=0)
        else:
            stale_msg = "missing"
            if result["skill_hash"]:
                stale_msg = f"hash mismatch (skill: {result['skill_hash'][:12]}..., policy: {result['policy_hash'][:12]}...)"
            console.print(f"[yellow]Skill for '{agent}' is stale ({stale_msg}).[/yellow]")
            raise typer.Exit(code=1)

    if write:
        if result["current"]:
            console.print(f"[green]Skill for '{agent}' is already current.[/green]")
        else:
            console.print(f"[green]Skill for '{agent}' regenerated from policy.[/green]")


@_typer_app.command("backup")
def backup_vault(
    ctx: typer.Context,
    output: Path = typer.Option(..., "--output", "-o", help="Output path for the backup file."),
    metadata_only: bool = typer.Option(False, "--metadata-only", help="Exclude encrypted secrets; produce a metadata-only backup for diff/inspection."),
    include_audit: bool = typer.Option(False, "--include-audit", help="Include audit log entries in the backup."),
) -> None:
    """Export an encrypted backup of all vault credentials to a JSON file.

    Backup file is chmod 600. Store it alongside your salt file.

    Examples:
      hermes-vault backup --output ~/vault-backup-2026-04.json
      hermes-vault backup --metadata-only --output ~/vault-meta.json
      hermes-vault backup --include-audit --output ~/vault-full.json
    """
    vault, _, _, _ = build_services(prompt=True)
    backup = vault.export_backup(metadata_only=metadata_only)
    if include_audit:
        settings = get_settings()
        audit = AuditLogger(settings.db_path)
        entries = audit.list_recent(limit=5000)
        backup["audit_log"] = entries
    content = json.dumps(backup, indent=2, sort_keys=True)
    output.write_text(content, encoding="utf-8")
    output.chmod(0o600)
    console.print(f"[green]Backup written to {output}[/green]")
    console.print(f"  {len(backup['credentials'])} credential(s) exported")


@_typer_app.command("restore")
def restore_vault(
    ctx: typer.Context,
    input: Path = typer.Option(..., "--input", "-i", help="Path to a vault backup file."),
    yes: bool = typer.Option(False, "--yes", help="Confirm restoration without prompting."),
) -> None:
    """Restore vault credentials from a backup file.

    Existing credentials with the same service+alias are replaced.
    Requires --yes to confirm.

    Metadata-only backups are rejected with a clear error.

    Example:
      hermes-vault restore --input ~/vault-backup-2026-04.json --yes
    """
    if not yes:
        console.print("[red]Restoration requires --yes flag.[/red]")
        raise typer.Exit(code=1)
    vault, _, _, _ = build_services(prompt=True)
    try:
        backup = json.loads(input.read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[red]Failed to read backup file: {exc}[/red]")
        raise typer.Exit(code=1)
    if backup.get("version") != "hvbackup-v1":
        console.print(f"[red]Unsupported backup version: {backup.get('version')}[/red]")
        raise typer.Exit(code=1)
    try:
        imported = vault.import_backup(backup)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]Restored {len(imported)} credential(s) from {input}[/green]")


@_typer_app.command("diff")
def diff(
    ctx: typer.Context,
    against: Path = typer.Option(..., "--against", help="Path to a backup file to compare against."),
    format: str = typer.Option("json", "--format", help="Output format: json or table."),
) -> None:
    """Compare current vault metadata against a backup file.

    Shows which credentials have been added, removed, or changed.
    Never exposes secrets — only metadata deltas.

    Accepts both full backups and metadata-only backups.

    Examples:
      hermes-vault diff --against ~/vault-backup-old.json
      hermes-vault diff --against ~/vault-meta.json --format table
    """
    if format not in ("json", "table"):
        console.print("[red]--format must be 'json' or 'table'[/red]")
        raise typer.Exit(code=2)

    try:
        compare = json.loads(against.read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[red]Failed to read backup file: {exc}[/red]")
        raise typer.Exit(code=2)

    vault, _, _, _ = build_services(prompt=True)
    current = vault.export_backup(metadata_only=True)

    entries = diff_backups(current, compare)

    if format == "json":
        output = [e.as_dict() for e in entries]
        console.print_json(data=json.dumps(output, sort_keys=True))
        return

    table = Table(title="Vault Diff")
    table.add_column("KIND")
    table.add_column("SERVICE")
    table.add_column("ALIAS")
    table.add_column("TYPE")
    table.add_column("STATUS")
    table.add_column("CHANGES")
    for e in entries:
        changes_str = ", ".join(
            f"{ch['field']}: {ch['from']} → {ch['to']}" for ch in e.changes
        ) if e.changes else "-"
        table.add_row(
            e.kind.upper(),
            e.service,
            e.alias,
            e.credential_type or "-",
            e.status or "-",
            changes_str[:60] + ("..." if len(changes_str) > 60 else ""),
        )
    console.print(table)


@_typer_app.command("mcp")
def mcp_command(ctx: typer.Context) -> None:
    """Start the Hermes Vault MCP server (stdio transport).

    This command launches the Model Context Protocol server so that
    compatible hosts (Claude Desktop, Cursor, etc.) can request
    credentials through the vault broker.

    The server reads HERMES_VAULT_PASSPHRASE from the environment and
    loads the same policy and vault as the CLI.

    \b
    Example:
      hermes-vault mcp
    """
    import asyncio
    from hermes_vault.mcp_server import main as mcp_main
    try:
        asyncio.run(mcp_main())
    except KeyboardInterrupt:
        pass


@_typer_app.command()
def update(
    ctx: typer.Context,
    check: bool = typer.Option(
        False,
        "--check",
        help="Read-only update check that prints the detected install method and planned action.",
    ),
) -> None:
    """Check for or apply a safe Hermes Vault CLI upgrade."""
    try:
        plan = resolve_update_plan()
    except UpdateError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    _print_update_plan(plan)

    if check:
        console.print("[green]Read-only check complete. No changes were made.[/green]")
        return

    if not plan.needs_update:
        console.print("[green]Hermes Vault is already up to date.[/green]")
        return

    if not plan.installation.auto_update_supported:
        console.print("[red]Auto-update is not supported for this installation.[/red]")
        console.print(f"Manual command: {plan.installation.manual_command}")
        raise typer.Exit(code=1)

    assert plan.installation.auto_update_command is not None
    console.print(f"Running: {' '.join(plan.installation.auto_update_command)}")
    try:
        verified_version = perform_update(plan)
    except UpdateError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Hermes Vault updated successfully to {verified_version}.[/green]")


# ── OAuth subcommands ────────────────────────────────────────────────────────────
oauth_app = typer.Typer(help="OAuth operations.")
_typer_app.add_typer(oauth_app, name="oauth")


@oauth_app.command("login")
def oauth_login(
    ctx: typer.Context,
    provider: str = typer.Argument(help="OAuth provider name (e.g. google, github, openai)."),
    alias: str = typer.Option("default", "--alias", help="Vault alias for the stored credential."),
    port: int = typer.Option(0, "--port", help="Callback server port. 0 = OS-assigned ephemeral."),
    timeout: int = typer.Option(120, "--timeout", help="Seconds to wait for the OAuth callback before aborting."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Skip auto-opening browser; print URL instead."),
    scopes: list[str] = typer.Option(None, "--scope", help="Override requested OAuth scopes (repeatable)."),
) -> None:
    """Log in via OAuth PKCE and store tokens in the vault.

    \b
    Examples:
      hermes-vault oauth login google --alias work
      hermes-vault oauth login github --alias personal --no-browser
      hermes-vault oauth login google --scope openid --scope email --scope profile
    """
    from hermes_vault.oauth.flow import LoginFlow
    try:
        flow = LoginFlow(
            provider_id=provider,
            alias=alias,
            port=port,
            timeout=timeout,
            no_browser=no_browser,
            scopes=list(scopes or []),
            console=console,
        )
        flow.run()
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


@oauth_app.command("providers")
def oauth_providers(ctx: typer.Context) -> None:
    """List registered OAuth providers."""
    from hermes_vault.config import get_settings
    from hermes_vault.oauth.providers import OAuthProviderRegistry
    settings = get_settings()
    registry = OAuthProviderRegistry(settings.runtime_home / "oauth-providers.yaml")
    table = Table(title="OAuth Providers")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Requires Client ID")
    table.add_column("Requires Client Secret")
    for pid in registry.list_providers():
        p = registry.get(pid)
        if p is None:
            continue
        table.add_row(
            p.service_id,
            p.name,
            "yes" if p.requires_client_id else "no",
            "yes" if p.requires_client_secret else "no",
        )
    console.print(table)


@oauth_app.command("refresh")
def oauth_refresh(
    ctx: typer.Context,
    service: str | None = typer.Argument(None, help="Service name to refresh (e.g. google, github)."),
    alias: str = typer.Option("default", "--alias", help="Alias of the access token to refresh."),
    all_services: bool = typer.Option(False, "--all", help="Refresh all expired/near-expiry tokens."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be refreshed without updating the vault."),
    margin: int = typer.Option(300, "--margin", help="Proactive refresh margin in seconds (default 300)."),
) -> None:
    """Refresh OAuth access tokens using stored refresh tokens.

    \b
    Examples:
      hermes-vault oauth refresh google --alias work
      hermes-vault oauth refresh --all
      hermes-vault oauth refresh google --dry-run
    """
    vault, _, broker, _ = build_services(prompt=True)
    from hermes_vault.oauth.oauth_refresh import RefreshEngine
    engine = RefreshEngine(vault=vault, proactive_margin_seconds=margin)
    if broker.audit is not None:
        engine.set_audit(broker.audit)

    if all_services:
        results = engine.refresh_all(dry_run=dry_run)
    elif service:
        try:
            result = engine.refresh(service, alias=alias, dry_run=dry_run)
            results = [result]
        except Exception as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc
    else:
        console.print("[red]Provide a service name or pass --all[/red]")
        raise typer.Exit(code=1)

    table = Table(title="OAuth Refresh Results" + (" (dry-run)" if dry_run else ""))
    table.add_column("Service")
    table.add_column("Alias")
    table.add_column("Status")
    table.add_column("Reason")
    for res in results:
        status_color = "[green]ok[/green]" if res.success else "[red]fail[/red]"
        table.add_row(res.service, res.alias, status_color, res.reason)
    console.print(table)

    if not dry_run:
        success_count = sum(1 for r in results if r.success)
        if success_count:
            console.print(f"[green]Refreshed {success_count}/{len(results)} token(s).[/green]")
        if any(not r.success for r in results):
            console.print("[yellow]Some refreshes failed. Check the table above.[/yellow]")


# ── App proxy ──────────────────────────────────────────────────────────────────
# The setuptools entry point imports `app` from this module.
# Strips deprecated --banner so neither Click nor Typer ever sees it.
def app() -> int:
    """Proxy that strips deprecated --banner, then delegates to _hermes_group."""
    argv = [arg for arg in sys.argv[1:] if arg != "--banner"]
    if _targets_root_command(argv) and "--no-banner" not in argv and _should_show_banner():
        _show_banner()
    return _hermes_group(args=argv, prog_name=Path(sys.argv[0]).name)


if __name__ == "__main__":
    raise SystemExit(app())
