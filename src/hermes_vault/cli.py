from __future__ import annotations

import json
import os
import sys
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
from hermes_vault.models import CredentialStatus
from hermes_vault.mutations import VaultMutations, OPERATOR_AGENT_ID
from hermes_vault.policy import PolicyEngine
from hermes_vault.scanner import Scanner
from hermes_vault.service_ids import normalize
from hermes_vault.skillgen import SkillGenerator
from hermes_vault.verifier import Verifier
from hermes_vault.vault import Vault

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


@_typer_app.command()
def scan(ctx: typer.Context, path: list[Path] = typer.Option(None, "--path"), format: str = typer.Option("table", "--format")) -> None:
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
    from_env: Path | None = typer.Option(None, "--from-env"),
    from_file: Path | None = typer.Option(None, "--from-file"),
    redact_source: bool = typer.Option(False, "--redact-source", help="Comment out imported lines in the source file after successful import."),
) -> None:
    if not from_env and not from_file:
        raise typer.BadParameter("Provide --from-env or --from-file")
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
                raise typer.BadParameter(result.reason)
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
                raise typer.BadParameter(result.reason)
            imported_names.append(key)

    console.print(f"Imported {len(imported_names)} credential(s).")
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
    service: str,
    alias: str = typer.Option("default", "--alias"),
    credential_type: str = typer.Option("api_key", "--credential-type"),
    secret: str | None = typer.Option(None, "--secret"),
) -> None:
    vault, _, _, mutations = build_services(prompt=True)
    service = normalize(service)
    secret_value = secret or typer.prompt("Secret", hide_input=True)
    result = mutations.add_credential(
        agent_id=OPERATOR_AGENT_ID,
        service=service,
        secret=secret_value,
        credential_type=credential_type,
        alias=alias,
    )
    if not result.allowed:
        raise typer.BadParameter(result.reason)
    assert result.record is not None
    console.print(f"Stored credential {result.record.id} for service '{result.record.service}' alias '{result.record.alias}'.")


@_typer_app.command(name="list")
def list_credentials_cmd(ctx: typer.Context) -> None:
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
    service_or_id: str,
    alias: str | None = typer.Option(None, "--alias", help="Target a specific alias when multiple credentials exist for a service."),
) -> None:
    vault, _, _, mutations = build_services(prompt=True)
    result = mutations.get_metadata(
        agent_id=OPERATOR_AGENT_ID,
        service_or_id=service_or_id,
        alias=alias,
    )
    if not result.allowed:
        console.print(f"[red]Denied: {result.reason}[/red]")
        raise typer.Exit(code=1)
    assert result.record is not None
    console.print_json(data=result.record.model_dump_json(exclude={"encrypted_payload"}))


@_typer_app.command()
def rotate(
    ctx: typer.Context,
    service_or_id: str,
    alias: str | None = typer.Option(None, "--alias", help="Target a specific alias when multiple credentials exist for a service."),
    secret: str | None = typer.Option(None, "--secret"),
) -> None:
    vault, _, _, mutations = build_services(prompt=True)
    secret_value = secret or typer.prompt("New secret", hide_input=True)
    result = mutations.rotate_credential(
        agent_id=OPERATOR_AGENT_ID,
        service_or_id=service_or_id,
        new_secret=secret_value,
        alias=alias,
    )
    if not result.allowed:
        console.print(f"[red]Denied: {result.reason}[/red]")
        raise typer.Exit(code=1)
    assert result.record is not None
    console.print(f"Rotated credential for service '{result.record.service}' alias '{result.record.alias}'.")


@_typer_app.command()
def delete(
    ctx: typer.Context,
    service_or_id: str,
    alias: str | None = typer.Option(None, "--alias", help="Target a specific alias when multiple credentials exist for a service."),
    yes: bool = typer.Option(False, "--yes"),
) -> None:
    if not yes:
        raise typer.BadParameter("Deletion requires --yes")
    vault, _, _, mutations = build_services(prompt=True)
    result = mutations.delete_credential(
        agent_id=OPERATOR_AGENT_ID,
        service_or_id=service_or_id,
        alias=alias,
    )
    if not result.allowed:
        console.print(f"[red]Denied: {result.reason}[/red]")
        raise typer.Exit(code=1)
    console.print(f"Deleted credential '{service_or_id}'.")


@_typer_app.command()
def verify(
    ctx: typer.Context,
    service: str | None = typer.Option(None, "--service"),
    alias: str | None = typer.Option(None, "--alias", help="Target a specific alias when multiple credentials exist for a service."),
    all: bool = typer.Option(False, "--all"),
) -> None:
    vault, _, broker, _ = build_services(prompt=True)
    if all:
        targets = [(record.service, record.alias) for record in vault.list_credentials()]
    elif service:
        targets = [(service, alias)]
    else:
        raise typer.BadParameter("Provide --service or use --all")
    results = []
    for svc, als in targets:
        results.append(broker.verify_credential(svc, alias=als))
    console.print_json(data=json.dumps([result.model_dump(mode="json") for result in results]))


@broker_app.command("get")
def broker_get(ctx: typer.Context, service: str, agent: str = typer.Option(..., "--agent"), purpose: str = typer.Option("task", "--purpose")) -> None:
    _, _, broker, _ = build_services(prompt=True)
    decision = broker.get_credential(service=service, purpose=purpose, agent_id=agent)
    if not decision.allowed:
        console.print_json(data=decision.model_dump_json())
        raise typer.Exit(code=1)
    console.print_json(data=json.dumps(decision.model_dump(mode="json")))


@broker_app.command("env")
def broker_env(ctx: typer.Context, service: str, agent: str = typer.Option(..., "--agent"), ttl: int = typer.Option(900, "--ttl")) -> None:
    _, _, broker, _ = build_services(prompt=True)
    decision = broker.get_ephemeral_env(service=service, agent_id=agent, ttl=ttl)
    if not decision.allowed:
        console.print_json(data=decision.model_dump_json())
        raise typer.Exit(code=1)
    console.print_json(data=json.dumps(decision.model_dump(mode="json")))


@broker_app.command("list")
def broker_list(ctx: typer.Context, agent: str = typer.Option(..., "--agent")) -> None:
    _, _, broker, _ = build_services(prompt=True)
    console.print_json(data=json.dumps(broker.list_available_credentials(agent)))


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


@_typer_app.command("backup")
def backup_vault(ctx: typer.Context, output: Path = typer.Option(..., "--output", help="Output path for the backup file")) -> None:
    """Export an encrypted backup of all vault credentials to a JSON file."""
    vault, _, _, _ = build_services(prompt=True)
    backup = vault.export_backup()
    content = json.dumps(backup, indent=2, sort_keys=True)
    output.write_text(content, encoding="utf-8")
    output.chmod(0o600)
    console.print(f"[green]Backup written to {output}[/green]")
    console.print(f"  {len(backup['credentials'])} credential(s) exported")


@_typer_app.command("restore")
def restore_vault(
    ctx: typer.Context,
    input: Path = typer.Option(..., "--input", help="Path to a vault backup file"),
    yes: bool = typer.Option(False, "--yes", help="Confirm restoration"),
) -> None:
    """Restore vault credentials from a backup file."""
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
    imported = vault.import_backup(backup)
    console.print(f"[green]Restored {len(imported)} credential(s) from {input}[/green]")


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
