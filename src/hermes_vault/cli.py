from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.config import get_settings
from hermes_vault.crypto import MissingPassphraseError, resolve_passphrase
from hermes_vault.detectors import detect_matches, guess_from_env_name
from hermes_vault.models import CredentialStatus
from hermes_vault.policy import PolicyEngine
from hermes_vault.scanner import Scanner
from hermes_vault.skillgen import SkillGenerator
from hermes_vault.verifier import Verifier
from hermes_vault.vault import DuplicateCredentialError, Vault

app = typer.Typer(help="Hermes-native local-first credential vault, scanner, and broker.")
broker_app = typer.Typer(help="Broker operations.")
app.add_typer(broker_app, name="broker")
console = Console()


def build_services(prompt: bool = False) -> tuple[Vault, PolicyEngine, Broker]:
    settings = get_settings()
    policy = PolicyEngine.from_yaml(settings.effective_policy_path)
    policy.write_default(settings.effective_policy_path)
    passphrase = resolve_passphrase(prompt=prompt)
    vault = Vault(settings.db_path, settings.salt_path, passphrase)
    audit = AuditLogger(settings.db_path)
    verifier = Verifier()
    broker = Broker(vault=vault, policy=policy, verifier=verifier, audit=audit)
    return vault, policy, broker


@app.command()
def scan(path: list[Path] = typer.Option(None, "--path"), format: str = typer.Option("table", "--format")) -> None:
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


@app.command("import")
def import_credentials(
    from_env: Path | None = typer.Option(None, "--from-env"),
    from_file: Path | None = typer.Option(None, "--from-file"),
    redact_source: bool = typer.Option(False, "--redact-source", help="Comment out imported lines in the source file after successful import."),
) -> None:
    if not from_env and not from_file:
        raise typer.BadParameter("Provide --from-env or --from-file")
    vault, _, _ = build_services(prompt=True)
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
            try:
                vault.add_credential(
                    service=service,
                    secret=value.strip().strip("'\""),
                    credential_type=credential_type,
                    alias=name.strip().lower(),
                    imported_from=str(source),
                )
                imported_names.append(name.strip())
                imported_lines.add(i)
            except DuplicateCredentialError as exc:
                raise typer.BadParameter(str(exc)) from exc
    else:
        parsed = json.loads(original_content)
        for key, value in parsed.items():
            if not isinstance(value, str):
                continue
            matches = detect_matches(value)
            if not matches:
                continue
            detector, secret = matches[0]
            try:
                vault.add_credential(
                    service=detector.service,
                    secret=secret,
                    credential_type=detector.credential_type,
                    alias=key.lower(),
                    imported_from=str(source),
                )
                imported_names.append(key)
            except DuplicateCredentialError as exc:
                raise typer.BadParameter(str(exc)) from exc

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


@app.command()
def add(
    service: str,
    alias: str = typer.Option("default", "--alias"),
    credential_type: str = typer.Option("api_key", "--credential-type"),
    secret: str | None = typer.Option(None, "--secret"),
) -> None:
    vault, _, _ = build_services(prompt=True)
    secret_value = secret or typer.prompt("Secret", hide_input=True)
    try:
        record = vault.add_credential(service=service, alias=alias, credential_type=credential_type, secret=secret_value)
    except DuplicateCredentialError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"Stored credential {record.id} for service '{record.service}' alias '{record.alias}'.")


@app.command(name="list")
def list_credentials_cmd() -> None:
    vault, _, _ = build_services(prompt=True)
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


@app.command("show-metadata")
def show_metadata(service_or_id: str) -> None:
    vault, _, _ = build_services(prompt=True)
    record = vault.get_credential(service_or_id)
    if not record:
        raise typer.Exit(code=1)
    console.print_json(data=record.model_dump_json(exclude={"encrypted_payload"}))


@app.command()
def rotate(service_or_id: str, secret: str | None = typer.Option(None, "--secret")) -> None:
    vault, _, _ = build_services(prompt=True)
    secret_value = secret or typer.prompt("New secret", hide_input=True)
    record = vault.rotate(service_or_id, secret_value)
    console.print(f"Rotated credential for service '{record.service}' alias '{record.alias}'.")


@app.command()
def delete(service_or_id: str, yes: bool = typer.Option(False, "--yes")) -> None:
    if not yes:
        raise typer.BadParameter("Deletion requires --yes")
    vault, _, _ = build_services(prompt=True)
    if not vault.delete(service_or_id):
        raise typer.Exit(code=1)
    console.print(f"Deleted credential '{service_or_id}'.")


@app.command()
def verify(
    service: str | None = typer.Option(None, "--service"),
    all: bool = typer.Option(False, "--all"),
) -> None:
    vault, _, broker = build_services(prompt=True)
    targets = [service] if service else []
    if all:
        targets = [record.service for record in vault.list_credentials()]
    if not targets:
        raise typer.BadParameter("Provide a service or use --all")
    results = []
    for target in targets:
        results.append(broker.verify_credential(target))
    console.print_json(data=json.dumps([result.model_dump(mode="json") for result in results]))


@broker_app.command("get")
def broker_get(service: str, agent: str = typer.Option(..., "--agent"), purpose: str = typer.Option("task", "--purpose")) -> None:
    _, _, broker = build_services(prompt=True)
    decision = broker.get_credential(service=service, purpose=purpose, agent_id=agent)
    if not decision.allowed:
        console.print_json(data=decision.model_dump_json())
        raise typer.Exit(code=1)
    console.print_json(data=json.dumps(decision.model_dump(mode="json")))


@broker_app.command("env")
def broker_env(service: str, agent: str = typer.Option(..., "--agent"), ttl: int = typer.Option(900, "--ttl")) -> None:
    _, _, broker = build_services(prompt=True)
    decision = broker.get_ephemeral_env(service=service, agent_id=agent, ttl=ttl)
    if not decision.allowed:
        console.print_json(data=decision.model_dump_json())
        raise typer.Exit(code=1)
    console.print_json(data=json.dumps(decision.model_dump(mode="json")))


@broker_app.command("list")
def broker_list(agent: str = typer.Option(..., "--agent")) -> None:
    _, _, broker = build_services(prompt=True)
    console.print_json(data=json.dumps(broker.list_available_credentials(agent)))


@app.command("generate-skill")
def generate_skill(
    agent: str | None = typer.Option(None, "--agent"),
    all_agents: bool = typer.Option(False, "--all-agents"),
) -> None:
    _, policy, _ = build_services(prompt=True)
    settings = get_settings()
    generator = SkillGenerator(policy=policy, output_dir=settings.generated_skills_dir)
    paths = generator.generate_all() if all_agents else [generator.generate_for_agent(agent or "hermes")]
    console.print_json(data=json.dumps([str(path) for path in paths]))


@app.command("backup")
def backup_vault(output: Path = typer.Option(..., "--output", help="Output path for the backup file")) -> None:
    """Export an encrypted backup of all vault credentials to a JSON file."""
    vault, _, _ = build_services(prompt=True)
    backup = vault.export_backup()
    content = json.dumps(backup, indent=2, sort_keys=True)
    output.write_text(content, encoding="utf-8")
    output.chmod(0o600)
    console.print(f"[green]Backup written to {output}[/green]")
    console.print(f"  {len(backup['credentials'])} credential(s) exported")


@app.command("restore")
def restore_vault(
    input: Path = typer.Option(..., "--input", help="Path to a vault backup file"),
    yes: bool = typer.Option(False, "--yes", help="Confirm restoration"),
) -> None:
    """Restore vault credentials from a backup file."""
    if not yes:
        console.print("[red]Restoration requires --yes flag.[/red]")
        raise typer.Exit(code=1)
    vault, _, _ = build_services(prompt=True)
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


if __name__ == "__main__":
    app()
