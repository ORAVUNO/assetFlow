"""Command-line interface for assetFlow.

Examples:
    assetflow validate                 # load & validate the registry
    assetflow feeds                    # list the data feeds
    assetflow list --status validated  # list queries
    assetflow show AI001               # show one query's details
    assetflow test-connection          # verify Elastic credentials
    assetflow run AI001 --limit 50     # execute a query against Elasticsearch
    assetflow run-feed FEED-IDENTITY   # execute every runnable query in a feed
"""

from __future__ import annotations

import sys
from typing import Optional

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from . import __version__
from .client import ConnectionConfigError, build_client_from_env, ping
from .models import Query, Registry
from .registry import load_registry
from .runner import QueryResult, run_query

console = Console()
err_console = Console(stderr=True)


def _load(registry_path: Optional[str]) -> Registry:
    try:
        return load_registry(registry_path)
    except Exception as exc:  # surface a clean message, not a traceback
        err_console.print(f"[red]Failed to load registry:[/red] {exc}")
        sys.exit(2)


def _connect():
    load_dotenv()
    try:
        return build_client_from_env()
    except ConnectionConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        sys.exit(2)


def _render_result(result: QueryResult, output: str) -> None:
    if output == "json":
        console.print_json(result.to_json())
        return
    if output == "csv":
        click.echo(result.to_csv())
        return

    table = Table(show_header=True, header_style="bold cyan")
    for name in result.column_names:
        table.add_column(str(name), overflow="fold")
    for row in result.rows:
        table.add_row(*["" if v is None else str(v) for v in row])
    console.print(table)
    console.print(f"[dim]{result.row_count} row(s)[/dim]")


@click.group()
@click.version_option(__version__, prog_name="assetflow")
@click.option(
    "--registry",
    "registry_path",
    default=None,
    help="Path to the registry YAML (defaults to config/asset_intelligence_registry.yaml).",
)
@click.pass_context
def main(ctx: click.Context, registry_path: Optional[str]) -> None:
    """assetFlow — run preloaded Asset Intelligence ES|QL queries."""
    ctx.ensure_object(dict)
    ctx.obj["registry_path"] = registry_path


@main.command()
@click.pass_context
def validate(ctx: click.Context) -> None:
    """Load and validate the registry, then print a summary."""
    reg = _load(ctx.obj["registry_path"])
    by_status: dict[str, int] = {}
    for q in reg.queries:
        by_status[q.status.value] = by_status.get(q.status.value, 0) + 1
    console.print("[green]Registry is valid.[/green]")
    console.print(
        f"version={reg.metadata.version}  "
        f"queries={len(reg.queries)}  feeds={len(reg.feeds)}"
    )
    console.print("status: " + "  ".join(f"{k}={v}" for k, v in sorted(by_status.items())))


@main.command(name="feeds")
@click.pass_context
def list_feeds(ctx: click.Context) -> None:
    """List the Asset Intelligence data feeds."""
    reg = _load(ctx.obj["registry_path"])
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Feed ID")
    table.add_column("Name")
    table.add_column("Queries")
    table.add_column("Refresh")
    for f in reg.feeds:
        table.add_row(f.id, f.name, ", ".join(f.query_ids), f.recommended_refresh_frequency)
    console.print(table)


@main.command(name="list")
@click.option("--status", default=None, help="Filter by status.")
@click.option("--category", default=None, help="Filter by category.")
@click.option("--feed", "feed_id", default=None, help="Filter to a feed's queries.")
@click.pass_context
def list_queries(
    ctx: click.Context,
    status: Optional[str],
    category: Optional[str],
    feed_id: Optional[str],
) -> None:
    """List queries, optionally filtered by status, category, or feed."""
    reg = _load(ctx.obj["registry_path"])

    if feed_id:
        try:
            queries = reg.queries_for_feed(feed_id)
        except KeyError as exc:
            err_console.print(f"[red]{exc}[/red]")
            sys.exit(2)
    else:
        queries = reg.queries

    def keep(q: Query) -> bool:
        if status and q.status.value != status:
            return False
        if category and q.category != category:
            return False
        return True

    queries = [q for q in queries if keep(q)]

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Runnable")
    for q in queries:
        table.add_row(
            q.id, q.name, q.category, q.status.value, "yes" if q.is_runnable else "no"
        )
    console.print(table)
    console.print(f"[dim]{len(queries)} quer(y/ies)[/dim]")


@main.command()
@click.argument("query_id")
@click.pass_context
def show(ctx: click.Context, query_id: str) -> None:
    """Show the full definition of one query."""
    reg = _load(ctx.obj["registry_path"])
    try:
        q = reg.get_query(query_id)
    except KeyError as exc:
        err_console.print(f"[red]{exc}[/red]")
        sys.exit(2)

    console.print(f"[bold]{q.id}[/bold] — {q.name}")
    console.print(f"category : {q.category}")
    console.print(f"status   : {q.status.value}  (validated={q.validated})")
    console.print(f"purpose  : {q.purpose}")
    console.print(f"refresh  : {q.recommended_refresh_frequency}")
    if q.expected_output_fields:
        console.print("output   : " + ", ".join(q.expected_output_fields))
    if q.notes:
        console.print(f"notes    : {q.notes}")
    if q.esql_query.strip():
        console.print("\n[bold]ES|QL[/bold]:")
        console.print(q.esql_query.strip())
    elif q.resource:
        console.print(f"\n[bold]resource[/bold]: {q.resource}  [dim](fetched via the Tufin adapter)[/dim]")
    else:
        console.print("\n[dim](no query — placeholder)[/dim]")


@main.command(name="test-connection")
def test_connection() -> None:
    """Verify Elasticsearch connectivity using your credentials."""
    client = _connect()
    try:
        info = ping(client)
    except Exception as exc:
        err_console.print(f"[red]Connection failed:[/red] {exc}")
        sys.exit(1)
    console.print("[green]Connected.[/green]")
    console.print(
        f"cluster={info['cluster_name']}  node={info['name']}  version={info['version']}"
    )


@main.command()
@click.argument("query_id")
@click.option("--limit", type=int, default=None, help="Cap the number of rows returned.")
@click.option(
    "--range",
    "time_range",
    type=click.Choice(["24h", "7d", "30d", "90d"]),
    default=None,
    help="Bound the query to recent data (adds a @timestamp filter).",
)
@click.option(
    "--output",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    help="Output format.",
)
@click.pass_context
def run(
    ctx: click.Context,
    query_id: str,
    limit: Optional[int],
    time_range: Optional[str],
    output: str,
) -> None:
    """Execute one query against Elasticsearch and print the results."""
    reg = _load(ctx.obj["registry_path"])
    try:
        q = reg.get_query(query_id)
    except KeyError as exc:
        err_console.print(f"[red]{exc}[/red]")
        sys.exit(2)

    client = _connect()
    try:
        result = run_query(client, q, limit=limit, time_range=time_range)
    except ValueError as exc:
        err_console.print(f"[yellow]{exc}[/yellow]")
        sys.exit(2)
    except Exception as exc:
        err_console.print(f"[red]Query failed:[/red] {exc}")
        sys.exit(1)

    if output == "table":
        console.print(f"[bold]{q.id}[/bold] — {q.name}  [dim]({q.status.value})[/dim]")
    _render_result(result, output)


@main.command(name="run-feed")
@click.argument("feed_id")
@click.option("--limit", type=int, default=None, help="Cap rows per query.")
@click.pass_context
def run_feed(ctx: click.Context, feed_id: str, limit: Optional[int]) -> None:
    """Execute every runnable query in a feed."""
    reg = _load(ctx.obj["registry_path"])
    try:
        queries = reg.queries_for_feed(feed_id)
    except KeyError as exc:
        err_console.print(f"[red]{exc}[/red]")
        sys.exit(2)

    client = _connect()
    ran = 0
    for q in queries:
        if not q.is_runnable:
            console.print(f"[dim]skip {q.id} ({q.status.value}): no ES|QL[/dim]")
            continue
        console.print(f"\n[bold]{q.id}[/bold] — {q.name}")
        try:
            result = run_query(client, q, limit=limit)
        except Exception as exc:
            err_console.print(f"[red]  failed:[/red] {exc}")
            continue
        _render_result(result, "table")
        ran += 1
    console.print(f"\n[dim]ran {ran} of {len(queries)} quer(y/ies) in {feed_id}[/dim]")


@main.command()
@click.option("--host", default="127.0.0.1", help="Interface to bind (default localhost).")
@click.option("--port", default=8000, type=int, help="Port to listen on.")
@click.pass_context
def serve(ctx: click.Context, host: str, port: int) -> None:
    """Launch the local web UI to browse and view results in the browser."""
    load_dotenv()
    try:
        import uvicorn

        from .webapp import create_app
    except ImportError:
        err_console.print(
            "[red]Web dependencies missing.[/red] Install with: pip install -e ."
        )
        sys.exit(2)

    import os

    from . import db as db_mod

    # Validate the registry up front so failures are clear, not buried in logs.
    _load(ctx.obj["registry_path"])
    app = create_app(ctx.obj["registry_path"])
    db_url = os.getenv("DATABASE_URL") or db_mod.DEFAULT_DB_URL
    console.print(f"[green]assetFlow UI[/green] → http://{host}:{port}  (Ctrl+C to stop)")
    console.print(f"[dim]results saved to {db_url}[/dim]")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":  # pragma: no cover
    main()
