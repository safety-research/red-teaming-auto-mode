"""`python -m auto_mode_eval.paper_results.analysis.tables` rebuilds the parquets."""

import typer

from ._build import build


def main(
    reuse: bool = typer.Option(
        False, "--reuse", help="derive from the frozen capability grid rather than the logs"
    ),
) -> None:
    build(reuse)


typer.run(main)
