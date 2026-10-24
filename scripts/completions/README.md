# Shell completion for reconflow

Both scripts implement completion for the **current Python CLI**: `scan`,
`diff`, `scope`, `report`, `mark`, plus their actual flags.

Install the `reconflow` console entry point first (e.g. `pip install -e .`).
These completions are opt-in and contain no external service calls.

## Bash

Load for the current shell:

```bash
source /path/to/reconflow/scripts/completions/reconflow.bash
reconflow sc<TAB>     # scan, scope
reconflow scan --<TAB> # scan flags
```

For persistent setup, source the file from `~/.bashrc` or copy it into a
directory loaded by your system's `bash-completion` package.

## Zsh

Load with the native completion system:

```zsh
fpath=(/path/to/reconflow/scripts/completions $fpath)
autoload -Uz compinit
compinit
```

Rename or symlink `reconflow.zsh` as `_reconflow` within an `fpath`
directory, then restart Zsh or run `rehash`. Alternatively, source the script
directly after `compinit`:

```zsh
source /path/to/reconflow/scripts/completions/reconflow.zsh
```

These scripts cover the flags implemented by the **current** `reconflow`
entry point; older README references to `reconflow_v2.py`, `--resume`,
`--sarif`, `--jwt-audit` etc. do not correspond to the current parser and
are deliberately not advertised as supported options. No live scan or
credentials are needed to validate the scripts.
