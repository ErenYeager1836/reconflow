#compdef reconflow
# Zsh completion for the installed "reconflow" console script.
_reconflow() {
  local command previous
  local -a flags
  if (( CURRENT == 2 )); then
    local -a commands
    commands=(
      "scan:Run an in-scope scan"
      "diff:Compare two scans"
      "scope:Check target scope"
      "report:Regenerate reports"
      "mark:Mark a host"
      "doctor:Check external recon toolchain and dependencies"
    )
    _describe -t commands "reconflow command" commands
    return
  fi

  command="${words[2]}"
  previous="${words[CURRENT-1]}"
  case "$command" in
    scan)
      flags=(-o --output --threads --timeout --keep-wildcard --json --csv -q --quiet --silent --screenshots --scope --stages --skip -h --help)
      ;;
    diff)
      flags=(-o --output --json --notify --webhook-url -h --help)
      ;;
    scope)
      flags=(-h --help)
      ;;
    report)
      flags=(-o --output --run --json -h --help)
      ;;
    mark)
      flags=(-d --domain -o --output --tested --ignore --notes --list -h --help)
      ;;
    doctor)
      flags=(-h --help)
      ;;
    *) return ;;
  esac

  case "$previous" in
    -o|--output|--scope|--run)
      _files
      return
      ;;
    --threads|--timeout|-d|--domain|--webhook-url|--notes)
      return
      ;;
  esac

  if [[ "$PREFIX" == -* ]]; then
    compadd -Q -- "${flags[@]}"
  elif [[ "$command" == scope ]]; then
    _files
  fi
}
compdef _reconflow reconflow
