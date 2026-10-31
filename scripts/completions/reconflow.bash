# Bash completion for the installed "reconflow" console script.
# Source this file after installing reconflow.
_reconflow_complete() {
  local current previous command item
  COMPREPLY=()
  current="${COMP_WORDS[COMP_CWORD]}"
  previous=""
  if (( COMP_CWORD > 0 )); then
    previous="${COMP_WORDS[COMP_CWORD-1]}"
  fi

  local -a commands=(scan diff scope report mark doctor)
  if (( COMP_CWORD == 1 )); then
    COMPREPLY=( $(compgen -W "${commands[*]} --version -v --help -h" -- "$current") )
    return
  fi

  command="${COMP_WORDS[1]}"
  local flags=""
  case "$command" in
    scan)
      flags="-o --output --threads --timeout --keep-wildcard --json --csv -q --quiet --silent --screenshots --scope --stages --skip -h --help"
      ;;
    diff)
      flags="-o --output --json --notify --webhook-url -h --help"
      ;;
    scope)
      flags="-h --help"
      ;;
    report)
      flags="-o --output --run --json -h --help"
      ;;
    mark)
      flags="-d --domain -o --output --tested --ignore --notes --list -h --help"
      ;;
    doctor)
      flags="-h --help"
      ;;
    *) return ;;
  esac

  case "$previous" in
    -o|--output|--scope|--run)
      COMPREPLY=( $(compgen -f -- "$current") )
      return
      ;;
    --threads|--timeout|--domain|-d|--webhook-url|--notes)
      return
      ;;
  esac

  if [[ "$current" == -* ]]; then
    COMPREPLY=( $(compgen -W "$flags" -- "$current") )
  elif [[ "$command" == "scope" && "$current" != -* ]]; then
    # Scope files and targets may also be local paths.
    COMPREPLY=( $(compgen -f -- "$current") )
  fi
}
complete -F _reconflow_complete reconflow
