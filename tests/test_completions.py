"""Ensure shell completions reflect the actual Python argparse options."""
import argparse
import re
import unittest
from pathlib import Path

from reconflow.cli import build_parser


ROOT = Path(__file__).resolve().parents[1] / "scripts" / "completions"


def parser_flags():
    parser = build_parser()
    subparsers = next(
        action for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    return {
        command: {
            flag
            for action in subparser._actions
            for flag in action.option_strings
        }
        for command, subparser in subparsers.choices.items()
    }


def completion_flags(source, command):
    pattern = (
        r"(?m)^    " + re.escape(command) +
        r"\)\s*\n\s*flags=\(([^)]*)\)"
        if "flags=(" in source else
        r"(?m)^    " + re.escape(command) +
        r"\)\s*\n\s*flags=\"([^\"]*)\""
    )
    match = re.search(pattern, source)
    if not match:
        raise AssertionError(f"completion flags not found for {command}")
    return set(match.group(1).split())


class CompletionTests(unittest.TestCase):
    def test_bash_includes_every_real_flag_for_each_command(self):
        text = (ROOT / "reconflow.bash").read_text(encoding="utf-8")
        for command, expected in parser_flags().items():
            with self.subTest(command=command):
                self.assertEqual(completion_flags(text, command), expected)

    def test_zsh_includes_every_real_flag_for_each_command(self):
        text = (ROOT / "reconflow.zsh").read_text(encoding="utf-8")
        for command, expected in parser_flags().items():
            with self.subTest(command=command):
                self.assertEqual(completion_flags(text, command), expected)

    def test_entry_point_and_all_current_subcommands_are_described(self):
        bash = (ROOT / "reconflow.bash").read_text(encoding="utf-8")
        zsh = (ROOT / "reconflow.zsh").read_text(encoding="utf-8")
        self.assertIn("complete -F _reconflow_complete reconflow", bash)
        self.assertIn("compdef _reconflow reconflow", zsh)
        for command in parser_flags():
            self.assertIn(command, bash)
            self.assertIn(command, zsh)
        for path in [ROOT / "reconflow.bash", ROOT / "reconflow.zsh"]:
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
