"""cage.cli -- the forcecage command surface.

Three commands:

  forcecage run  [flags] <agent> <clone> <binary> -- <agent-args...>
      Absorb the whole cage: the agent-user hop, the per-session egress gate,
      the bwrap layout, the grant service, and teardown. The agent's own
      prompts/model/Moshi wiring stays opaque inside <agent-args>.
  forcecage check  [flags]
      Verify the host prerequisites (agent user, sudo hop, bwrap, iron-proxy)
      before a run. Read-only.
  forcecage version
      Print the version.

``--config`` (before the subcommand) selects forcecage.toml; ``--bindings``
selects the per-session credential bindings. Config values are the defaults;
these flags override them.
"""

import argparse
import sys

VERSION = "0.1.0"
VALID_AGENTS = ("pi", "claude", "codex")


class _Request:
    """The parsed command, with command-specific fields populated."""

    def __init__(self, command, config_path=None, bindings_path=None,
                 agent=None, clone=None, binary=None, agent_args=None):
        self.command = command
        self.config_path = config_path
        self.bindings_path = bindings_path
        self.agent = agent
        self.clone = clone
        self.binary = binary
        self.agent_args = list(agent_args or [])


def _build_parser():
    p = argparse.ArgumentParser(prog="forcecage")
    p.add_argument("--config", default=None,
                   help="path to forcecage.toml (default: $FORCECAGE_CONFIG, "
                        "./forcecage.toml, then the XDG config dir)")
    sub = p.add_subparsers(dest="command", required=True)

    runp = sub.add_parser("run", help="run an agent inside the cage")
    runp.add_argument("--bindings", default=None,
                      help="path to the per-session credential bindings file")
    runp.add_argument("agent", help="agent name: pi, claude or codex")
    runp.add_argument("clone", help="absolute path to the agent's clone dir")
    runp.add_argument("binary", help="absolute path to the agent binary")
    runp.add_argument("rest", nargs=argparse.REMAINDER,
                      help="the agent args, following a -- separator")

    chkp = sub.add_parser("check", help="verify host prerequisites")
    chkp.add_argument("--bindings", default=None,
                      help="also validate this bindings file")

    sub.add_parser("version", help="print the version")
    return p


def parse_args(argv):
    # The "--" is our boundary: everything after it is the agent's args. argparse
    # consumes a bare "--" itself, so detect it in the raw argv and let
    # REMAINDER collect the agent args (which argparse never mis-parses).
    has_separator = "--" in argv
    args = _build_parser().parse_args(argv)
    req = _Request(command=args.command, config_path=args.config)
    if args.command == "run":
        req.bindings_path = args.bindings
        req.agent = args.agent
        req.clone = args.clone
        req.binary = args.binary
        if not has_separator:
            raise SystemExit(
                "forcecage run: expected -- before the agent args")
        req.agent_args = list(args.rest)
    elif args.command == "check":
        req.bindings_path = args.bindings
    return req


def main(argv):
    req = parse_args(argv)
    if req.command == "version":
        print("forcecage %s" % VERSION)
        return 0
    if req.command == "check":
        from cage import check as check_mod
        return check_mod.cmd_check(req)
    if req.command == "run":
        if req.agent not in VALID_AGENTS:
            raise SystemExit(
                "forcecage run: unknown agent %r (want %s)"
                % (req.agent, " | ".join(VALID_AGENTS)))
        import cage.run as run_mod
        return run_mod.run(req)
    raise SystemExit("forcecage: unknown command %r" % req.command)


def console_main():
    """The console-script entry point (no args: reads ``sys.argv``). Returns an
    int exit code so ``pip install -e .``'s ``forcecage`` shim exits with the
    same code the CLI would."""
    return main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
