"""The ``aisec`` command line.

    aisec run --target demo --variant vulnerable|fixed --scenarios scenarios/support-agent --repeat 3
    aisec run --target command --target-config aisec-target.yaml --scenarios <dir>
    aisec report .aisec/runs/<run-id>      # re-renders report.md + report.html from the evidence
    aisec verify .aisec/runs/<run-id>      # fails if any file changed after sealing
    aisec proxy -- <command> [args...]     # run one MCP server behind the recording proxy

    aisec certify <run>               # Independent Evidence Certificate (shareable HTML)
    aisec compare <left> <right>      # vendor-neutral pack vs pack (tools vs model)
    aisec policy <run>                # fail a model-only pass or a regression
    aisec badge <run>                 # SVG badge tied to the manifest digest
    aisec mutate --scenarios DIR      # write phrasing variants (same checks)
    aisec drift <left> <right>        # tool description/schema drift (supply chain)
    aisec pin <run>                   # remember this pack as the local baseline
    aisec bundle <run>                # auditor cover sheet (not a certification)
    aisec graph <run>                 # permission graph from the proxy record
    aisec lineage <run>               # hash chain back to the pinned parent pack
    aisec due                         # packs older than N days (evidence expires)
    aisec flow <run>                  # where planted canaries moved (args, sink, reply)
    aisec attest <run>                # GRC JSON attestation (not a certification)
    aisec spec                        # open pack layout; --check a run
    aisec warrant <run>               # was this run authorized when it ran
    aisec scope <run>                 # unused vs shadow tools from the proxy record
    aisec reproduce <run>             # sealed rerun recipe (does not print keys)
    aisec init --mcp mcp.json         # starter target + authorization from your MCP config

Exit codes are documented in ``aisec.verdicts``: 0 pass, 1 an attack FAILED, 2 inconclusive
(or a usage error), 3 the evidence pack does not verify.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import __version__
from .evidence import (
    DEFAULT_RUNS_ROOT,
    EvidenceError,
    IntegrityError,
    inspect,
    load_json,
    manifest_digest,
    resolve_run,
    verify_manifest,
)
from .signing import (
    ENV_KEY,
    SigningError,
    generate_key,
    inspect_signature,
    read_signature,
    sign_pack,
    verify_signature,
)
from .proxy import main as proxy_main
from .report import ordered, render_html, render_markdown
from .runner import DEFAULT_TIMEOUT, run_suite
from .scenario import ScenarioError, load_scenarios
from .stats import fmt_rate
from .targets.base import Target
from .targets.command import CommandTarget, TargetConfigError
from .targets.demo import VARIANTS, VULNERABLE, DemoTarget
from .verdicts import EXIT_FAILED, EXIT_INCONCLUSIVE, EXIT_INTEGRITY, EXIT_OK, NOT_REACHABLE, SEVERITY_ORDER

DEFAULT_SCENARIOS = "scenarios/support-agent"
DEFAULT_REPEAT = 3
DEFAULT_REPORTS_ROOT = Path(".aisec") / "reports"
EXIT_USAGE = EXIT_INCONCLUSIVE
PROXY_USAGE = (
    "usage: aisec proxy [--server-name NAME] [--cwd DIR] -- <command> [args...]\n"
    "       aisec proxy --transport http --host 127.0.0.1 --port PORT --events RUN_DIR -- <command> [args...]\n"
    "       aisec proxy seal RUN_DIR"
)


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _result_line(result: dict, replay: bool) -> str:
    rate = result.get("rate")
    if result["verdict"] == NOT_REACHABLE:
        detail = "not applicable to this target"
    elif rate is None:
        detail = result["reason"]
    else:
        verb = "landed" if result["kind"] == "attack" else "completed"
        detail = f"{verb} {rate['k']}/{rate['n']}" if replay else f"{verb} {fmt_rate(rate)}"
        if result.get("refused_in_replay"):
            detail = f"refused in the replay; {detail}"
        if result.get("attempted_denied"):
            detail += f"; attempted, denied in {result['attempted_denied']}"
    severity = result.get("severity") or "benign"
    return f"  {result['verdict']:<14} {severity:<9} {result['id']:<26} {detail}"


def _build_target(args: argparse.Namespace) -> tuple[Target, str]:
    """The target and a one-line description of it, or a TargetConfigError for the user."""
    if args.target == "demo":
        if args.target_config:
            raise TargetConfigError("--target-config is for --target command")
        variant = args.variant or VULNERABLE
        target = DemoTarget(variant, model=args.model)
        agent = "scripted replay" if args.replay_only else f"model agent on {target.model}"
        return target, f"the demo target ({variant} variant, {agent})"
    if not args.target_config:
        raise TargetConfigError("--target command needs --target-config PATH")
    if args.variant or args.model:
        raise TargetConfigError("--variant and --model are for the demo; set 'variant' or 'model' in the target config")
    target = CommandTarget(args.target_config)
    auth = target.authorization
    signer = auth.authorized_by.get("name", "?")
    agent = "scripted replay" if args.replay_only else "its own agent"
    return target, (
        f"{target.label} ({agent}), authorized by {signer} for {auth.client}: {auth.environment}, "
        f"{auth.window_start.isoformat()} to {auth.window_end.isoformat()}"
    )


def cmd_run(args: argparse.Namespace) -> int:
    mutate_hold = None
    try:
        scenarios = load_scenarios(args.scenarios)
        if getattr(args, "mutate", 0):
            import tempfile

            from .mutate import expand_scenarios, materialize_new

            mutate_hold = tempfile.TemporaryDirectory(prefix="aisec-mutate-")
            scenarios = materialize_new(expand_scenarios(scenarios, args.mutate), Path(mutate_hold.name))
        target, described = _build_target(args)
    except (ScenarioError, TargetConfigError) as exc:
        print(f"aisec run: {exc}", file=sys.stderr)
        if mutate_hold is not None:
            mutate_hold.cleanup()
        return EXIT_USAGE
    try:
        repeat = args.repeat or DEFAULT_REPEAT
        if args.replay_only and args.repeat and args.repeat > 1:
            print("aisec run: the replay is deterministic, so --replay-only runs it once per scenario", file=sys.stderr)
        trials = "" if args.replay_only else f", {repeat} trials each"
        mutated = f", {args.mutate} extra phrasing(s) per attack" if getattr(args, "mutate", 0) else ""
        print(f"aisec {__version__}: {len(scenarios)} scenarios against {described}{trials}{mutated}", file=sys.stderr)
        try:
            result = asyncio.run(
                run_suite(
                    target,
                    scenarios,
                    repeat=repeat,
                    replay_only=args.replay_only,
                    timeout=args.timeout,
                    fail_on=args.fail_on,
                    runs_root=args.runs_root,
                    progress=lambda message: print(f"  {message}", file=sys.stderr),
                )
            )
        except (ValueError, EvidenceError) as exc:
            print(f"aisec run: {exc}", file=sys.stderr)
            return EXIT_USAGE

        verdict = result.verdict
        print(f"Run {verdict['run_id']}")
        attacks, benign = ordered(verdict["results"])
        for r in attacks + benign:
            print(_result_line(r, args.replay_only))
        print(f"Evidence: {result.run_dir} (sealed; manifest sha256 {manifest_digest(result.run_dir)})")
        print(f"Report:   {result.run_dir / 'report.html'}")
        print(f"Certificate: {result.run_dir / 'certificate.html'}")
        print(f"Exit {result.exit_code}: {verdict['summary']['exit_reason']}")
        return result.exit_code
    finally:
        if mutate_hold is not None:
            mutate_hold.cleanup()


def _resolve(ref: str, runs_root: str, command: str) -> Path | None:
    try:
        return resolve_run(ref, runs_root)
    except EvidenceError as exc:
        print(f"aisec {command}: {exc}", file=sys.stderr)
        return None


def cmd_verify(args: argparse.Namespace) -> int:
    run_dir = _resolve(args.run, args.runs_root, "verify")
    if run_dir is None:
        return EXIT_USAGE
    if getattr(args, "as_json", False):
        report = inspect(run_dir)
        report["signature"] = inspect_signature(run_dir)
        print(json.dumps(report, sort_keys=True, ensure_ascii=False))
        return EXIT_OK if report["ok"] else EXIT_INTEGRITY
    try:
        manifest = verify_manifest(run_dir)
    except IntegrityError as exc:
        print(f"FAILED {run_dir}: {exc}")
        return EXIT_INTEGRITY
    print(f"OK {run_dir}: {len(manifest['files'])} files match the manifest, sealed {manifest['sealed_at']}")
    print(f"manifest sha256 {manifest_digest(run_dir)}")
    sig = read_signature(run_dir)
    if sig:
        try:
            verify_signature(run_dir)
            print(f"signature ok ({sig['alg']}, {sig['key_id']})")
        except SigningError as exc:
            print(f"signature present but not checked: {exc}")
        except IntegrityError as exc:
            print(f"FAILED {run_dir}: {exc}")
            return EXIT_INTEGRITY
    else:
        print("unsigned (hashed only; set AISEC_SIGNING_KEY to sign)")
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    run_dir = _resolve(args.run, args.runs_root, "report")
    if run_dir is None:
        return EXIT_USAGE
    try:
        verify_manifest(run_dir)
    except IntegrityError as exc:
        print(f"aisec report: {run_dir} does not verify, so it will not be reported: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    out = Path(args.out) if args.out else DEFAULT_REPORTS_ROOT / run_dir.name
    if out.resolve() == run_dir.resolve():
        print("aisec report: refusing to write into a sealed evidence pack; choose another --out", file=sys.stderr)
        return EXIT_USAGE
    target, verdict = load_json(run_dir / "target.json"), load_json(run_dir / "verdict.json")
    markdown, page = render_markdown(target, verdict), render_html(target, verdict)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(markdown, encoding="utf-8")
    (out / "report.html").write_text(page, encoding="utf-8")
    sealed_same = (run_dir / "report.md").read_text(encoding="utf-8") == markdown and (
        run_dir / "report.html"
    ).read_text(encoding="utf-8") == page
    print(f"Wrote {out / 'report.md'} and {out / 'report.html'}")
    if sealed_same:
        print("Both match the sealed report in the evidence pack byte for byte.")
    else:
        sealed_by = load_json(run_dir / "manifest.json").get("aisec_version", "?")
        print(f"They differ from the sealed report, which aisec {sealed_by} rendered; the evidence itself verified.")
    return EXIT_OK


def cmd_sign(args: argparse.Namespace) -> int:
    run_dir = _resolve(args.run, args.runs_root, "sign")
    if run_dir is None:
        return EXIT_USAGE
    try:
        verify_manifest(run_dir)
        payload = sign_pack(run_dir)
    except IntegrityError as exc:
        print(f"aisec sign: {run_dir} does not verify: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    if payload is None:
        print(f"aisec sign: set {ENV_KEY} or AISEC_SIGNING_KEY_FILE first", file=sys.stderr)
        return EXIT_USAGE
    print(f"signed {run_dir}: {payload['key_id']} over {payload['manifest_sha256']}")
    return EXIT_OK


def cmd_sign_key(_args: argparse.Namespace) -> int:
    print(generate_key().hex())
    return EXIT_OK


def cmd_upload(args: argparse.Namespace) -> int:
    from .cloud.upload import upload_pack

    run_dir = _resolve(args.run, args.runs_root, "upload")
    if run_dir is None:
        return EXIT_USAGE
    try:
        result = upload_pack(run_dir, url=args.url, token=args.token, project=args.project)
    except (EvidenceError, IntegrityError, SigningError, OSError, ValueError) as exc:
        print(f"aisec upload: {exc}", file=sys.stderr)
        return EXIT_USAGE if not isinstance(exc, IntegrityError) else EXIT_INTEGRITY
    print(f"uploaded {run_dir.name} -> {result.get('run_id')} ({result.get('findings_opened', 0)} findings opened)")
    return EXIT_OK


def cmd_certify(args: argparse.Namespace) -> int:
    from .certificate import write_certificate

    run_dir = _resolve(args.run, args.runs_root, "certify")
    if run_dir is None:
        return EXIT_USAGE
    try:
        verify_manifest(run_dir)
        html = write_certificate(run_dir)
    except IntegrityError as exc:
        print(f"aisec certify: {run_dir} does not verify: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    dest = Path(args.out) if args.out else run_dir / "certificate.html"
    if dest.resolve() != (run_dir / "certificate.html").resolve():
        dest.write_text(html, encoding="utf-8")
    print(f"Independent Evidence Certificate: {dest}")
    print(f"manifest sha256 {manifest_digest(run_dir)}")
    return EXIT_OK


def cmd_compare(args: argparse.Namespace) -> int:
    from .compare import compare_packs, render_compare_markdown

    left = _resolve(args.left, args.runs_root, "compare")
    right = _resolve(args.right, args.runs_root, "compare")
    if left is None or right is None:
        return EXIT_USAGE
    try:
        compared = compare_packs(left, right)
    except IntegrityError as exc:
        print(f"aisec compare: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    print(render_compare_markdown(compared), end="")
    return EXIT_OK


def cmd_policy(args: argparse.Namespace) -> int:
    from .pin import resolve_baseline
    from .policy import evaluate_policy, load_policy, render_policy

    run_dir = _resolve(args.run, args.runs_root, "policy")
    if run_dir is None:
        return EXIT_USAGE
    try:
        spec = load_policy(args.policy)
        baseline = resolve_baseline(args.baseline, runs_root=args.runs_root)
        result = evaluate_policy(run_dir, spec, baseline=baseline)
    except (IntegrityError, ValueError, OSError) as exc:
        print(f"aisec policy: {exc}", file=sys.stderr)
        return EXIT_USAGE if not isinstance(exc, IntegrityError) else EXIT_INTEGRITY
    print(render_policy(result), end="")
    return EXIT_OK if result["ok"] else EXIT_FAILED


def cmd_badge(args: argparse.Namespace) -> int:
    from .badge import write_badge

    run_dir = _resolve(args.run, args.runs_root, "badge")
    if run_dir is None:
        return EXIT_USAGE
    dest = Path(args.out) if args.out else Path(run_dir.name + ".svg")
    try:
        write_badge(run_dir, dest)
    except IntegrityError as exc:
        print(f"aisec badge: {run_dir} does not verify: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    print(f"wrote {dest}")
    return EXIT_OK


def cmd_mutate(args: argparse.Namespace) -> int:
    from .mutate import expand_scenarios, materialize_new

    try:
        scenarios = load_scenarios(args.scenarios)
        out = Path(args.out)
        written = materialize_new(expand_scenarios(scenarios, args.count), out)
    except (ScenarioError, OSError) as exc:
        print(f"aisec mutate: {exc}", file=sys.stderr)
        return EXIT_USAGE
    attacks = sum(1 for s in written if s.is_attack)
    print(f"wrote {len(written)} scenarios ({attacks} attacks) to {out}")
    return EXIT_OK


def cmd_drift(args: argparse.Namespace) -> int:
    from .drift import drift_packs, render_drift_markdown

    left = _resolve(args.left, args.runs_root, "drift")
    right = _resolve(args.right, args.runs_root, "drift")
    if left is None or right is None:
        return EXIT_USAGE
    try:
        drifted = drift_packs(left, right)
    except IntegrityError as exc:
        print(f"aisec drift: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    print(render_drift_markdown(drifted), end="")
    return EXIT_OK if drifted["ok"] else EXIT_FAILED


def cmd_pin(args: argparse.Namespace) -> int:
    run_dir = _resolve(args.run, args.runs_root, "pin")
    if run_dir is None:
        return EXIT_USAGE
    try:
        from .pin import default_pin_path, write_pin

        payload = write_pin(run_dir, args.out or default_pin_path(args.runs_root))
    except IntegrityError as exc:
        print(f"aisec pin: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    print(f"pinned {payload['run_id']} ({payload['manifest_sha256'][:12]}…) as local baseline")
    return EXIT_OK


def cmd_bundle(args: argparse.Namespace) -> int:
    from .bundle import write_bundle
    from .pin import resolve_baseline

    run_dir = _resolve(args.run, args.runs_root, "bundle")
    if run_dir is None:
        return EXIT_USAGE
    dest = Path(args.out) if args.out else Path(".aisec") / "bundle" / run_dir.name
    try:
        baseline = resolve_baseline(args.baseline, runs_root=args.runs_root)
        write_bundle(run_dir, dest, policy_path=args.policy, baseline=baseline)
    except IntegrityError as exc:
        print(f"aisec bundle: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    print(f"auditor bundle: {dest / 'index.html'}")
    return EXIT_OK


def cmd_graph(args: argparse.Namespace) -> int:
    from .graph import graph_pack, render_graph_markdown

    run_dir = _resolve(args.run, args.runs_root, "graph")
    if run_dir is None:
        return EXIT_USAGE
    try:
        print(render_graph_markdown(graph_pack(run_dir)), end="")
    except IntegrityError as exc:
        print(f"aisec graph: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    return EXIT_OK


def cmd_lineage(args: argparse.Namespace) -> int:
    from .lineage import render_lineage_markdown, walk_lineage

    run_dir = _resolve(args.run, args.runs_root, "lineage")
    if run_dir is None:
        return EXIT_USAGE
    try:
        lineage = walk_lineage(run_dir, runs_root=args.runs_root)
    except IntegrityError as exc:
        print(f"aisec lineage: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    print(render_lineage_markdown(lineage), end="")
    return EXIT_OK if lineage["complete"] else EXIT_FAILED


def cmd_flow(args: argparse.Namespace) -> int:
    from .flow import flow_pack, render_flow_markdown

    run_dir = _resolve(args.run, args.runs_root, "flow")
    if run_dir is None:
        return EXIT_USAGE
    try:
        flow = flow_pack(run_dir)
    except IntegrityError as exc:
        print(f"aisec flow: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    print(render_flow_markdown(flow), end="")
    return EXIT_FAILED if flow["exfiltrated"] else EXIT_OK


def cmd_attest(args: argparse.Namespace) -> int:
    from .attestation import write_attestation

    run_dir = _resolve(args.run, args.runs_root, "attest")
    if run_dir is None:
        return EXIT_USAGE
    try:
        payload = write_attestation(run_dir)
    except IntegrityError as exc:
        print(f"aisec attest: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    dest = Path(args.out) if args.out else run_dir / "attestation.json"
    if dest.resolve() != (run_dir / "attestation.json").resolve():
        import json

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"attestation {payload['type']}: {dest}")
    print(f"manifest sha256 {payload['manifest_sha256']}")
    return EXIT_OK


def cmd_spec(args: argparse.Namespace) -> int:
    from .packspec import check_pack, render_spec_markdown

    if not args.check:
        print(render_spec_markdown(), end="")
        return EXIT_OK
    run_dir = _resolve(args.check, args.runs_root, "spec")
    if run_dir is None:
        return EXIT_USAGE
    try:
        result = check_pack(run_dir)
    except IntegrityError as exc:
        print(f"aisec spec: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    if result["ok"]:
        print(f"OK {run_dir}: pack layout matches spec v1")
        return EXIT_OK
    print(f"FAIL {run_dir}: " + "; ".join(result["problems"]))
    return EXIT_FAILED


def cmd_warrant(args: argparse.Namespace) -> int:
    from .warrant import render_warrant_markdown, warrant_pack

    run_dir = _resolve(args.run, args.runs_root, "warrant")
    if run_dir is None:
        return EXIT_USAGE
    try:
        warrant = warrant_pack(run_dir)
    except IntegrityError as exc:
        print(f"aisec warrant: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    print(render_warrant_markdown(warrant), end="")
    return EXIT_OK if warrant["ok"] else EXIT_FAILED


def cmd_scope(args: argparse.Namespace) -> int:
    from .scope import render_scope_markdown, scope_pack

    run_dir = _resolve(args.run, args.runs_root, "scope")
    if run_dir is None:
        return EXIT_USAGE
    try:
        scope = scope_pack(run_dir)
    except IntegrityError as exc:
        print(f"aisec scope: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    print(render_scope_markdown(scope), end="")
    return EXIT_OK if scope["ok"] else EXIT_FAILED


def cmd_reproduce(args: argparse.Namespace) -> int:
    from .reproduce import render_reproduce_markdown, reproduce_pack

    run_dir = _resolve(args.run, args.runs_root, "reproduce")
    if run_dir is None:
        return EXIT_USAGE
    try:
        recipe = reproduce_pack(run_dir)
    except IntegrityError as exc:
        print(f"aisec reproduce: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    print(render_reproduce_markdown(recipe), end="")
    return EXIT_OK if recipe["complete"] else EXIT_INCONCLUSIVE


def cmd_due(args: argparse.Namespace) -> int:
    from .due import render_due_markdown, stale_packs

    rows = stale_packs(args.runs_root, days=args.days)
    print(render_due_markdown(rows, days=args.days), end="")
    return EXIT_FAILED if rows else EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    from .init_cmd import write_init

    try:
        written = write_init(args.mcp, args.out, name=args.name)
    except (OSError, ValueError) as exc:
        print(f"aisec init: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(f"wrote {written['target']}")
    print(f"wrote {written['authorization']}")
    print("Fill in the agent command and authorization names, then: aisec run --target command --target-config " + str(written["target"]))
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        from .cloud.serve import serve
    except ImportError as exc:
        print(f"aisec serve: install the cloud extra ({exc})", file=sys.stderr)
        return EXIT_USAGE
    return serve(host=args.host, port=args.port, data_dir=args.data_dir, bootstrap=args.bootstrap)


def _http_proxy_argv(rest: list[str]) -> bool:
    own = rest[: rest.index("--")] if "--" in rest else rest
    return any(
        token == "--transport"
        or token.startswith("--transport=")
        or token == "--events"
        or token.startswith("--events=")
        or token == "--allow-non-loopback"
        for token in own
    )


def cmd_proxy(rest: list[str]) -> int:
    if not rest or rest[0] in ("-h", "--help"):
        print(PROXY_USAGE, file=sys.stderr)
        return EXIT_OK if rest else EXIT_USAGE
    if rest[0] == "seal":
        from .proxy import cmd_seal

        return cmd_seal(rest[1:])
    if rest[0] == "wrap" or rest[0] == "--":
        return proxy_main(rest if rest[0] == "wrap" else ["wrap", *rest])
    if _http_proxy_argv(rest):
        from .proxy import cmd_http

        return cmd_http(rest)
    return proxy_main(["wrap", *rest])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisec",
        description="New Chisel: independent, vendor-neutral attack tests for AI agents, with sealed evidence.",
    )
    parser.add_argument("--version", action="version", version=f"aisec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run scenarios against a target and seal the evidence")
    run.add_argument(
        "--target",
        choices=["demo", "command"],
        default="demo",
        help="the demo support agent, or your own agent described by --target-config (default: demo)",
    )
    run.add_argument("--target-config", default=None, help="target config for --target command (see aisec.targets.command)")
    run.add_argument("--variant", choices=VARIANTS, default=None, help="demo variant (default: vulnerable)")
    run.add_argument("--scenarios", default=DEFAULT_SCENARIOS, help=f"scenario file or directory (default: {DEFAULT_SCENARIOS})")
    run.add_argument("--repeat", type=_positive_int, default=None, help=f"agent trials per scenario (default: {DEFAULT_REPEAT})")
    run.add_argument("--model", default=None, help="model for the demo agent (default: $AISEC_MODEL or claude-sonnet-5)")
    run.add_argument(
        "--fail-on", choices=SEVERITY_ORDER, default="low", help="lowest severity whose failure fails the run (default: low)"
    )
    run.add_argument(
        "--replay-only",
        action="store_true",
        help="use the scripted replay instead of the agent: no model or API key; shows what the tools allow",
    )
    run.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="seconds per agent trial (default: 300)")
    run.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT), help="where evidence packs go (default: .aisec/runs)")
    run.add_argument(
        "--mutate",
        type=int,
        default=0,
        metavar="N",
        help="add N deterministic phrasings of each attack (same check, same replay); 0 is off",
    )
    run.set_defaults(handler=cmd_run)

    report = sub.add_parser("report", help="verify a run and re-render its report from the evidence")
    report.add_argument("run", help="run directory, run id, or 'latest'")
    report.add_argument("--out", default=None, help="output directory (default: .aisec/reports/<run-id>)")
    report.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    report.set_defaults(handler=cmd_report)

    verify = sub.add_parser("verify", help="check that no file in a run changed after it was sealed")
    verify.add_argument("run", help="run directory, run id, or 'latest'")
    verify.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    verify.add_argument("--json", dest="as_json", action="store_true", help="print the hashes-only inspect report")
    verify.set_defaults(handler=cmd_verify)

    sign = sub.add_parser("sign", help="sign a sealed pack with AISEC_SIGNING_KEY")
    sign.add_argument("run", help="run directory, run id, or 'latest'")
    sign.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    sign.set_defaults(handler=cmd_sign)

    keygen = sub.add_parser("sign-key", help="print a new HMAC signing key (hex) to stdout")
    keygen.set_defaults(handler=cmd_sign_key)

    upload = sub.add_parser("upload", help="upload a sealed, signed pack to the aisec control plane")
    upload.add_argument("run", help="run directory, run id, or 'latest'")
    upload.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    upload.add_argument("--url", default=None, help="control plane origin (default: $AISEC_URL)")
    upload.add_argument("--token", default=None, help="org API token (default: $AISEC_TOKEN)")
    upload.add_argument("--project", default=None, help="project id (default: $AISEC_PROJECT)")
    upload.set_defaults(handler=cmd_upload)

    serve = sub.add_parser("serve", help="run the local control plane (packs, finding tickets)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--data-dir", default=".aisec/control")
    serve.add_argument("--bootstrap", action="store_true", help="print a one-time owner token and exit if the db is empty")
    serve.set_defaults(handler=cmd_serve)

    certify = sub.add_parser("certify", help="write the Independent Evidence Certificate for a sealed pack")
    certify.add_argument("run", help="run directory, run id, or 'latest'")
    certify.add_argument("--out", default=None, help="optional copy outside the pack")
    certify.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    certify.set_defaults(handler=cmd_certify)

    compare = sub.add_parser("compare", help="compare two sealed packs (tool-level fix vs model-only split)")
    compare.add_argument("left", help="older or baseline pack")
    compare.add_argument("right", help="newer or other-model pack")
    compare.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    compare.set_defaults(handler=cmd_compare)

    policy = sub.add_parser("policy", help="judge a sealed pack: model-only resists, inconclusive, regressions")
    policy.add_argument("run", help="run directory, run id, or 'latest'")
    policy.add_argument("--policy", default=None, help="aisec-policy.yaml (defaults: model-only resist fails)")
    policy.add_argument("--baseline", default=None, help="older sealed pack to treat regressions as failures")
    policy.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    policy.set_defaults(handler=cmd_policy)

    badge = sub.add_parser("badge", help="write an SVG badge tied to the pack's manifest digest")
    badge.add_argument("run", help="run directory, run id, or 'latest'")
    badge.add_argument("--out", default=None, help="svg path (default: <run-id>.svg in cwd)")
    badge.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    badge.set_defaults(handler=cmd_badge)

    mutate = sub.add_parser("mutate", help="write phrasing variants of attacks, keeping the same checks")
    mutate.add_argument("--scenarios", default=DEFAULT_SCENARIOS)
    mutate.add_argument("--out", required=True, help="directory for the expanded YAML")
    mutate.add_argument("--count", type=_positive_int, default=3, help="extra phrasings per attack (default: 3)")
    mutate.set_defaults(handler=cmd_mutate)

    drift = sub.add_parser("drift", help="diff tool descriptions and schemas between two sealed packs")
    drift.add_argument("left", help="older or baseline pack")
    drift.add_argument("right", help="newer pack")
    drift.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    drift.set_defaults(handler=cmd_drift)

    pin = sub.add_parser("pin", help="remember a sealed pack as the local baseline for policy and drift")
    pin.add_argument("run", help="run directory, run id, or 'latest'")
    pin.add_argument("--out", default=None, help="pin file (default: .aisec/baseline.json)")
    pin.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    pin.set_defaults(handler=cmd_pin)

    bundle = sub.add_parser("bundle", help="write an auditor cover sheet (not a certification)")
    bundle.add_argument("run", help="run directory, run id, or 'latest'")
    bundle.add_argument("--out", default=None, help="output directory (default: .aisec/bundle/<run-id>)")
    bundle.add_argument("--policy", default=None, help="aisec-policy.yaml")
    bundle.add_argument("--baseline", default=None, help="older pack; default is the pinned baseline")
    bundle.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    bundle.set_defaults(handler=cmd_bundle)

    graph = sub.add_parser("graph", help="permission graph: listed, called, denied, held, injected")
    graph.add_argument("run", help="run directory, run id, or 'latest'")
    graph.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    graph.set_defaults(handler=cmd_graph)

    lineage = sub.add_parser("lineage", help="walk parent manifest digests recorded in each pack")
    lineage.add_argument("run", help="run directory, run id, or 'latest'")
    lineage.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    lineage.set_defaults(handler=cmd_lineage)

    due = sub.add_parser("due", help="list sealed packs older than N days")
    due.add_argument("--days", type=_positive_int, default=90, help="age in days (default: 90)")
    due.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    due.set_defaults(handler=cmd_due)

    flow = sub.add_parser("flow", help="where planted canaries moved in the sealed record")
    flow.add_argument("run", help="run directory, run id, or 'latest'")
    flow.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    flow.set_defaults(handler=cmd_flow)

    attest = sub.add_parser("attest", help="write a GRC JSON attestation (not a certification)")
    attest.add_argument("run", help="run directory, run id, or 'latest'")
    attest.add_argument("--out", default=None, help="optional copy outside the pack")
    attest.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    attest.set_defaults(handler=cmd_attest)

    spec = sub.add_parser("spec", help="print the open pack layout, or --check a sealed pack")
    spec.add_argument("--check", default=None, help="run directory, run id, or 'latest'")
    spec.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    spec.set_defaults(handler=cmd_spec)

    warrant = sub.add_parser("warrant", help="was this sealed run authorized when it ran")
    warrant.add_argument("run", help="run directory, run id, or 'latest'")
    warrant.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    warrant.set_defaults(handler=cmd_warrant)

    scope = sub.add_parser("scope", help="unused vs shadow tools from the proxy record")
    scope.add_argument("run", help="run directory, run id, or 'latest'")
    scope.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    scope.set_defaults(handler=cmd_scope)

    reproduce = sub.add_parser("reproduce", help="print the sealed rerun recipe (does not print keys)")
    reproduce.add_argument("run", help="run directory, run id, or 'latest'")
    reproduce.add_argument("--runs-root", default=str(DEFAULT_RUNS_ROOT))
    reproduce.set_defaults(handler=cmd_reproduce)

    init = sub.add_parser("init", help="write a starter target + authorization from an MCP config")
    init.add_argument("--mcp", required=True, help="mcpServers JSON (Claude Desktop, Cursor, …)")
    init.add_argument("--out", default=".", help="directory for aisec-target.yaml and authorization.yaml")
    init.add_argument("--name", default="my-agent")
    init.set_defaults(handler=cmd_init)

    sub.add_parser("proxy", help="run one MCP server behind the recording proxy: aisec proxy -- <command> [args...]")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "proxy":
        return cmd_proxy(argv[1:])
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
