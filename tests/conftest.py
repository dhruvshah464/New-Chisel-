from pathlib import Path

import pytest

from aisec.checks import evaluate
from aisec.sandbox import Sandbox
from aisec.targets.base import open_router, proxied
from aisec.targets.demo import DemoTarget
from aisec.targets.replay import run_replay

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIOS_DIR = REPO_ROOT / "scenarios" / "support-agent"


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def scenarios_dir() -> Path:
    return SCENARIOS_DIR


@pytest.fixture
def replay_demo():
    """Run a scenario's replay against the demo target's proxied servers; destroy sandboxes after."""
    sandboxes = []

    async def run(scenario, variant, reachability=False):
        target = DemoTarget(variant)
        sb = Sandbox.create(canaries=target.canaries())
        sandboxes.append(sb)
        sb.write_proxy_config(scenario.injection.to_dict() if scenario.injection else None, list(scenario.hold_tools))
        specs = [proxied(spec, sb) for spec in target.servers(scenario, sb, reachability=reachability)]
        with open(sb.root / "stderr.log", "w", encoding="utf-8") as errlog:
            async with open_router(specs, errlog=errlog) as router:
                transcript = await run_replay(router, scenario)
        return sb, transcript, evaluate(scenario.success_check, sb)

    yield run
    for sb in sandboxes:
        sb.destroy()
