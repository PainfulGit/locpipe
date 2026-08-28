import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from locpipe._demo_support.test_fluency_lifecycle_v0 import FluencyLifecycleV0Tests


__all__ = ("FluencyLifecycleV0Tests",)
