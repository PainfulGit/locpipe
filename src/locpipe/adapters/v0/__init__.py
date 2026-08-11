"""Generic read-only adapter SDK v0.

Import this facade explicitly as ``locpipe.adapters.v0``. It is intentionally
not re-exported from :mod:`locpipe` or the kernel facade.
"""

from ._corpus import adapter_output_declarations_v0, validate_adapter_corpus_v0
from ._models import (
    AdapterCorpusSummaryV0,
    AdapterExtractContextV0,
    AdapterMapContextV0,
    AdapterProbeContextV0,
)
from ._protocol import ReadOnlyAdapterV0
from ._runner import bind_read_only_adapter_v0

__all__ = [
    "AdapterCorpusSummaryV0",
    "AdapterExtractContextV0",
    "AdapterMapContextV0",
    "AdapterProbeContextV0",
    "ReadOnlyAdapterV0",
    "adapter_output_declarations_v0",
    "bind_read_only_adapter_v0",
    "validate_adapter_corpus_v0",
]
