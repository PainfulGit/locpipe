from __future__ import annotations

from typing import Protocol

from locpipe.contracts.v0 import AdapterDescriptorV0, ErrorRecord

from ._models import AdapterExtractContextV0, AdapterMapContextV0, AdapterProbeContextV0


class ReadOnlyAdapterV0(Protocol):
    @property
    def descriptor(self) -> AdapterDescriptorV0: ...

    def probe(self, context: AdapterProbeContextV0) -> ErrorRecord | None: ...

    def extract(self, context: AdapterExtractContextV0) -> ErrorRecord | None: ...

    def map(self, context: AdapterMapContextV0) -> ErrorRecord | None: ...
