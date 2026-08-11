CONTRACT_VERSION = "0.1.0-draft.2"
SCHEMA_PREFIX = "urn:locpipe:contracts:v0:"
KIND_TO_SCHEMA = {
    "source_branch": SCHEMA_PREFIX + "segment",
    "target_branch": SCHEMA_PREFIX + "segment",
    "source_snapshot": SCHEMA_PREFIX + "source-snapshot",
    "relation": SCHEMA_PREFIX + "relation",
    "workflow_profile": SCHEMA_PREFIX + "workflow-profile",
    "binding_set": SCHEMA_PREFIX + "binding",
    "receipt": SCHEMA_PREFIX + "receipt",
    "error": SCHEMA_PREFIX + "error",
    "operation_request": SCHEMA_PREFIX + "operation-request",
    "operation_result": SCHEMA_PREFIX + "operation-result",
}
