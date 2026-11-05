"""A thin name for the guard's entry points, so the scenario reads as a scenario."""
from guard.ingest import ingest, sign, verify, write_manifest  # noqa: F401

__all__ = ["ingest", "sign", "verify", "write_manifest"]
