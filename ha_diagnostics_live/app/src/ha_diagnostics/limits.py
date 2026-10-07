"""Shared admission state; no unbounded query waiting queue."""
from contextvars import ContextVar

rate_admitted_context=ContextVar("rate_admitted",default=False)

class RateLimited(Exception):
    def __init__(self,retry_after=1):
        self.retry_after=max(1,int(retry_after))
        super().__init__("RATE_LIMITED")
