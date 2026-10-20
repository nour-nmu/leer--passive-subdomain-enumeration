"""
base.py
-------
Base interface that every passive-source provider implements. Keeping a
shared interface means new providers can be dropped into the
`enumeration/` package and picked up by manager.py without changing any
other code.
"""

from abc import ABC, abstractmethod
from typing import Set, Tuple


class PassiveProvider(ABC):
    """
    A passive subdomain-discovery source (e.g. crt.sh, CertSpotter).

    Providers must NEVER perform active scanning against the target --
    they only query third-party public datasets/APIs about the target.
    """

    name: str = "base"

    @abstractmethod
    def discover(self, domain: str, timeout: int) -> Set[str]:
        """
        Return a set of raw hostnames (lowercase, no protocol, no
        trailing dot) discovered for `domain`. Implementations must
        catch their own network/parsing errors and return whatever
        partial results they have (or an empty set) rather than
        raising, so one failing provider never stops the others.
        """
        raise NotImplementedError

    def safe_discover(self, domain: str, timeout: int) -> Tuple[str, Set[str], str]:
        """
        Wrapper used by the manager. Always returns:
            (provider_name, set_of_hostnames, error_message_or_empty_string)
        Never raises.
        """
        try:
            results = self.discover(domain, timeout)
            return self.name, results, ""
        except Exception as exc:  # noqa: BLE001 - intentional catch-all boundary
            return self.name, set(), f"{type(exc).__name__}: {exc}"
