"""
5G Core Integrations Module (Future Extension Point).

This module is reserved for direct integrations with real 5G Core implementations:
1. Open5GS (https://open5gs.org/)
2. free5GC (https://free5gc.org/)

Architectural Design:
--------------------
Future integrations should implement adapters conforming to the base configuration
import pipeline without altering the core Scanner, Analyzer, or Rules modules.

Planned pipeline workflow:
  [Open5GS Config Importer / free5GC Config Importer / Manual File Upload]
                                |
                                v
                [Standardized Config Dict Pipeline]
                                |
                                v
                      [5G Sentinel Analyzer]

Current Status: Stub reserved for Phase 2 integration. No dependencies or deployments required.
"""

from typing import Dict, Any, Optional
from abc import ABC, abstractmethod


class Base5GCoreAdapter(ABC):
    """
    Abstract adapter interface for importing and normalizing 5G Core configuration
    files from specific distributions (Open5GS, free5GC, etc.) into the 5G Sentinel scanner.
    """

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Name of the 5G Core platform (e.g. 'Open5GS', 'free5GC')."""
        pass

    @abstractmethod
    def load_configuration(self, source_path_or_data: Any) -> Dict[str, Any]:
        """
        Normalize platform-specific configs into standard dictionary format
        suitable for scanner.analyzer.analyze_configuration.
        """
        pass
