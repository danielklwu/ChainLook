"""Manufacturer and registry data source providers.

Each provider implements :class:`BaseProvider` to expose a uniform
``lookup(part_number, manufacturer)`` interface. New sources (e.g. TI
material content, NXP product lifecycle, Octopart) can be added here
without touching the core pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseProvider(ABC):
    """Abstract interface for manufacturer/registry data sources."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name (e.g. 'Texas Instruments')."""

    @abstractmethod
    def lookup(self, part_number: str, manufacturer: str) -> dict:
        """Fetch provider-specific data for a component.

        Args:
            part_number:  Normalised part number from ComponentResult.
            manufacturer: Manufacturer name from ComponentResult.

        Returns:
            Arbitrary dict of provider-specific fields. Callers should
            treat this as supplementary data, not a fixed schema.
        """
