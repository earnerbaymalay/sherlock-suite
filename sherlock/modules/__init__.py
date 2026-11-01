"""
Module registry for Sherlock OSINT Suite.
"""

from typing import Dict, List, Type
from .base import BaseModule
from .dns_scanner import DNSScannerModule
from .crtsh_scanner import CrtShScannerModule
from .http_headers import HTTPHeadersScannerModule
from .rdap_scanner import RDAPScannerModule
from .port_surface import PortSurfaceScannerModule
from .due_diligence import DueDiligenceModule

ALL_MODULES: List[Type[BaseModule]] = [
    DNSScannerModule,
    CrtShScannerModule,
    HTTPHeadersScannerModule,
    RDAPScannerModule,
    PortSurfaceScannerModule,
    DueDiligenceModule,
]

MODULE_MAP: Dict[str, Type[BaseModule]] = {
    m.module_id: m for m in ALL_MODULES
}

__all__ = [
    "BaseModule",
    "DNSScannerModule",
    "CrtShScannerModule",
    "HTTPHeadersScannerModule",
    "RDAPScannerModule",
    "PortSurfaceScannerModule",
    "DueDiligenceModule",
    "ALL_MODULES",
    "MODULE_MAP",
]
