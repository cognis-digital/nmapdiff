"""Core engine for nmapdiff.

Parses nmap XML output (``nmap -oX``) into a normalized model and computes a
structured diff between a baseline scan and a current scan. The diff highlights:

  * new / removed hosts
  * hosts whose up/down state changed
  * new / removed / changed open ports
  * service or version changes on an existing port

Everything here is pure, offline analysis built on the standard library only.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Service:
    """A normalized service description for one open port."""

    name: str = ""
    product: str = ""
    version: str = ""

    def label(self) -> str:
        parts = [p for p in (self.name, self.product, self.version) if p]
        return " ".join(parts) if parts else "unknown"


@dataclass(frozen=True)
class Port:
    """A single port observation (only open/filtered ports are tracked)."""

    portid: int
    protocol: str
    state: str
    service: Service = field(default_factory=Service)

    @property
    def key(self) -> Tuple[str, int]:
        return (self.protocol, self.portid)


@dataclass
class Host:
    """One host within a scan."""

    address: str
    status: str = "up"
    hostname: str = ""
    ports: Dict[Tuple[str, int], Port] = field(default_factory=dict)


@dataclass
class ScanReport:
    """A parsed scan: a collection of hosts keyed by address."""

    hosts: Dict[str, Host] = field(default_factory=dict)
    args: str = ""
    start: str = ""

    def open_port_count(self) -> int:
        return sum(
            1
            for h in self.hosts.values()
            for p in h.ports.values()
            if p.state == "open"
        )


# --------------------------------------------------------------------------- #
# Diff model
# --------------------------------------------------------------------------- #


@dataclass
class PortChange:
    address: str
    protocol: str
    portid: int
    kind: str  # "new_port" | "removed_port" | "service_change" | "state_change"
    before: Optional[str] = None
    after: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "protocol": self.protocol,
            "port": self.portid,
            "kind": self.kind,
            "before": self.before,
            "after": self.after,
        }


@dataclass
class HostDiff:
    address: str
    kind: str  # "new_host" | "removed_host" | "state_change"
    before: Optional[str] = None
    after: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "kind": self.kind,
            "before": self.before,
            "after": self.after,
        }


@dataclass
class Diff:
    host_changes: List[HostDiff] = field(default_factory=list)
    port_changes: List[PortChange] = field(default_factory=list)

    def has_findings(self) -> bool:
        return bool(self.host_changes or self.port_changes)

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "host_changes": [h.to_dict() for h in self.host_changes],
            "port_changes": [p.to_dict() for p in self.port_changes],
        }

    def summary(self) -> dict:
        counts: Dict[str, int] = {}
        for h in self.host_changes:
            counts[h.kind] = counts.get(h.kind, 0) + 1
        for p in self.port_changes:
            counts[p.kind] = counts.get(p.kind, 0) + 1
        return {
            "total_findings": len(self.host_changes) + len(self.port_changes),
            "by_kind": counts,
        }


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


_OPEN_STATES = {"open", "open|filtered"}


def _parse_service(port_el: ET.Element) -> Service:
    svc = port_el.find("service")
    if svc is None:
        return Service()
    return Service(
        name=svc.get("name", "") or "",
        product=svc.get("product", "") or "",
        version=svc.get("version", "") or "",
    )


def _host_address(host_el: ET.Element) -> str:
    # Prefer IPv4/IPv6, fall back to MAC.
    addr_fallback = ""
    for addr in host_el.findall("address"):
        atype = addr.get("addrtype", "")
        value = addr.get("addr", "")
        if atype in ("ipv4", "ipv6") and value:
            return value
        if value and not addr_fallback:
            addr_fallback = value
    return addr_fallback


def _host_name(host_el: ET.Element) -> str:
    hostnames = host_el.find("hostnames")
    if hostnames is None:
        return ""
    hn = hostnames.find("hostname")
    return hn.get("name", "") if hn is not None else ""


def parse_scan(xml_text: str) -> ScanReport:
    """Parse nmap XML text into a :class:`ScanReport`.

    Raises ``ValueError`` if the document is not recognizable nmap XML.
    """

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise ValueError(
            f"not an nmap XML document (root element <{root.tag}>, expected <nmaprun>)"
        )

    report = ScanReport(args=root.get("args", ""), start=root.get("startstr", ""))

    for host_el in root.findall("host"):
        address = _host_address(host_el)
        if not address:
            continue

        status_el = host_el.find("status")
        status = status_el.get("state", "up") if status_el is not None else "up"

        host = Host(address=address, status=status, hostname=_host_name(host_el))

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                try:
                    portid = int(port_el.get("portid", ""))
                except (TypeError, ValueError):
                    continue
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                # Track only open / open|filtered ports — those are the
                # security-relevant surface for change detection.
                if state not in _OPEN_STATES:
                    continue
                port = Port(
                    portid=portid,
                    protocol=protocol,
                    state=state,
                    service=_parse_service(port_el),
                )
                host.ports[port.key] = port

        report.hosts[address] = host

    return report


def parse_scan_file(path: str) -> ScanReport:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_scan(fh.read())


# --------------------------------------------------------------------------- #
# Diff engine
# --------------------------------------------------------------------------- #


def diff_scans(baseline: ScanReport, current: ScanReport) -> Diff:
    """Compute the change set from ``baseline`` to ``current``."""

    diff = Diff()

    base_addrs = set(baseline.hosts)
    cur_addrs = set(current.hosts)

    # Host-level changes.
    for addr in sorted(cur_addrs - base_addrs):
        diff.host_changes.append(HostDiff(address=addr, kind="new_host"))
    for addr in sorted(base_addrs - cur_addrs):
        diff.host_changes.append(HostDiff(address=addr, kind="removed_host"))

    for addr in sorted(base_addrs & cur_addrs):
        b_host = baseline.hosts[addr]
        c_host = current.hosts[addr]
        if b_host.status != c_host.status:
            diff.host_changes.append(
                HostDiff(
                    address=addr,
                    kind="state_change",
                    before=b_host.status,
                    after=c_host.status,
                )
            )
        diff.port_changes.extend(_diff_ports(addr, b_host, c_host))

    # Ports on brand-new hosts are surfaced as new_port findings too.
    for addr in sorted(cur_addrs - base_addrs):
        c_host = current.hosts[addr]
        for key in sorted(c_host.ports):
            port = c_host.ports[key]
            diff.port_changes.append(
                PortChange(
                    address=addr,
                    protocol=port.protocol,
                    portid=port.portid,
                    kind="new_port",
                    after=port.service.label(),
                )
            )

    return diff


def _diff_ports(addr: str, b_host: Host, c_host: Host) -> List[PortChange]:
    changes: List[PortChange] = []
    b_keys = set(b_host.ports)
    c_keys = set(c_host.ports)

    for key in sorted(c_keys - b_keys):
        port = c_host.ports[key]
        changes.append(
            PortChange(
                address=addr,
                protocol=port.protocol,
                portid=port.portid,
                kind="new_port",
                after=port.service.label(),
            )
        )

    for key in sorted(b_keys - c_keys):
        port = b_host.ports[key]
        changes.append(
            PortChange(
                address=addr,
                protocol=port.protocol,
                portid=port.portid,
                kind="removed_port",
                before=port.service.label(),
            )
        )

    for key in sorted(b_keys & c_keys):
        b_port = b_host.ports[key]
        c_port = c_host.ports[key]
        if b_port.state != c_port.state:
            changes.append(
                PortChange(
                    address=addr,
                    protocol=c_port.protocol,
                    portid=c_port.portid,
                    kind="state_change",
                    before=b_port.state,
                    after=c_port.state,
                )
            )
        b_label = b_port.service.label()
        c_label = c_port.service.label()
        if b_label != c_label:
            changes.append(
                PortChange(
                    address=addr,
                    protocol=c_port.protocol,
                    portid=c_port.portid,
                    kind="service_change",
                    before=b_label,
                    after=c_label,
                )
            )

    return changes
