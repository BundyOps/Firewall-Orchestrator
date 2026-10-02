"""
server/rule_manager.py
----------------------
Encapsulates iptables operations and an in-memory rule registry.
"""
from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class RuleError(Exception):
    """Raised on invalid input or iptables failure."""


class RuleNotFound(RuleError):
    pass


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
CHAIN_NAMES = {1: "INPUT", 2: "OUTPUT", 3: "FORWARD"}
PROTO_NAMES = {1: "tcp", 2: "udp", 3: "icmp", 4: "all"}
ACTION_NAMES = {1: "ACCEPT", 2: "DROP", 3: "REJECT"}


@dataclass
class RuleRecord:
    id: str
    chain: str
    protocol: str
    source: str
    destination: str
    port: int
    action: str
    comment: str = ""
    # The exact argv (minus "iptables") we used to insert the rule,
    # so we can delete it later reliably.
    iptables_args: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------
class RuleManager:
    """
    Thread-safe manager that owns the authoritative list of rules and
    executes iptables commands.
    """

    def __init__(self, dry_run: bool = False):
        self._lock = threading.RLock()
        self._rules: Dict[str, RuleRecord] = {}
        self._dry_run = dry_run

        if shutil.which("iptables") is None and not dry_run:
            raise RuntimeError(
                "iptables binary not found. Run with dry_run=True for testing."
            )

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _validate_cidr(cidr: str) -> str:
        """Empty string -> '0.0.0.0/0'. Otherwise validate as network."""
        if not cidr:
            return "0.0.0.0/0"
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            return str(net)
        except ValueError as exc:
            raise RuleError(f"Invalid CIDR '{cidr}': {exc}") from exc

    def _run_iptables(self, args: List[str]) -> str:
        """Execute iptables (or log if dry_run)."""
        cmd = ["iptables"] + args
        logger.info("exec: %s", " ".join(cmd))
        if self._dry_run:
            return ""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True, timeout=10
            )
            return result.stdout
        except subprocess.CalledProcessError as exc:
            raise RuleError(
                f"iptables failed: {exc.stderr.strip() or exc}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuleError("iptables timed out") from exc

    # ------------------------------------------------------------------ rules
    def add_rule(
        self,
        chain: str,
        protocol: str,
        source: str,
        destination: str,
        port: int,
        action: str,
        comment: str = "",
        extra_args: Optional[List[str]] = None,
    ) -> RuleRecord:
        with self._lock:
            chain = chain.upper()
            protocol = protocol.lower()
            action = action.upper()

            if chain not in ("INPUT", "OUTPUT", "FORWARD"):
                raise RuleError(f"Unknown chain {chain}")
            if protocol not in ("tcp", "udp", "icmp", "all"):
                raise RuleError(f"Unknown protocol {protocol}")
            if action not in ("ACCEPT", "DROP", "REJECT"):
                raise RuleError(f"Unknown action {action}")

            src = self._validate_cidr(source)
            dst = self._validate_cidr(destination)

            args: List[str] = ["-A", chain]
            if protocol != "all":
                args += ["-p", protocol]
            args += ["-s", src, "-d", dst]
            if port and protocol in ("tcp", "udp"):
                args += ["--dport", str(port)]
            if comment:
                args += ["-m", "comment", "--comment", comment]
            if extra_args:
                args += extra_args
            args += ["-j", action]

            self._run_iptables(args)

            rec = RuleRecord(
                id=str(uuid.uuid4()),
                chain=chain,
                protocol=protocol,
                source=src,
                destination=dst,
                port=port,
                action=action,
                comment=comment,
                iptables_args=args,
            )
            self._rules[rec.id] = rec
            return rec

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            rec = self._rules.get(rule_id)
            if rec is None:
                raise RuleNotFound(rule_id)

            # Convert -A (append) -> -D (delete)
            del_args = list(rec.iptables_args)
            del_args[0] = "-D"
            self._run_iptables(del_args)

            del self._rules[rule_id]
            return True

    def list_rules(self, chain: Optional[str] = None) -> List[RuleRecord]:
        with self._lock:
            if chain and chain.upper() != "CHAIN_UNSPECIFIED":
                c = chain.upper()
                return [r for r in self._rules.values() if r.chain == c]
            return list(self._rules.values())

    # ------------------------------------------------------------ rate limiting
    def apply_rate_limit(
        self,
        target: str,
        rate: int,
        unit: str,
        action: str,
        chain: str,
        protocol: str = "all",
        port: int = 0,
        comment: str = "",
    ) -> RuleRecord:
        """
        Uses iptables' `hashlimit` module to enforce per-source rate limiting.

        Example emitted rule:
          iptables -A INPUT -s 10.0.0.5 -p tcp --dport 22 \
            -m hashlimit --hashlimit-above 10/second \
            --hashlimit-mode srcip --hashlimit-name rl_<id> \
            -j DROP
        """
        with self._lock:
            if rate <= 0:
                raise RuleError("rate must be > 0")
            unit = unit.lower()
            if unit not in ("second", "minute", "hour"):
                raise RuleError("unit must be second|minute|hour")

            chain = chain.upper()
            protocol = protocol.lower()
            action = action.upper()

            src = self._validate_cidr(target)
            rl_name = f"rl_{uuid.uuid4().hex[:8]}"

            args: List[str] = ["-A", chain, "-s", src]
            if protocol != "all":
                args += ["-p", protocol]
                if port:
                    args += ["--dport", str(port)]
            args += [
                "-m", "hashlimit",
                "--hashlimit-above", f"{rate}/{unit}",
                "--hashlimit-mode", "srcip",
                "--hashlimit-name", rl_name,
                "--hashlimit-burst", str(max(rate, 1)),
            ]
            if comment:
                args += ["-m", "comment", "--comment", comment]
            args += ["-j", action]

            self._run_iptables(args)

            rec = RuleRecord(
                id=str(uuid.uuid4()),
                chain=chain,
                protocol=protocol,
                source=src,
                destination="0.0.0.0/0",
                port=port,
                action=action,
                comment=comment or f"ratelimit {rate}/{unit}",
                iptables_args=args,
            )
            self._rules[rec.id] = rec
            return rec
