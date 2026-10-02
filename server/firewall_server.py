"""
server/firewall_server.py
-------------------------
gRPC server exposing the FirewallService.
"""
from __future__ import annotations

import logging
import signal
import sys
import time
from concurrent import futures
from queue import Queue
from typing import Dict, List

import grpc

# Adjust import path if you run this as a package
#sys.path.insert(0, ".")
from generated import firewall_pb2, firewall_pb2_grpc  # noqa: E402



# import os, sys
# sys.path.insert(0, os.path.dirname(__file__))

# import firewall_pb2
# import firewall_pb2_grpc

from server.rule_manager import (  # noqa: E402
    ACTION_NAMES,
    CHAIN_NAMES,
    PROTO_NAMES,
    RuleError,
    RuleManager,
    RuleNotFound,
    RuleRecord,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("firewall.server")


# ---------------------------------------------------------------------------
# Helpers for enum <-> string conversion
# ---------------------------------------------------------------------------
def _action_to_str(v: int) -> str:
    return ACTION_NAMES.get(v, "DROP")


def _proto_to_str(v: int) -> str:
    return PROTO_NAMES.get(v, "all")


def _chain_to_str(v: int) -> str:
    return CHAIN_NAMES.get(v, "INPUT")


def _str_to_action(s: str) -> int:
    inv = {v: k for k, v in ACTION_NAMES.items()}
    return inv.get(s.upper(), 2)  # default DROP


def _str_to_proto(s: str) -> int:
    inv = {v: k for k, v in PROTO_NAMES.items()}
    return inv.get(s.lower(), 4)  # default ALL


def _str_to_chain(s: str) -> int:
    inv = {v: k for k, v in CHAIN_NAMES.items()}
    return inv.get(s.upper(), 1)  # default INPUT


def _record_to_pb(rec: RuleRecord) -> firewall_pb2.Rule:
    return firewall_pb2.Rule(
        id=rec.id,
        chain=_str_to_chain(rec.chain),
        protocol=_str_to_proto(rec.protocol),
        source=rec.source,
        destination=rec.destination,
        port=rec.port,
        action=_str_to_action(rec.action),
        comment=rec.comment,
    )


# ---------------------------------------------------------------------------
# Servicer
# ---------------------------------------------------------------------------
class FirewallServicer(firewall_pb2_grpc.FirewallServiceServicer):
    def __init__(self, manager: RuleManager):
        self._mgr = manager
        # per-watcher queues for streaming updates
        self._watchers: List[Queue] = []
        self._watchers_lock = __import__("threading").Lock()

    # --------------------------------------------------------------- watchers
    def _broadcast(self, event_type: int, rec: RuleRecord) -> None:
        evt = firewall_pb2.WatchEvent(
            type=event_type, rule=_record_to_pb(rec)
        )
        with self._watchers_lock:
            for q in list(self._watchers):
                q.put(evt)

    # --------------------------------------------------------------- unary RPC
    def AddRule(self, request, context):
        r = request.rule
        try:
            rec = self._mgr.add_rule(
                chain=_chain_to_str(r.chain),
                protocol=_proto_to_str(r.protocol),
                source=r.source,
                destination=r.destination,
                port=r.port,
                action=_action_to_str(r.action),
                comment=r.comment,
            )
        except RuleError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
        self._broadcast(firewall_pb2.WatchEvent.ADDED, rec)
        return firewall_pb2.AddRuleResponse(rule=_record_to_pb(rec))

    def RemoveRule(self, request, context):
        try:
            self._mgr.remove_rule(request.id)
            return firewall_pb2.RemoveRuleResponse(removed=True)
        except RuleNotFound:
            context.abort(grpc.StatusCode.NOT_FOUND, f"rule {request.id}")
        except RuleError as exc:
            context.abort(grpc.StatusCode.INTERNAL, str(exc))

    def ListRules(self, request, context):
        chain = None
        if request.chain != firewall_pb2.CHAIN_UNSPECIFIED:
            chain = _chain_to_str(request.chain)
        rules = self._mgr.list_rules(chain)
        return firewall_pb2.ListRulesResponse(
            rules=[_record_to_pb(r) for r in rules]
        )

    def ApplyRateLimit(self, request, context):
        try:
            rec = self._mgr.apply_rate_limit(
                target=request.target,
                rate=request.rate,
                unit=request.unit or "second",
                action=_action_to_str(request.action),
                chain=_chain_to_str(request.chain or firewall_pb2.INPUT),
                protocol=_proto_to_str(request.protocol),
                port=request.port,
                comment=request.comment,
            )
        except RuleError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
        self._broadcast(firewall_pb2.WatchEvent.ADDED, rec)
        return firewall_pb2.RateLimitResponse(rule=_record_to_pb(rec))

    # ------------------------------------------------------------- streaming
    def WatchRules(self, request, context):
        q: Queue = Queue()
        with self._watchers_lock:
            self._watchers.append(q)
        logger.info("Watcher connected (chain filter=%s)", request.chain)
        try:
            # Send existing rules first
            chain = None
            if request.chain != firewall_pb2.CHAIN_UNSPECIFIED:
                chain = _chain_to_str(request.chain)
            for rec in self._mgr.list_rules(chain):
                yield firewall_pb2.WatchEvent(
                    type=firewall_pb2.WatchEvent.ADDED,
                    rule=_record_to_pb(rec),
                )
            while context.is_active():
                try:
                    evt = q.get(timeout=1.0)
                    yield evt
                except Exception:
                    continue
        finally:
            with self._watchers_lock:
                self._watchers.remove(q)
            logger.info("Watcher disconnected")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def serve(host: str = "[::]", port: int = 50051, dry_run: bool = False):
    mgr = RuleManager(dry_run=dry_run)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    firewall_pb2_grpc.add_FirewallServiceServicer_to_server(
        FirewallServicer(mgr), server
    )
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    logger.info("Firewall gRPC server listening on %s:%d (dry_run=%s)",
                host, port, dry_run)

    def _shutdown(signum, _frame):
        logger.info("Shutting down (signal %s)...", signum)
        server.stop(grace=2).wait()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    server.wait_for_termination()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="[::]")
    parser.add_argument("--port", type=int, default=50051)
    parser.add_argument("--dry-run", action="store_true",
                        help="Do not actually call iptables")
    args = parser.parse_args()
    serve(args.host, args.port, args.dry_run)
