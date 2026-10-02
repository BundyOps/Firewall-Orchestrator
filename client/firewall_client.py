"""
client/firewall_client.py
-------------------------
Simple CLI client for the FirewallService.
"""
from __future__ import annotations

import sys

import grpc

#sys.path.insert(0, ".")
from generated import firewall_pb2, firewall_pb2_grpc  # noqa: E402


# import sys, os
# SERVER_DIR = os.path.abspath(
#     os.path.join(os.path.dirname(__file__), "..", "server")
# )
# sys.path.insert(0, SERVER_DIR)

# import firewall_pb2          # noqa: E402
# import firewall_pb2_grpc     # noqa: E402

def _print_rule(r: firewall_pb2.Rule) -> None:
    print(
        f"[{r.id[:8]}] chain={firewall_pb2.Chain.Name(r.chain):<7} "
        f"proto={firewall_pb2.Protocol.Name(r.protocol):<7} "
        f"src={r.source:<18} dst={r.destination:<18} "
        f"port={r.port:<5} action={firewall_pb2.Action.Name(r.action):<7} "
        f"comment={r.comment}"
    )


def main():
    channel = grpc.insecure_channel("localhost:50051")
    stub = firewall_pb2_grpc.FirewallServiceStub(channel)

    # 1) Add a rule
    add_resp = stub.AddRule(
        firewall_pb2.AddRuleRequest(
            rule=firewall_pb2.Rule(
                chain=firewall_pb2.INPUT,
                protocol=firewall_pb2.TCP,
                source="203.0.113.0/24",
                destination="",
                port=22,
                action=firewall_pb2.DROP,
                comment="block ssh from testnet",
            )
        )
    )
    print("Added:", add_resp.rule.id)

    # # 2) Apply a rate limit
    # rl_resp = stub.ApplyRateLimit(
    #     firewall_pb2.RateLimitRequest(
    #         target="198.51.100.0/24",
    #         rate=50,
    #         unit="second",
    #         action=firewall_pb2.DROP,
    #         chain=firewall_pb2.INPUT,
    #         protocol=firewall_pb2.TCP,
    #         port=80,
    #         comment="rate-limit web flood",
    #     )
    # )
    # print("Rate-limit rule:", rl_resp.rule.id)

    # 3) List rules
    print("\n--- Current rules ---")
    for r in stub.ListRules(firewall_pb2.ListRulesRequest()).rules:
        _print_rule(r)

    # # 4) Remove the first rule
    # stub.RemoveRule(firewall_pb2.RemoveRuleRequest(id=add_resp.rule.id))
    # print("\nRemoved:", add_resp.rule.id)

    # # 5) List again
    # print("\n--- After removal ---")
    # for r in stub.ListRules(firewall_pb2.ListRulesRequest()).rules:
    #     _print_rule(r)


if __name__ == "__main__":
    main()
