# Firewall-Orchestrator
A gRPC-based Firewall Orchestrator with Pluggable Policy Engines



no design pattern yet!!!!!!!!!!!

                       sudo ./venv/bin/python3 -m server.firewall_server
or just for test do:   python3 -m server.firewall_server --dry-run

then:                   python -m client.firewall_client

Watch live events with grpcurl: grpcurl -plaintext -d '{}' localhost:50051 firewall.FirewallService/WatchRules
