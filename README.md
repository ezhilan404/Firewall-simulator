# Firewall Simulator

A Python-based firewall simulation tool that applies rule-based filtering to network packets.  
The system reads packet data and firewall rules from JSON files, processes them, and generates decision logs showing which packets were allowed or blocked.

This project was built to understand how real firewalls evaluate traffic, how rule priority affects outcomes, and how packet inspection is performed in a security environment.

---

## 🔍 Overview

The simulator processes incoming network packets loaded from `packets.json` and evaluates them against a rule set defined in `rules.json`.  
Each packet is inspected based on source/destination IP, port, and protocol, and a decision is logged as either **ALLOW** or **DENY**.

Final results are written to `firewall_logs.json`, which contains the decision history for analysis and visualization.

---

## 🧠 Features

- JSON-based rule definition and packet input
- Simulates real firewall logic:
  - Rule matching
  - Default deny behavior
  - Protocol & port filtering
- Outputs detailed logs of each decision
- Helps visualize packet filtering behavior

---

## 🧱 Tech Stack

| Component | Usage |
|-----------|--------|
| **Python** | Core simulation engine |
| **JSON** | Stores packet definitions, rules, and logs |
| **Networking concepts** | Port filtering, rule ordering, packet analysis |

---

