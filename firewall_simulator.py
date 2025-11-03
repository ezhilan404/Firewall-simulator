# -*- coding: utf-8 -*-
import json
import sys

# Ensure UTF-8 output
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

# -------------------------------
# Firewall Rule Simulator (Plain Version)
# -------------------------------

RULES_FILE = "rules.json"
PACKETS_FILE = "packets.json"
LOG_FILE = "firewall_log.json"


# --- Helper: Load JSON File ---
def load_json(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in {file_path}.")
        sys.exit(1)


# --- Match Logic ---
def match_field(value, pattern):
    if pattern == "*":
        return True
    if "*" in pattern:
        return value.startswith(pattern.split("*")[0])
    return value == pattern


def match_rule(packet, rule):
    return (match_field(packet["src"], rule["src"]) and
            match_field(packet["dst"], rule["dst"]) and
            match_field(packet["port"], rule["port"]) and
            match_field(packet["protocol"], rule["protocol"]))


# --- Apply Rules ---
def apply_firewall_rules(packets, rules):
    results = []
    for pkt in packets:
        for rule in rules:
            if match_rule(pkt, rule):
                results.append({
                    "packet": pkt,
                    "action": rule["action"],
                    "matched_rule": rule
                })
                break
    return results


# --- Main Program ---
def main():
    rules = load_json(RULES_FILE)
    packets = load_json(PACKETS_FILE)

    results = apply_firewall_rules(packets, rules)

    print("\n=== FIREWALL SIMULATION RESULTS ===\n")
    for res in results:
        pkt = res["packet"]
        act = res["action"]
        rule = res["matched_rule"]

        print(f"Packet: {pkt}")
        print(f"Matched Rule: {rule}")
        print(f"Action: {act}\n")

    # Save results to JSON log
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"Simulation results saved to {LOG_FILE}")


if __name__ == "__main__":
    main()

