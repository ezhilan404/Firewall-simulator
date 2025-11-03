# -*- coding: utf-8 -*-
import json
import sys
import matplotlib.pyplot as plt

# Ensure UTF-8 output
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

RULES_FILE = "rules.json"
PACKETS_FILE = "packets.json"
LOG_FILE = "firewall_log.json"


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


# -------------------------------
# Visualization
# -------------------------------
def visualize(results):
    sources = list({res["packet"]["src"] for res in results})
    destinations = list({res["packet"]["dst"] for res in results})

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, max(len(sources), len(destinations)) + 1)
    ax.axis('off')

    # Position sources and destinations
    src_positions = {ip: (1, i+1) for i, ip in enumerate(sources)}
    dst_positions = {ip: (9, i+1) for i, ip in enumerate(destinations)}

    # Draw nodes
    for ip, (x, y) in src_positions.items():
        ax.text(x, y, ip, ha='center', va='center', bbox=dict(facecolor='lightblue', boxstyle="round,pad=0.3"))

    for ip, (x, y) in dst_positions.items():
        ax.text(x, y, ip, ha='center', va='center', bbox=dict(facecolor='lightgreen', boxstyle="round,pad=0.3"))

    # Draw arrows for each packet
    for res in results:
        pkt = res["packet"]
        action = res["action"]
        src = pkt["src"]
        dst = pkt["dst"]

        start = src_positions[src]
        end = dst_positions[dst]

        color = 'green' if action.upper() == 'ALLOW' else 'red'
        ax.annotate("",
                    xy=end, xycoords='data',
                    xytext=start, textcoords='data',
                    arrowprops=dict(arrowstyle="->", color=color, lw=2))

        # Optional: write port/protocol along the arrow
        mid_x = (start[0] + end[0]) / 2
        mid_y = (start[1] + end[1]) / 2
        ax.text(mid_x, mid_y, f"{pkt['port']}/{pkt['protocol']}", ha='center', va='bottom', fontsize=8)

    plt.title("Firewall Packet Flow Simulation")
    plt.show()


# -------------------------------
# Main Program
# -------------------------------
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

    # Visualize packet flow
    visualize(results)


if __name__ == "__main__":
    main()
