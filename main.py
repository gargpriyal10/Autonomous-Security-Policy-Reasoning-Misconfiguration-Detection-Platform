from parser.policy_parser import load_policy, normalize_policy
from detector.misconfig_detector import detect_misconfigurations
from graph.policy_graph import build_graph, simulate_attack

file_path = "data/sample_policy.json"

policy = load_policy(file_path)
rules = normalize_policy(policy)

print("\nNormalized Rules:\n")
for r in rules:
    print(r)

# risk detection
issues = detect_misconfigurations(rules)

print("\nSecurity Issues Found:\n")
if not issues:
    print("No major misconfigurations detected")
else:
    for i in issues:
        print("Risk Level :", i["risk"])
        print("Problem    :", i["problem"])
        print("Reason     :", i["reason"])
        print("---------------------------")

# build graph
G = build_graph(rules)

print("\nGraph Created Successfully")
print("Nodes:", G.number_of_nodes())
print("Edges:", G.number_of_edges())

# simulate attack
simulate_attack(G)
