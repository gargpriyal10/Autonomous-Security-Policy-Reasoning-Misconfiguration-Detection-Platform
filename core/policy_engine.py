from detector.misconfig_detector import (
    detect_misconfigurations,
    generate_ai_explanation,
    generate_recommendations
)

from graph.policy_graph import (
    build_graph,
    simulate_attack_paths
)


def analyze_policy(rules):

    issues, risk_score = detect_misconfigurations(rules)
    ai_text = generate_ai_explanation(issues)
    recs = generate_recommendations(issues)
    G = build_graph(rules)
    attack_paths = simulate_attack_paths(G)

    return {
        "issues": issues,
        "risk_score": risk_score,
        "ai_text": ai_text,
        "recommendations": recs,
        "graph": G,
        "attack_paths": attack_paths
    }