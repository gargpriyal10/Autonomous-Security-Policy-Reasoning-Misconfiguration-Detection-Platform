import networkx as nx


# ---------------- BUILD ATTACK GRAPH ----------------
def build_graph(rules):

    G = nx.DiGraph()

    # Entry point
    entry_node = "Internet User"
    G.add_node(entry_node, type="entry")

    for rule in rules:

        action = str(rule.get("Action", "")).lower()
        resource = str(rule.get("Resource", "*"))

        # ---------------- Identity Layer ----------------
        if "iam" in action:

            G.add_node("IAM Role", type="identity")
            G.add_edge(entry_node, "IAM Role", exploit="Assume Role")

        # ---------------- Privilege Escalation ----------------
        if (
            "passrole" in action
            or "attachrolepolicy" in action
            or "createpolicyversion" in action
            or "setdefaultpolicyversion" in action
        ):

            G.add_node("Privilege Escalation", type="exploit")
            G.add_edge(
                "IAM Role", "Privilege Escalation", exploit="Privilege Escalation"
            )

        # ---------------- Compute Layer ----------------
        if "ec2" in action:

            G.add_node("EC2 Instance", type="compute")
            G.add_edge(entry_node, "EC2 Instance", exploit="Access EC2")

        # ---------------- Storage Layer ----------------
        if "s3" in action:

            G.add_node("S3 Bucket", type="storage")

            if G.has_node("Privilege Escalation"):
                G.add_edge("Privilege Escalation", "S3 Bucket", exploit="Access S3")

            else:
                G.add_edge(entry_node, "S3 Bucket", exploit="Direct Access")

        # ---------------- Database Layer ----------------
        if "dynamodb" in action:

            G.add_node("DynamoDB", type="database")
            G.add_edge("Privilege Escalation", "DynamoDB", exploit="Database Access")

        # ---------------- Target Asset ----------------
        if resource == "*":

            G.add_node("Sensitive Data", type="target")

            if G.has_node("S3 Bucket"):
                G.add_edge("S3 Bucket", "Sensitive Data", exploit="Data Exfiltration")

            elif G.has_node("DynamoDB"):
                G.add_edge("DynamoDB", "Sensitive Data", exploit="Data Extraction")

    return G


# ---------------- SIMULATE ATTACK PATHS ----------------
def simulate_attack_paths(G):

    attack_paths = []

    entry_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "entry"]
    target_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "target"]

    for entry in entry_nodes:

        for target in target_nodes:

            if nx.has_path(G, entry, target):

                for path in nx.all_simple_paths(G, entry, target):

                    attack_paths.append(path)

    return attack_paths


# ---------------- CHOKE POINT DETECTION ----------------
def find_choke_points(G):

    centrality = nx.betweenness_centrality(G)

    choke_points = sorted(centrality.items(), key=lambda x: x[1], reverse=True)

    return choke_points[:3]


# ---------------- GRAPH METADATA ----------------
def graph_metadata(G):

    metadata = []

    for node, data in G.nodes(data=True):

        metadata.append({"node": node, "type": data.get("type", "unknown")})

    return metadata
