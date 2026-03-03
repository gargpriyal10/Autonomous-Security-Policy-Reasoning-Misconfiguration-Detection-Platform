import networkx as nx
from pyvis.network import Network


# ---------------- BUILD GRAPH ----------------
def build_graph(rules):

    G = nx.DiGraph()
    G.add_node("COMPROMISED_ROLE")

    for rule in rules:
        action = str(rule.get("Action"))
        resource = str(rule.get("Resource"))

        service = action.split(":")[0] if ":" in action else action

        G.add_edge("COMPROMISED_ROLE", service)
        G.add_edge(service, action)
        G.add_edge(action, resource)

    return G


# ---------------- VISUALIZE GRAPH ----------------
def visualize_graph(G):

    import streamlit.components.v1 as components

    net = Network(height="600px", width="100%", directed=True)

    for node in G.nodes():
        net.add_node(node)

    for edge in G.edges():
        net.add_edge(edge[0], edge[1])

    html_content = net.generate_html()
    components.html(html_content, height=600)


# ---------------- ATTACK PATH SIMULATION ----------------
def simulate_attack_paths(G):

    paths = []

    for node in G.nodes():
        if node != "COMPROMISED_ROLE":
            try:
                path = nx.shortest_path(G, "COMPROMISED_ROLE", node)
                if len(path) > 1:
                    paths.append(path)
            except:
                pass

    return paths