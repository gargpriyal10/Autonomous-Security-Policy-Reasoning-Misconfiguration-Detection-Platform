import networkx as nx
from pyvis.network import Network


def build_graph(rules):

    G = nx.DiGraph()

    G.add_node("COMPROMISED_ROLE", color="red")

    for rule in rules:
        action = str(rule.get("Action"))
        resource = str(rule.get("Resource"))

        service = action.split(":")[0] if ":" in action else action

        G.add_node(service, color="orange")
        G.add_node(action, color="blue")
        G.add_node(resource, color="green")

        G.add_edge("COMPROMISED_ROLE", service)
        G.add_edge(service, action)
        G.add_edge(action, resource)

    return G


def visualize_graph(G):

    from pyvis.network import Network
    import streamlit.components.v1 as components
    import tempfile
    import os

    net = Network(height="600px", width="100%", directed=True)

    for node in G.nodes():
        net.add_node(node)

    for edge in G.edges():
        net.add_edge(edge[0], edge[1])

    # Save to temporary file
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
    net.save_graph(tmp_file.name)

    # Read HTML content
    with open(tmp_file.name, "r", encoding="utf-8") as f:
        html_content = f.read()

    # Render inside Streamlit
    components.html(html_content, height=600)

    # Optional cleanup
    os.unlink(tmp_file.name)