import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.offsetbox import OffsetImage, AnnotationBbox

# Function to load and scale images
def load_icon(path, zoom=0.1):
    return OffsetImage(plt.imread(path), zoom=zoom)

def draw_topology_with_controller():
    # Create a graph
    G = nx.Graph()

    # Add switches, hosts, and the controller as nodes
    switches = [f's{i}' for i in range(1, 7)]
    hosts = [f'h{i}' for i in range(1, 19)]
    controller = 'controller'
    G.add_nodes_from(switches, type='switch')
    G.add_nodes_from(hosts, type='host')
    G.add_node(controller, type='controller')

    # Add edges (links)
    links = [
        ('h1', 's1'), ('h2', 's1'), ('h3', 's1'),
        ('h4', 's2'), ('h5', 's2'), ('h6', 's2'),
        ('h7', 's3'), ('h8', 's3'), ('h9', 's3'),
        ('h10', 's4'), ('h11', 's4'), ('h12', 's4'),
        ('h13', 's5'), ('h14', 's5'), ('h15', 's5'),
        ('h16', 's6'), ('h17', 's6'), ('h18', 's6'),
        ('s1', 's2'), ('s2', 's3'), ('s3', 's4'), ('s4', 's5'), ('s5', 's6')
    ]

    # Add controller connections to all switches
    controller_links = [(controller, switch) for switch in switches]
    G.add_edges_from(links + controller_links)

    # Define layout
    pos = nx.spring_layout(G, seed=42)  # Fixed seed for consistent layout

    # Create a Matplotlib figure
    fig, ax = plt.subplots(figsize=(14, 10))

    # Draw edges
    nx.draw_networkx_edges(G, pos, edgelist=links, width=1.5, alpha=0.7, ax=ax)
    nx.draw_networkx_edges(G, pos, edgelist=controller_links, width=1.0, alpha=0.5, style='dashed', ax=ax, edge_color='red')

    # Add custom icons for nodes
    for node, (x, y) in pos.items():
        if node == 'controller':  # SDN Controller
            icon = load_icon('controller_icon.png', zoom=0.12)  # Path to controller icon
        elif node.startswith('s'):  # Switches
            icon = load_icon('switch_icon.png', zoom=0.08)  # Path to switch icon
        else:  # Hosts
            icon = load_icon('host_icon.png', zoom=0.1)  # Path to host icon
        ab = AnnotationBbox(icon, (x, y), frameon=False)
        ax.add_artist(ab)

    # Add labels
    for node, (x, y) in pos.items():
        if node.startswith('h'):  # Host labels (offset below the icon)
            plt.text(x, y, node, fontsize=9, color="white", ha='center', va='center')
        elif node.startswith('s'):  # Switch labels (above the icon)
            plt.text(x, y, node, fontsize=9, color="black", ha='center', va='center')
        elif node == 'controller':  # Controller label (under the icon)
            plt.text(x, y - 0.15, node, fontsize=10, color="green", ha='center', va='center', fontweight='bold')

    # Final adjustments
    plt.title("Network Topology with SDN Controller", fontsize=16)
    plt.axis('off')
    plt.show()

if __name__ == "__main__":
    draw_topology_with_controller()
