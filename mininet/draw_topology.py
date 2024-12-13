import networkx as nx
import matplotlib.pyplot as plt

def draw_topology():
    # Create a graph
    G = nx.Graph()

    # Add switches and hosts as nodes
    switches = [f's{i}' for i in range(1, 7)]
    hosts = [f'h{i}' for i in range(1, 19)]
    G.add_nodes_from(switches, type='switch')
    G.add_nodes_from(hosts, type='host')

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
    G.add_edges_from(links)

    # Define layout
    pos = nx.spring_layout(G)

    # Draw nodes and edges
    nx.draw_networkx_nodes(G, pos, nodelist=switches, node_color='lightblue', node_size=500, label='Switches')
    nx.draw_networkx_nodes(G, pos, nodelist=hosts, node_color='lightgreen', node_size=300, label='Hosts')
    nx.draw_networkx_edges(G, pos, edgelist=links, width=1.5, alpha=0.7)
    nx.draw_networkx_labels(G, pos, font_size=10, font_color='black')

    # Display the graph
    plt.title("Network Topology")
    plt.legend(["Switches", "Hosts"])
    plt.show()

if __name__ == "__main__":
    draw_topology()
