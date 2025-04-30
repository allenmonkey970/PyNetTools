import ipaddress

def find_subnets(network_address, new_prefix):
    """
    Generates all subnets of a given network with a specified prefix length.

    Args:
        network_address (str): The network address in CIDR notation (e.g., "192.168.1.0/24").
        new_prefix (int): The desired prefix length for the subnets (must be greater than the original prefix).

    Returns:
        list: A list of subnet objects.
    """
    network = ipaddress.ip_network(network_address)
    if new_prefix <= network.prefixlen:
        raise ValueError("New prefix must be greater than the original prefix.")

    subnets = list(network.subnets(new_prefix=new_prefix))
    return subnets

# Example usage:
network_address = "192.168.1.0/24"
new_prefix = 26
subnets = find_subnets(network_address, new_prefix)

for subnet in subnets:
    print(subnet)