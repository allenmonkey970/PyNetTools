import ipaddress


def find_subnets(network_address, new_prefix):
    """Generate all subnets of a given network with the specified prefix length."""
    network = ipaddress.ip_network(network_address)
    if new_prefix <= network.prefixlen:
        raise ValueError("New prefix must be greater than the original prefix.")
    return list(network.subnets(new_prefix=new_prefix))


if __name__ == "__main__":
    for subnet in find_subnets("192.168.1.0/24", 26):
        print(subnet)
