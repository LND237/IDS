import socket

def get_domain_from_ip(ip_address):
    try:
        domain = socket.gethostbyaddr(ip_address)
        return domain[0]
    except socket.herror:
        return "Domain not found"

# Example usage
ip_address = "8.8.8.8"  # Replace this with the IP address you have
domain = get_domain_from_ip(ip_address)
print("Domain:", domain)
