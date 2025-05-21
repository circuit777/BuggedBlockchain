from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from threading import RLock
import ipaddress

app = Flask(__name__)

# Dictionary: node address -> last ping time
nodes = {}
lock = RLock()

# Time-to-live for node records (remove if not pinged within this time)
NODE_TTL = timedelta(minutes=5)  # 5 minutes

def is_public_ip(ip_str):
    """Check if the IP address is public (not private, loopback, or reserved)."""
    try:
        ip = ipaddress.ip_address(ip_str.split(':')[0])  # Extract IP from ip:port
        return not (ip.is_private or ip.is_loopback or ip.is_reserved)
    except ValueError:
        return False

def prune_dead_nodes():
    """Remove nodes that haven't pinged within NODE_TTL."""
    now = datetime.utcnow()
    with lock:
        to_delete = [addr for addr, ts in nodes.items() if now - ts > NODE_TTL]
        for addr in to_delete:
            del nodes[addr]

@app.route('/nodes', methods=['GET'])
def register_and_list():
    """
    Register a node if address is provided and is a public IP.
    Always return the list of active nodes.
    GET /nodes?address=ip:port or simply /nodes
    """
    addr = request.args.get('address')
    now = datetime.utcnow()

    with lock:
        if addr:
            if not is_public_ip(addr):
                return jsonify({'error': 'Only public IP addresses are allowed'}), 400
            nodes[addr] = now
        prune_dead_nodes()
        current_nodes = list(nodes.keys())

    # Return empty JSON if no active nodes
    if not current_nodes:
        return jsonify({}), 200

    return jsonify({'nodes': current_nodes}), 200

if __name__ == '__main__':
    # Run on all interfaces, port 5000
    app.run(host='0.0.0.0', port=5000)
