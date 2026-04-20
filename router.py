
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
from typing import Any


PROTOCOL_VERSION = 1.0
PORT = int(os.getenv("PORT", "5000"))
INFINITY = int(os.getenv("INFINITY", "16"))
BROADCAST_INTERVAL = float(os.getenv("BROADCAST_INTERVAL", "2"))
NEIGHBOR_DEAD_INTERVAL = float(os.getenv("NEIGHBOR_DEAD_INTERVAL", "9"))

MY_IP = os.getenv("MY_IP", "127.0.0.1")
NEIGHBORS = [n.strip() for n in os.getenv("NEIGHBORS", "").split(",") if n.strip()]
DIRECT_SUBNETS_ENV = [s.strip() for s in os.getenv("DIRECT_SUBNETS", "").split(",") if s.strip()]

DIRECT_SOURCE = "direct"
NEIGHBOR_SOURCE = "neighbor"
DIRECT_NEXT_HOP = "0.0.0.0"

RouteEntry = dict[str, Any]
RoutingTable = dict[str, RouteEntry]
NeighborState = dict[str, Any]

routing_table: RoutingTable = {}
neighbor_tables: dict[str, NeighborState] = {}
state_lock = threading.Lock()


def log(msg):
    """Print a simple timestamped log line."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def run_ip_route(args: list[str]) -> None:
    """Run an `ip route` command and keep going if it fails."""
    result = subprocess.run(
        ["ip", "route", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        err = result.stderr.strip() or result.stdout.strip() or "unknown error"
        log(f"ip route {' '.join(args)} failed: {err}")


def normalize_subnet(value: str) -> str | None:
    """Return a normalized CIDR string, or `None` if the input is invalid."""
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def make_route(distance: int, next_hop: str, source: str) -> RouteEntry:
    """Create a routing-table entry in one place."""
    return {
        "distance": distance,
        "next_hop": next_hop,
        "source": source,
    }


def route_learned_from_neighbor(entry: RouteEntry | None) -> bool:
    """Tell whether a route came from a neighbor update."""
    return bool(entry and entry["source"] == NEIGHBOR_SOURCE)


def discover_direct_subnets() -> set[str]:
    """Collect directly connected IPv4 subnets from interfaces and env vars."""
    discovered = set()

    try:
        output = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            text=True,
        )
        for line in output.splitlines():
            parts = line.split()
            if "inet" not in parts:
                continue
            cidr = parts[parts.index("inet") + 1]
            network = ipaddress.ip_interface(cidr).network
            discovered.add(str(network))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        log(f"Could not auto-discover subnets from interfaces: {exc}")

    for subnet in DIRECT_SUBNETS_ENV:
        normalized = normalize_subnet(subnet)
        if normalized is None:
            log(f"Ignoring invalid DIRECT_SUBNETS entry: {subnet}")
            continue
        discovered.add(normalized)

    return discovered


def direct_route_entries() -> RoutingTable:
    """Build route entries for the networks attached to this router."""
    entries: RoutingTable = {}
    for subnet in sorted(discover_direct_subnets()):
        entries[subnet] = make_route(0, DIRECT_NEXT_HOP, DIRECT_SOURCE)
    return entries


def init_routing_table() -> None:
    """Start the routing table with directly connected networks."""
    direct_entries = direct_route_entries()
    if not direct_entries:
        log("No direct subnets discovered. Set DIRECT_SUBNETS env var if needed.")

    with state_lock:
        routing_table.clear()
        routing_table.update(direct_entries)

    log(f"Router started with MY_IP={MY_IP}, neighbors={NEIGHBORS}")
    log(f"Direct subnets: {sorted(direct_entries)}")


def validate_packet(packet: dict[str, Any]) -> bool:
    """Check that an incoming packet looks like one of our DV updates."""
    return (
        isinstance(packet, dict)
        and packet.get("version") == PROTOCOL_VERSION
        and isinstance(packet.get("routes"), list)
    )


def parse_routes(routes: list[dict[str, Any]]) -> dict[str, int]:
    """Turn raw packet routes into validated subnet-to-distance pairs."""
    cleaned: dict[str, int] = {}

    for entry in routes:
        if not isinstance(entry, dict):
            continue

        subnet = entry.get("subnet")
        distance = entry.get("distance")

        if not isinstance(subnet, str):
            continue
        subnet = normalize_subnet(subnet)
        if subnet is None:
            continue

        try:
            distance = int(distance)
        except (ValueError, TypeError):
            continue

        cleaned[subnet] = max(0, min(distance, INFINITY))

    return cleaned


def build_packet(for_neighbor: str | None = None) -> dict[str, Any]:
    """Build the current distance vector, with poison reverse when needed."""
    with state_lock:
        packet_routes = []
        for subnet, entry in sorted(routing_table.items()):
            advertised_distance = entry["distance"]

            if (
                for_neighbor
                and entry["source"] == NEIGHBOR_SOURCE
                and entry["next_hop"] == for_neighbor
            ):
                # If we learned a route from this neighbor, do not offer it back.
                advertised_distance = INFINITY

            packet_routes.append(
                {
                    "subnet": subnet,
                    "distance": int(min(advertised_distance, INFINITY)),
                }
            )

    return {
        "router_id": MY_IP,
        "version": PROTOCOL_VERSION,
        "routes": packet_routes,
    }


def apply_kernel_route_changes(
    old_table: RoutingTable,
    new_table: RoutingTable,
) -> None:
    """Keep the kernel routing table in sync with the latest learned routes."""
    affected_subnets = set(old_table.keys()) | set(new_table.keys())

    for subnet in sorted(affected_subnets):
        old_entry = old_table.get(subnet)
        new_entry = new_table.get(subnet)

        old_is_dynamic = route_learned_from_neighbor(old_entry)
        new_is_dynamic = route_learned_from_neighbor(new_entry)

        if old_is_dynamic and not new_is_dynamic:
            run_ip_route(["del", subnet])
            log(f"Removed route {subnet}")
            continue

        if new_is_dynamic:
            should_replace = (
                not old_is_dynamic
                or old_entry["next_hop"] != new_entry["next_hop"]
                or old_entry["distance"] != new_entry["distance"]
            )
            if should_replace:
                run_ip_route(["replace", subnet, "via", new_entry["next_hop"]])
                log(
                    f"Route {subnet} via {new_entry['next_hop']} "
                    f"(distance {new_entry['distance']})"
                )


def recompute_routes_locked() -> None:
    """Rebuild the best routes from the latest live neighbor information."""
    old_table = dict(routing_table)

    # Re-check interfaces each round so late-attached Docker networks show up.
    new_table = direct_route_entries()

    for neighbor_ip in NEIGHBORS:
        neighbor_state = neighbor_tables.get(neighbor_ip)
        if not neighbor_state:
            continue

        age = time.time() - neighbor_state["last_seen"]
        if age > NEIGHBOR_DEAD_INTERVAL:
            continue

        for subnet, neighbor_distance in neighbor_state["routes"].items():
            if subnet in new_table:
                continue

            candidate = min(INFINITY, neighbor_distance + 1)
            if candidate >= INFINITY:
                continue

            current = new_table.get(subnet)
            if not current:
                new_table[subnet] = make_route(candidate, neighbor_ip, NEIGHBOR_SOURCE)
                continue

            better_distance = candidate < current["distance"]
            same_distance_better_tie = (
                candidate == current["distance"] and neighbor_ip < current["next_hop"]
            )
            if better_distance or same_distance_better_tie:
                new_table[subnet] = make_route(candidate, neighbor_ip, NEIGHBOR_SOURCE)

    apply_kernel_route_changes(old_table, new_table)
    routing_table.clear()
    routing_table.update(new_table)


def broadcast_updates() -> None:
    """Send the current distance vector to each neighbor every few seconds."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        for neighbor in NEIGHBORS:
            packet = build_packet(for_neighbor=neighbor)
            data = json.dumps(packet).encode("utf-8")
            try:
                sock.sendto(data, (neighbor, PORT))
            except OSError as exc:
                log(f"Failed sending update to {neighbor}: {exc}")

        time.sleep(BROADCAST_INTERVAL)


def listen_for_updates() -> None:
    """Listen for neighbor advertisements and fold them into local state."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    log(f"Listening for updates on UDP {PORT}")

    while True:
        data, addr = sock.recvfrom(65535)
        neighbor_ip = addr[0]

        if NEIGHBORS and neighbor_ip not in NEIGHBORS:
            continue

        try:
            packet = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            continue

        if not validate_packet(packet):
            continue

        routes = parse_routes(packet["routes"])

        with state_lock:
            neighbor_tables[neighbor_ip] = {
                "last_seen": time.time(),
                "routes": routes,
            }
            recompute_routes_locked()


def maintenance_loop() -> None:
    """Recompute routes in the background so timeouts can expire cleanly."""
    while True:
        with state_lock:
            recompute_routes_locked()
        time.sleep(1)


def format_routing_table() -> str:
    """Render the routing table in a readable multi-line format."""
    rows = []
    for subnet, entry in sorted(routing_table.items()):
        rows.append(
            f"{subnet:<18} dist={entry['distance']:<2} "
            f"next_hop={entry['next_hop']:<15} source={entry['source']}"
        )

    if not rows:
        return "Routing table: (empty)"

    return "Routing table:\n  " + "\n  ".join(rows)


def print_table_loop() -> None:
    """Print the current routing table at a fixed interval."""
    while True:
        with state_lock:
            table_snapshot = format_routing_table()
        log(table_snapshot)
        time.sleep(5)


def main() -> None:
    """Start the router and hand off work to the background threads."""
    init_routing_table()

    threading.Thread(target=broadcast_updates, daemon=True).start()
    threading.Thread(target=maintenance_loop, daemon=True).start()
    threading.Thread(target=print_table_loop, daemon=True).start()

    listen_for_updates()


if __name__ == "__main__":
    main()
