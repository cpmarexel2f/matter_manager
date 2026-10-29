# SHA256 (Inhalt ab Zeile 2, d.h. dieser Datei ohne diese erste Zeile): e24299bf6554a1979be219da03f4608c5ba391c8b896ab1a577aa40050751178
"""Netzwerkkarte: Thread-, WLAN- und Ethernet-Topologie aus den Diagnose-Clustern.

Der Matter Server liefert für jedes Gerät die Netzwerk-Diagnose mit. Daraus baut dieses
Modul eine Näherung der Struktur, wie sie der Zigbee2MQTT Manager für Zigbee zeigt:

* Thread: Nachbartabellen (Cluster 53, Attribut 7) und Hardware-Adressen der Schnittstellen
  (Cluster 51, Attribut 0). Router hängen am besten Pfad zum Leader, Endgeräte am Router, der
  sie als Kind führt bzw. den sie selbst als Nachbarn mit dem besten Signal melden. Router,
  die nicht zu den eigenen Geräten gehören (z. B. Border Router von Apple oder Google),
  erscheinen als „externer Router“, wenn sie in einer Nachbartabelle auftauchen.
* WLAN: Gruppierung nach Access Point (BSSID, Cluster 54, Attribut 0) mit dem Signal
  (RSSI, Attribut 4) jedes Geräts.
* Ethernet: ein gemeinsamer Knoten „LAN“.

Es werden keine Anfragen an Geräte gestellt; die Funktion arbeitet nur mit dem, was der
Matter Server bereits kennt. Nicht an echter Hardware geprüft.
"""

from __future__ import annotations

import base64
import re
from collections import deque
from typing import Any

C_DESCRIPTOR = 29
C_GENERAL_DIAG = 51
C_THREAD = 53
C_WIFI = 54
C_ETHERNET = 55

_THREAD_ROUTER = 5
_THREAD_LEADER = 6
_IFACE_THREAD = 4  # InterfaceTypeEnum.Thread

_HEX16 = re.compile(r"^[0-9a-fA-F]{16}$")
_HEX12 = re.compile(r"^[0-9a-fA-F]{12}$")
_SEP8 = re.compile(r"^(?:[0-9a-fA-F]{2}[:\-]){7}[0-9a-fA-F]{2}$")
_SEP6 = re.compile(r"^(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _field(struct: Any, tag: int, *names: str) -> Any:
    """Feld einer Matter-Struktur lesen (Tag-Nummer als Schlüssel, ersatzweise Name)."""
    if not isinstance(struct, dict):
        return None
    for key in (str(tag), tag, *names):
        if key in struct:
            return struct[key]
    return None


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _bytes_of(value: Any, size: int) -> bytes | None:
    """Bytefolge der angegebenen Länge aus Hex, Base64, Trennzeichen-Text oder Liste lesen."""
    if isinstance(value, (bytes, bytearray)) and len(value) == size:
        return bytes(value)
    if isinstance(value, list) and len(value) == size and all(_int(v) is not None and 0 <= v < 256 for v in value):
        return bytes(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if size == 8 and _HEX16.match(text):
        return bytes.fromhex(text)
    if size == 6 and _HEX12.match(text):
        return bytes.fromhex(text)
    if (size == 8 and _SEP8.match(text)) or (size == 6 and _SEP6.match(text)):
        return bytes.fromhex(re.sub(r"[:\-]", "", text))
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        return None
    return raw if len(raw) == size else None


def ext_address(value: Any) -> int | None:
    """Erweiterte Thread-Adresse (EUI-64) als Zahl."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value if 0 <= value < 1 << 64 else None
    raw = _bytes_of(value, 8)
    return int.from_bytes(raw, "big") if raw is not None else None


def bssid_text(value: Any) -> str | None:
    """BSSID als „aa:bb:cc:dd:ee:ff“."""
    raw = _bytes_of(value, 6)
    return ":".join(f"{b:02x}" for b in raw) if raw is not None else None


def _hex16(ext: int) -> str:
    return f"{ext:016x}"


class _Node:
    """Lesezugriff auf die Attribute eines Knotens (Pfad „Endpunkt/Cluster/Attribut“)."""

    def __init__(self, node_id: int, node: dict[str, Any], name: str) -> None:
        attrs = node.get("attributes")
        self.attrs: dict[str, Any] = attrs if isinstance(attrs, dict) else {}
        self.node_id = node_id
        self.name = name
        self.available: bool | None = node.get("available") if "available" in node else None
        root = self.attrs.get("0/29/1")
        self.root_clusters: set[int] = {c for c in _as_list(root) if _int(c) is not None}

    def get(self, cluster: int, attribute: int) -> Any:
        return self.attrs.get(f"0/{cluster}/{attribute}")

    @property
    def device_id(self) -> str:
        return str(self.node_id)

    @property
    def network(self) -> str | None:
        if C_THREAD in self.root_clusters:
            return "thread"
        if C_WIFI in self.root_clusters:
            return "wifi"
        if C_ETHERNET in self.root_clusters:
            return "ethernet"
        return None


def _rssi_of(entry: Any) -> int | None:
    rssi = _int(_field(entry, 6, "averageRssi"))
    if rssi is None:
        rssi = _int(_field(entry, 7, "lastRssi"))
    return rssi if rssi is not None and rssi < 0 else None


def _thread_ext_of(node: _Node) -> int | None:
    """Eigene erweiterte Adresse: Hardware-Adresse der Thread-Schnittstelle (Cluster 51)."""
    for iface in _as_list(node.get(C_GENERAL_DIAG, 0)):
        if _int(_field(iface, 7, "type")) != _IFACE_THREAD:
            continue
        ext = ext_address(_field(iface, 4, "hardwareAddress"))
        if ext is not None:
            return ext
    return None


def build_thread(nodes: list[_Node]) -> dict[str, Any] | None:
    members = [n for n in nodes if n.network == "thread"]
    if not members:
        return None

    by_ext: dict[int, _Node] = {}
    info: dict[int, dict[str, Any]] = {}
    for n in members:
        ext = _thread_ext_of(n)
        role = _int(n.get(C_THREAD, 1))
        table = []
        for entry in _as_list(n.get(C_THREAD, 7)):
            e = ext_address(_field(entry, 0, "extAddress"))
            if e is None:
                continue
            table.append(
                {
                    "ext": e,
                    "rssi": _rssi_of(entry),
                    "lqi": _int(_field(entry, 5, "lqi")),
                    "child": _field(entry, 13, "isChild") is True,
                    "full": _field(entry, 11, "fullThreadDevice") is True,
                }
            )
        info[n.node_id] = {
            "ext": ext,
            "role": role,
            "router": role in (_THREAD_ROUTER, _THREAD_LEADER),
            "table": table,
        }
        if ext is not None:
            by_ext[ext] = n

    # Hubs: eigene Router/Leader plus externe Router, die in Nachbartabellen vorkommen
    hubs: dict[str, dict[str, Any]] = {}
    hub_of_ext: dict[int, str] = {}
    for n in members:
        i = info[n.node_id]
        if not i["router"]:
            continue
        hid = f"n{n.node_id}"
        hubs[hid] = _new_hub(hid, n.name, "leader" if i["role"] == _THREAD_LEADER else "router", n)
        if i["ext"] is not None:
            hub_of_ext[i["ext"]] = hid
    for n in members:
        for row in info[n.node_id]["table"]:
            e = row["ext"]
            if e in hub_of_ext or e in by_ext or row["child"] or not row["full"]:
                continue
            hid = f"x{_hex16(e)}"
            hubs[hid] = _new_hub(hid, None, "external", None)
            hubs[hid]["ext"] = _hex16(e)
            hub_of_ext[e] = hid

    # Verbindungen Hub-Hub (ungerichtet, bestes Signal beider Seiten)
    link: dict[tuple[str, str], int | None] = {}

    def add_link(a: str, b: str, rssi: int | None) -> None:
        key = (a, b) if a < b else (b, a)
        old = link.get(key)
        if key not in link or (rssi is not None and (old is None or rssi > old)):
            link[key] = rssi

    for n in members:
        if not info[n.node_id]["router"]:
            continue
        a = f"n{n.node_id}"
        for row in info[n.node_id]["table"]:
            b = hub_of_ext.get(row["ext"])
            if b and b != a and not row["child"]:
                add_link(a, b, row["rssi"])

    neighbors: dict[str, dict[str, int | None]] = {h: {} for h in hubs}
    for (a, b), rssi in link.items():
        neighbors[a][b] = rssi
        neighbors[b][a] = rssi

    # Wurzel: Leader, sonst der am besten verbundene Hub (externe zuerst: meist ein Border Router)
    root = next((h for h, v in hubs.items() if v["type"] == "leader"), None)
    if root is None and hubs:
        root = max(hubs, key=lambda h: (len(neighbors[h]), hubs[h]["type"] == "external", h))

    depth: dict[str, int] = {}
    order: list[str] = []
    todo: deque[str] = deque()
    if root is not None:
        depth[root] = 0
        todo.append(root)
    while todo:
        cur = todo.popleft()
        order.append(cur)
        for nb in sorted(neighbors[cur]):
            if nb not in depth:
                depth[nb] = depth[cur] + 1
                todo.append(nb)

    for h in order[1:]:
        cands = [(neighbors[h][nb], nb) for nb in neighbors[h] if depth.get(nb) == depth[h] - 1]
        best = max(cands, key=lambda c: (-999 if c[0] is None else c[0], c[1]))
        hubs[h]["parent"] = best[1]
        hubs[h]["rssi"] = best[0]
    for h in hubs:
        if h not in depth:
            hubs[h]["orphan"] = True
        for nb, rssi in neighbors[h].items():
            hubs[h]["neighbors"].append(
                {"id": nb, "rssi": rssi, "rel": "parent" if hubs[h]["parent"] == nb else "child" if hubs[nb]["parent"] == h else "neighbor"}
            )

    # Endgeräte (alles, was kein Router ist) einem Hub zuordnen
    child_of: dict[str, dict[str, Any]] = {}
    for n in members:
        if info[n.node_id]["router"]:
            continue
        cands: list[tuple[int | None, str]] = []
        for row in info[n.node_id]["table"]:
            h = hub_of_ext.get(row["ext"])
            if h:
                cands.append((row["rssi"], h))
        if not cands and info[n.node_id]["ext"] is not None:
            for m in members:
                for row in info[m.node_id]["table"]:
                    if row["ext"] == info[n.node_id]["ext"] and row["child"] and info[m.node_id]["router"]:
                        cands.append((row["rssi"], f"n{m.node_id}"))
        if cands:
            rssi, h = max(cands, key=lambda c: (-999 if c[0] is None else c[0], c[1]))
            child_of[n.device_id] = {"hub": h, "rssi": rssi}

    unassigned: list[dict[str, Any]] = []
    for n in members:
        if info[n.node_id]["router"]:
            continue
        row = _client(n, info[n.node_id]["role"], child_of.get(n.device_id, {}).get("rssi"))
        target = child_of.get(n.device_id)
        if target:
            hubs[target["hub"]]["clients"].append(row)
        else:
            unassigned.append(row)

    out_hubs = list(hubs.values())
    for h in out_hubs:
        h["clients"].sort(key=lambda c: (c["name"] or "").lower())
    out_hubs.sort(key=lambda h: (h["id"] != root, depth.get(h["id"], 99), (h["name"] or "~").lower(), h["id"]))
    unassigned.sort(key=lambda c: (c["name"] or "").lower())
    return {
        "hubs": out_hubs,
        "unassigned": unassigned,
        "routers": sum(1 for h in out_hubs if h["type"] != "external"),
        "external": sum(1 for h in out_hubs if h["type"] == "external"),
        "clients": sum(len(h["clients"]) for h in out_hubs) + len(unassigned),
        "links": len(link) + sum(len(h["clients"]) for h in out_hubs),
    }


def _new_hub(hid: str, name: str | None, kind: str, node: _Node | None) -> dict[str, Any]:
    return {
        "id": hid,
        "name": name,
        "type": kind,
        "device": node.device_id if node else None,
        "available": node.available if node else None,
        "parent": None,
        "rssi": None,
        "orphan": False,
        "neighbors": [],
        "clients": [],
    }


def _client(node: _Node, role: int | None, rssi: int | None) -> dict[str, Any]:
    return {
        "id": node.device_id,
        "name": node.name,
        "role": {2: "sleepy", 3: "end", 4: "reed"}.get(role or -1, "end"),
        "rssi": rssi,
        "available": node.available,
    }


def build_wifi(nodes: list[_Node]) -> dict[str, Any] | None:
    members = [n for n in nodes if n.network == "wifi"]
    if not members:
        return None
    groups: dict[str, list[_Node]] = {}
    for n in members:
        bssid = bssid_text(n.get(C_WIFI, 0)) or "unknown"
        groups.setdefault(bssid, []).append(n)
    hubs = []
    for bssid, items in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        channels = [c for c in (_int(n.get(C_WIFI, 3)) for n in items) if c]
        clients = []
        for n in items:
            rssi = _int(n.get(C_WIFI, 4))
            clients.append(
                {
                    "id": n.device_id,
                    "name": n.name,
                    "role": "wifi",
                    "rssi": rssi if rssi is not None and rssi < 0 else None,
                    "available": n.available,
                }
            )
        clients.sort(key=lambda c: (c["name"] or "").lower())
        hub = _new_hub(f"ap:{bssid}", None, "ap", None)
        hub["bssid"] = None if bssid == "unknown" else bssid
        hub["channel"] = max(set(channels), key=channels.count) if channels else None
        hub["clients"] = clients
        hubs.append(hub)
    return {
        "hubs": hubs,
        "unassigned": [],
        "routers": len(hubs),
        "external": 0,
        "clients": len(members),
        "links": len(members),
    }


def build_ethernet(nodes: list[_Node]) -> dict[str, Any] | None:
    members = [n for n in nodes if n.network == "ethernet"]
    if not members:
        return None
    hub = _new_hub("lan", None, "lan", None)
    hub["clients"] = sorted(
        (
            {"id": n.device_id, "name": n.name, "role": "lan", "rssi": None, "available": n.available}
            for n in members
        ),
        key=lambda c: (c["name"] or "").lower(),
    )
    return {
        "hubs": [hub],
        "unassigned": [],
        "routers": 1,
        "external": 0,
        "clients": len(members),
        "links": len(members),
    }


def build_topology(raw_nodes: dict[int, dict[str, Any]], names: dict[int, str]) -> dict[str, Any]:
    """Netzwerkstruktur aller Knoten: ``{"thread": …, "wifi": …, "ethernet": …}`` (None = leer)."""
    nodes = [
        _Node(node_id, node, names.get(node_id) or f"Node {node_id}")
        for node_id, node in sorted(raw_nodes.items())
        if isinstance(node, dict)
    ]
    return {
        "thread": build_thread(nodes),
        "wifi": build_wifi(nodes),
        "ethernet": build_ethernet(nodes),
    }
