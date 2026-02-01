import json
import os
import threading
import time
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, request
from scapy.all import (
    ARP,
    Ether,
    srp,
    RadioTap,
    Dot11,
    Dot11Deauth,
    sendp,
)
import socket
from mac_vendor_lookup import MacLookup

app = Flask(__name__)

# --------- KONFIGURACJA ---------

NETWORK_CIDR = "192.168.1.0/24"  # Twoja podsieć
SCAN_INTERVAL = 10  # sekundy między skanami

KNOWN_IPS_FILE = "known_ips.json"
LOG_FILE = "logs.jsonl"

# hasło do systemu (zmieniane przez API)
DISCONNECT_PASSWORD = "zrodlana4"

# Wi‑Fi do deauth
WIFI_IFACE = "wlxc04a002b0890"  # interfejs TL‑WN722N w monitor mode
AP_BSSID = "C0:3C:04:37:13:E0"  # MAC wybranego NETGEAR NIGHTHAWK

# plik z typami połączeń
CONN_TYPES_FILE = "conn_types.json"

# --------- STAN W APLIKACJI ---------

# ip -> {ip, mac, name, ever_seen, first_seen_at, conn_type}
devices_cache = {}
known_ips = set()
close_network_enabled = False
allowed_ips = set()  # whitelist IP z chwili włączenia Close Network
conn_types = {}      # ip -> "lan" / "wifi" / "unknown"
lock = threading.Lock()

mac_lookup = MacLookup()
mac_vendor_cache = {}

# --------- POMOCNICZE ---------

def get_vendor(mac: str) -> str:
    if not mac:
        return "Unknown vendor"
    m = mac.upper()
    if m in mac_vendor_cache:
        return mac_vendor_cache[m]
    try:
        vendor = mac_lookup.lookup(m)
    except Exception:
        vendor = "Unknown vendor"
    mac_vendor_cache[m] = vendor
    return vendor


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_password():
    global DISCONNECT_PASSWORD
    return DISCONNECT_PASSWORD


def set_password(new_password: str):
    global DISCONNECT_PASSWORD
    DISCONNECT_PASSWORD = new_password


def load_known_ips():
    global known_ips
    if os.path.exists(KNOWN_IPS_FILE):
        try:
            with open(KNOWN_IPS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    known_ips = set(data)
        except Exception as e:
            print(f"[WARN] Nie udało się wczytać {KNOWN_IPS_FILE}: {e}")
            known_ips = set()
    else:
        known_ips = set()


def save_known_ips():
    try:
        with open(KNOWN_IPS_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(list(known_ips)), f, indent=2)
    except Exception as e:
        print(f"[WARN] Nie udało się zapisać {KNOWN_IPS_FILE}: {e}")


def load_conn_types():
    global conn_types
    if os.path.exists(CONN_TYPES_FILE):
        try:
            with open(CONN_TYPES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    conn_types = data
        except Exception as e:
            print(f"[WARN] Nie udało się wczytać {CONN_TYPES_FILE}: {e}")
            conn_types = {}
    else:
        conn_types = {}


def save_conn_types():
    try:
        with open(CONN_TYPES_FILE, "w", encoding="utf-8") as f:
            json.dump(conn_types, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[WARN] Nie udało się zapisać {CONN_TYPES_FILE}: {e}")


def append_log(event_type, ip, name_or_mac):
    entry = {
        "timestamp": utc_now_iso(),
        "event": event_type,
        "ip": ip,
        "name": name_or_mac,
    }
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[WARN] Nie udało się zapisać logu: {e}")


def read_logs(limit=200):
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[WARN] Nie udało się odczytać logów: {e}")
        return []
    lines = lines[-limit:]
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


# --------- DEAUTH PO WI‑FI (SCAPY) ---------


def disconnect_device(ip, mac, count=24):
    """
    Wysyła ramki deauth między AP_BSSID a klientem 'mac' przez WIFI_IFACE.
    Używaj WYŁĄCZNIE w swojej sieci, jako admin.
    """
    if not mac:
        print(f"[WARN] Brak MAC dla IP {ip}, nie mogę odłączyć.")
        return
    try:
        print(f"[DEAUTH] {ip} ({mac}) z AP {AP_BSSID} via {WIFI_IFACE}")
        dot11_to_client = Dot11(addr1=mac, addr2=AP_BSSID, addr3=AP_BSSID)
        pkt_to_client = RadioTap() / dot11_to_client / Dot11Deauth(reason=7)
        dot11_to_ap = Dot11(addr1=AP_BSSID, addr2=mac, addr3=AP_BSSID)
        pkt_to_ap = RadioTap() / dot11_to_ap / Dot11Deauth(reason=7)
        sendp(pkt_to_client, iface=WIFI_IFACE, count=count, inter=0.05, verbose=False)
        sendp(pkt_to_ap, iface=WIFI_IFACE, count=count, inter=0.05, verbose=False)
    except Exception as e:
        print(f"[ERROR] disconnect_device {ip} {mac}: {e}")


def auto_disconnect(ip, mac):
    print(f"[AUTO] Close Network disconnect {ip} ({mac})")
    append_log("auto_disconnect", ip, mac)
    disconnect_device(ip, mac)


# --------- SKAN SIECI ---------


def scan_network():
    global devices_cache, known_ips, close_network_enabled, allowed_ips
    while True:
        new_devices = {}
        try:
            arp = ARP(pdst=NETWORK_CIDR)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            answered, _ = srp(packet, timeout=2, retry=1, verbose=False)
            current_time = utc_now_iso()

            for _, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                hostname = resolve_hostname(ip)
                ever_seen = ip in known_ips
                first_seen_at = None

                if not ever_seen:
                    print(f"[INFO] Nowe IP w sieci: {ip} ({hostname}) [{mac}]")
                    known_ips.add(ip)
                    save_known_ips()
                    append_log("first_seen", ip, f"{hostname} [{mac}]")
                    first_seen_at = current_time
                else:
                    if ip in devices_cache:
                        first_seen_at = devices_cache[ip].get("first_seen_at")

                # typ połączenia z conn_types (LAN / WiFi / unknown)
                conn_type = conn_types.get(ip, "unknown")

                # producent po MAC (OUI)
                vendor = get_vendor(mac)

                new_devices[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "name": hostname,
                    "ever_seen": ever_seen,
                    "first_seen_at": first_seen_at,
                    "conn_type": conn_type,
                    "vendor": vendor,
                }

            # CLOSE NETWORK: auto‑odcinanie wszystkiego spoza whitelisty
            if close_network_enabled:
                for ip, dev in list(new_devices.items()):
                    if ip not in allowed_ips:
                        auto_disconnect(ip, dev.get("mac"))

            with lock:
                devices_cache = new_devices

        except Exception as e:
            print(f"[ERROR] Błąd w scan_network: {e}")

        time.sleep(SCAN_INTERVAL)



# --------- ROUTES ---------


@app.route("/")
def index():
    return render_template("index.html", title="MUSG Network Dashboard")


@app.route("/api/devices")
def api_devices():
    with lock:
        devices = list(devices_cache.values())
    return jsonify(devices)


@app.route("/api/logs")
def api_logs():
    limit = request.args.get("limit", default=200, type=int)
    entries = read_logs(limit=limit)
    entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return jsonify(entries)


@app.route("/api/disconnect", methods=["POST"])
def api_disconnect():
    data = request.get_json() or {}
    ip = data.get("ip")
    password = data.get("password")

    if password != get_password():
        return jsonify({"status": "error", "message": "Invalid password"}), 403
    if not ip:
        return jsonify({"status": "error", "message": "No IP provided"}), 400

    with lock:
        dev = devices_cache.get(ip, {})
        mac = dev.get("mac")
        name = dev.get("name", "Unknown")

    print(f"[ACTION] Manual disconnect for {ip} {mac} {name}")
    append_log("manual_disconnect", ip, f"{name} [{mac}]")
    # dodatkowy log – intruz
    append_log("intruder", ip, f"{name} [{mac}]")

    disconnect_device(ip, mac)
    return jsonify({"status": "ok", "message": f"Disconnect triggered for {ip}"}), 200


@app.route("/api/change_password", methods=["POST"])
def api_change_password():
    data = request.get_json() or {}
    current = data.get("current")
    new = data.get("new")

    if not current or not new:
        return jsonify({"status": "error", "message": "Missing fields"}), 400
    if current != get_password():
        return jsonify({"status": "error", "message": "Invalid current password"}), 403

    set_password(new)
    append_log("password_change", "", "password changed")
    return jsonify({"status": "ok", "message": "Password changed"}), 200


@app.route("/api/close_network/enable", methods=["POST"])
def api_close_network_enable():
    global close_network_enabled, allowed_ips
    data = request.get_json() or {}
    password = data.get("password")

    if password != get_password():
        return jsonify({"status": "error", "message": "Invalid password"}), 403

    with lock:
        allowed_ips = set(devices_cache.keys())
        close_network_enabled = True
    append_log("close_network_on", "", f"allowed_ips={len(allowed_ips)}")

    return jsonify({"status": "ok", "message": "Close Network enabled"}), 200


@app.route("/api/close_network/disable", methods=["POST"])
def api_close_network_disable():
    global close_network_enabled
    data = request.get_json() or {}
    password = data.get("password")

    if password != get_password():
        return jsonify({"status": "error", "message": "Invalid password"}), 403

    close_network_enabled = False
    append_log("close_network_off", "", "")
    return jsonify({"status": "ok", "message": "Close Network disabled"}), 200


@app.route("/api/set_conn_type", methods=["POST"])
def api_set_conn_type():
    data = request.get_json() or {}
    password = data.get("password")
    ip = data.get("ip")
    ctype = data.get("conn_type")  # "lan" / "wifi" / "unknown"

    if password != get_password():
        return jsonify({"status": "error", "message": "Invalid password"}), 403
    if not ip or ctype not in ("lan", "wifi", "unknown"):
        return jsonify({"status": "error", "message": "Bad request"}), 400

    with lock:
        conn_types[ip] = ctype
        if ip in devices_cache:
            devices_cache[ip]["conn_type"] = ctype
    save_conn_types()
    append_log("conn_type_change", ip, ctype)

    return jsonify({"status": "ok", "message": f"Type set to {ctype} for {ip}"}), 200


if __name__ == "__main__":
    load_known_ips()
    load_conn_types()
    t = threading.Thread(target=scan_network, daemon=True)
    t.start()
    # URUCHAMIAJ JAKO ROOT (bo monitor mode + Scapy):
    # sudo -E python app.py
    app.run(host="0.0.0.0", port=5000, debug=True)
