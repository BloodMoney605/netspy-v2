#!/usr/bin/env python3

from __future__ import annotations
import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from common import apply_thread_override, t
from config import cargar as load_config

from netspy_env import (
    objetivo_valido,
    have,
    is_interactive,
    popen as _popen,
    run as _run,
    tmp_dir as _tmp_dir,
)


def tmp_path():
    return _tmp_dir()

BOLD = "\033[1m"
CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
NC = "\033[0m"
BAR_LEN = 30


def _run_progress_bar(label: str, total_steps: int):
    stop_event = threading.Event()
    interactive = is_interactive()

    def _animate():
        step = 0
        max_steps = total_steps * 10
        while not stop_event.is_set() and step < max_steps:
            time.sleep(0.15)
            step += 1
            pct = min(int((step / max_steps) * 100), 99)
            filled = int(BAR_LEN * pct // 100)
            bar = "#" * filled + "-" * (BAR_LEN - filled)
            if interactive:
                print(f"\r  [{bar}] {pct}% {label}", end="", flush=True)

    anim = threading.Thread(target=_animate, daemon=True)
    anim.start()
    return anim, stop_event


def _finish_progress_bar(anim, stop_event, label: str):
    stop_event.set()
    anim.join(timeout=1)
    if is_interactive():
        print(f"\r  [{'#' * BAR_LEN}] 100% {label}", flush=True)


def load_targets(targets_path: str) -> list[str]:
    """Lee el archivo de objetivos y devuelve IPs o hosts validos.

    Todo lo que sale de aca termina como argumento de nmap, asi que se
    descarta lo que no sea un host o una IP. Sin esto, un valor que empieza
    con "-" lo interpretaria nmap como opcion.
    """
    if not os.path.exists(targets_path):
        print(f"  [!] no se encontro el archivo de objetivos: {targets_path}")
        return []

    with open(targets_path, encoding="utf-8", errors="replace") as f:
        targets = [line.strip() for line in f if line.strip()]

    resueltos: list[str] = []
    descartados = 0

    for target in targets:
        if not objetivo_valido(target):
            descartados += 1
            continue

        if any(c.isalpha() for c in target):
            try:
                resueltos.append(socket.gethostbyname(target))
            except OSError:
                resueltos.append(target)
        else:
            resueltos.append(target)

    if descartados:
        print(f"  [!] {descartados} objetivo(s) descartado(s): no son host ni IP")

    return resueltos


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 162, 389,
    443, 445, 465, 500, 512, 513, 514, 523, 548, 554, 587, 593, 636, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1434,
    1521, 1604, 1720, 1723, 1883, 1900, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2181, 2222, 2375, 2376, 2443, 2483, 2484, 2525, 3000,
    3128, 3306, 3389, 3690, 3868, 4000, 4001, 4040, 4041, 4333, 4443,
    4444, 4500, 4567, 4646, 4711, 4712, 4848, 4899, 5000, 5001, 5003,
    5004, 5005, 5006, 5007, 5008, 5009, 5050, 5060, 5061, 5140, 5222,
    5353, 5432, 5443, 5445, 5555, 5556, 5631, 5632, 5666, 5672, 5673,
    5800, 5801, 5802, 5900, 5901, 5902, 5903, 5984, 5985, 5986, 6000,
    6001, 6002, 6003, 6379, 6443, 6580, 6665, 6666, 6667, 6668, 6669,
    6697, 7001, 7002, 7070, 7071, 7077, 7777, 7778, 8000, 8001, 8002,
    8008, 8009, 8010, 8020, 8030, 8040, 8050, 8060, 8070, 8080, 8081,
    8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092,
    8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8111, 8112, 8123,
    8161, 8172, 8200, 8222, 8243, 8280, 8300, 8332, 8333, 8400, 8403,
    8443, 8500, 8530, 8531, 8600, 8649, 8800, 8834, 8880, 8888, 8889,
    8899, 8900, 8983, 9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007,
    9008, 9009, 9010, 9042, 9043, 9050, 9060, 9080, 9090, 9091, 9092,
    9100, 9150, 9200, 9290, 9300, 9418, 9443, 9595, 9600, 9900, 9999,
    10000, 10001, 10050, 10051, 10080, 10082, 11000, 11211, 11371,
    12000, 12345, 12346, 12443, 14000, 16080, 16110, 16992, 16993,
    17017, 18080, 18081, 18090, 18101, 18200, 18201, 19000, 20000,
    20001, 20720, 21000, 21306, 22222, 23000, 23101, 24000, 24444,
    25000, 25565, 26000, 26208, 27000, 27017, 27374, 28017,
    28080, 30000, 30704, 31138, 31337, 31339, 32764, 32768, 32769,
    32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778,
    32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33890,
    34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 44176,
    44334, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154,
    49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
    49167, 49175, 49176, 49400, 50000, 50001, 50002, 50003, 50006,
    50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822,
    52848, 52869, 54045, 54328, 55055, 55056, 55553, 55554, 55555,
    55600, 56737, 56738, 57294, 57797, 58080, 60000, 60001, 60020,
    60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129,
    65389, 65535,
]


#: Well-known port -> service name, used when the service cannot be detected
#: from a banner (i.e. when running without nmap).
COMMON_SERVICE_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 67: "dhcps", 68: "bootpc", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "shell", 587: "submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 2375: "docker", 2376: "docker", 3000: "http-alt",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 5901: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "cslistener", 9090: "zeus-admin",
    9200: "elasticsearch", 27017: "mongodb", 11211: "memcached",
}


def tcp_scan_port(ip: str, port: int, timeout: float = 2.0) -> int | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def custom_port_scan(
    ips: list[str],
    ports: list[int] | None = None,
    threads: int = 50,
    timeout: float = 1.0,
) -> dict[str, list[int]]:
    if ports is None:
        ports = TOP_PORTS

    results: dict[str, list[int]] = {ip: [] for ip in ips}
    total_checks = len(ips) * len(ports)
    global_checked = 0

    print(f"  escaneando {len(ips)} IPs x {len(ports)} puertos ({total_checks} comprobaciones)...")

    for idx, ip in enumerate(ips, 1):
        ip_ports: list[int] = []
        ip_checks = len(ports)

        def check_port(port: int) -> int | None:
            return tcp_scan_port(ip, port, timeout)

        with ThreadPoolExecutor(max_workers=min(threads, ip_checks)) as pool:
            futures = {pool.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                global_checked += 1
                if global_checked % 500 == 0:
                    print(f"    {global_checked}/{total_checks} checks", end="\r", flush=True)
                if future.result() is not None:
                    ip_ports.append(futures[future])

        if ip_ports:
            results[ip] = sorted(ip_ports)
            print(f"    [{idx}/{len(ips)}] {ip}: {len(ip_ports)} puertos abiertos")
        else:
            print(f"    [{idx}/{len(ips)}] {ip}: sin puertos abiertos")

    print(f"    {global_checked}/{total_checks} comprobaciones listas")
    return results


def run_nmap_version_scan(
    ip_ports: dict[str, list[int]],
    timeout: int = 300,
    service_detect: bool = True,
    os_detect: bool = False,
) -> dict[str, Any]:
    if not ip_ports:
        return {"hosts": [], "total_open_ports": 0, "services": []}

    if not have("nmap"):
        return None

    tmp_dir = str(tmp_path())
    output_file = os.path.join(tmp_dir, f"nmap_{int(time.time())}.xml")
    host_list = list(ip_ports.items())
    total_hosts = len(host_list)

    anim_thread, stop_event = _run_progress_bar("deteccion de versiones con nmap", total_hosts)

    for hidx, (ip, ports) in enumerate(host_list, 1):
        port_list = ",".join(str(p) for p in sorted(ports))
        # -sV es lo mas caro; -O solo si lo piden explicitamente.
        flags = ["-sV"] if service_detect else []
        if os_detect:
            flags.append("-O")
        nmap_cmd = [
            *flags,
            "nmap",
            "-Pn",
            "-sT",
            "-T4",
            "--max-retries", "2",
            "--host-timeout", "30s",
            "-p", port_list,
            "-oX", f"{output_file}.{hidx}",
            ip,
        ]

        try:
            nmap_proc = _popen(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            nmap_proc.wait(timeout=120)
        except Exception:
            try:
                nmap_proc.kill()
                nmap_proc.wait()
            except Exception:
                pass

    _finish_progress_bar(anim_thread, stop_event, "deteccion de versiones con nmap")

    # nmap escribe un XML por host; se juntan
    all_xml = ""
    for bidx in range(1, total_hosts + 1):
        xml_path = f"{output_file}.{bidx}"
        if os.path.exists(xml_path):
            with open(xml_path, encoding="utf-8", errors="replace") as f:
                all_xml += f.read()
            os.remove(xml_path)

    if not all_xml:
        return {"hosts": [], "total_open_ports": 0, "services": []}

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(all_xml)

    results = parse_nmap_xml(output_file)
    os.remove(output_file)
    return results


def parse_nmap_xml(xml_path: str) -> dict[str, Any]:
    import xml.etree.ElementTree as ET

    results: dict[str, Any] = {
        "hosts": [],
        "total_open_ports": 0,
        "services": [],
    }

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        return {"error": f"xml parse: {e}"}

    for host in root.findall("host"):
        host_data: dict[str, Any] = {
            "ip": "",
            "hostname": "",
            "status": "",
            "ports": [],
        }

        addr = host.find("address")
        if addr is not None:
            host_data["ip"] = addr.get("addr", "")

        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                host_data["hostname"] = hn.get("name", "")

        status = host.find("status")
        if status is not None:
            host_data["status"] = status.get("state", "")

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            port_data: dict[str, Any] = {
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", ""),
                "state": "",
                "service": "",
                "product": "",
                "version": "",
                "cpe": "",
            }

            state = port.find("state")
            if state is not None:
                port_data["state"] = state.get("state", "")

            service = port.find("service")
            if service is not None:
                port_data["service"] = service.get("name", "")
                port_data["product"] = service.get("product", "")
                port_data["version"] = service.get("version", "")
                port_data["cpe"] = service.get("cpe", "")

            if port_data["state"] == "open":
                results["total_open_ports"] += 1
                results["services"].append({
                    "ip": host_data["ip"],
                    "port": port_data["port"],
                    "protocol": port_data["protocol"],
                    "service": port_data["service"],
                    "product": port_data["product"],
                    "version": port_data["version"],
                    "cpe": port_data["cpe"],
                })

            host_data["ports"].append(port_data)

        results["hosts"].append(host_data)

    return results


def run_nmap_direct_scan(
    ips: list[str],
    top_n: int = 1000,
    timeout: int = 600,
    service_detect: bool = True,
    os_detect: bool = False,
) -> dict[str, Any] | None:
    tmp_dir = str(tmp_path())
    output_file = os.path.join(tmp_dir, f"nmap_{int(time.time())}.xml")
    flags = ["-sV"] if service_detect else []
    if os_detect:
        flags.append("-O")
    nmap_cmd = [
        "nmap", "-Pn", "-sT", *flags, "-T4",
        "--top-ports", str(top_n),
        "--max-retries", "2",
        "-oX", output_file,
    ] + ips

    nmap_proc = _popen(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    anim_thread, stop_event = _run_progress_bar(f"nmap -sV --top-ports {top_n}", 1)

    try:
        nmap_proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        nmap_proc.kill()
        nmap_proc.wait()
    except KeyboardInterrupt:
        nmap_proc.kill()
        nmap_proc.wait()
        raise
    finally:
        _finish_progress_bar(anim_thread, stop_event, "escaneo con nmap")

    if nmap_proc.returncode != 0 and not os.path.exists(output_file):
        return None

    if not os.path.exists(output_file):
        return None

    results = parse_nmap_xml(output_file)
    os.remove(output_file)
    return results


def build_results_from_open_ports(ip_ports: dict[str, list[int]]) -> dict[str, Any]:
    """Arma el resultado con la forma de nmap usando el escaner propio.

    Sin nmap solo se conhece el numero de puerto, asi que el nombre del
    servicio sale de una tabla y no hay versiones de producto.
    """
    results: dict[str, Any] = {"hosts": [], "total_open_ports": 0, "services": []}
    for ip, ports in ip_ports.items():
        results["hosts"].append({"ip": ip})
        for port in sorted(ports):
            results["total_open_ports"] += 1
            results["services"].append({
                "ip": ip,
                "port": port,
                "protocol": "tcp",
                "service": COMMON_SERVICE_NAMES.get(port, ""),
                "product": "",
                "version": "",
                "cpe": "",
            })
    return results


def run_scan(targets_path: str, config: dict, output: str) -> dict[str, Any]:
    ips = load_targets(targets_path)
    if not ips:
        print("  [!] no hay objetivos para escanear")
        return {"error": "no targets"}

    top_n = config.get("scan", {}).get("ports", {}).get("top", 1000)
    use_custom = config.get("scan", {}).get("use_custom_scanner", False)
    service_detect = config.get("scan", {}).get("service_detect", True)
    os_detect = config.get("scan", {}).get("os_detect", False)
    nmap_available = have("nmap")

    if not nmap_available:
        # nmap is an accelerator here, not a requirement: the built-in TCP
        # scanner gives port numbers on any platform with a socket.
        print(f"  [!] nmap no esta, se usa el escaner TCP propio")
        use_custom = True

    print(f"  {t('targets')}: {len(ips)} IPs")

    if use_custom:
        print(f"  [{t('custom_scan')}]...")
        ports = TOP_PORTS[:top_n] if top_n < len(TOP_PORTS) else TOP_PORTS
        threads = config.get("target", {}).get("threads", 50)
        open_ports = custom_port_scan(ips, ports, threads=threads, timeout=1.0)
        ip_ports = {ip: pts for ip, pts in open_ports.items() if pts}
        print(f"  hosts con puertos abiertos: {len(ip_ports)}")
        print()

        if nmap_available:
            print(f"  [{t('nmap_version')}]...")
            nmap_results = run_nmap_version_scan(ip_ports, service_detect=service_detect, os_detect=os_detect)
            scan_method = "propio+nmap"
            if nmap_results is None:
                nmap_results = build_results_from_open_ports(ip_ports)
                scan_method = "custom"
        else:
            nmap_results = build_results_from_open_ports(ip_ports)
            scan_method = "custom"
    else:
        print(f"  [{t('nmap_scan')}]...")
        nmap_results = run_nmap_direct_scan(ips, top_n, service_detect=service_detect, os_detect=os_detect)
        scan_method = "nmap-direct"

    if nmap_results is None:
        print("  [!] el escaneo no dio resultados utilizables")
        return {"error": "escaneo fallo"}

    results = nmap_results
    results["scan_method"] = scan_method

    # Save
    scan_path = os.path.join(output, "ports.json")
    with open(scan_path, "w", encoding="utf-8") as scan_file:
        json.dump(results, scan_file, indent=2, default=str)

    # archivos de texto que consume la fase 3
    services = results.get("services", [])
    unique_services = len(set(svc["service"] for svc in services if svc.get("service")))
    print(f"  {BOLD}{t('services_detected')}: {unique_services}{NC}")
    if services:
        print(f"  {BOLD}{'─' * 50}{NC}")
        for svc in services:
            proto = svc.get("service", "?")
            port = svc["port"]
            ip = svc["ip"]
            product = svc.get("product", "")
            version = svc.get("version", "")
            ver_str = f" {product} {version}" if product else ""
            print(f"  {GREEN}{ip}{NC}:{port}/{proto}{ver_str}")

    svc_path = os.path.join(output, "services.txt")
    with open(svc_path, "w", encoding="utf-8") as svc_file:
        for svc in services:
            line = f"{svc['ip']}:{svc['port']} {svc['service']}"
            if svc.get("product"):
                line += f" ({svc['product']} {svc.get('version', '')})"
            svc_file.write(line + "\n")

    url_path = os.path.join(output, "urls.txt")
    with open(url_path, "w", encoding="utf-8") as url_file:
        for svc in services:
            svc_name = svc.get("service", "")
            if svc_name in ("http", "https", "http-proxy", "ssl|http"):
                proto = "https" if svc["port"] in (443, 8443) or svc_name == "https" else "http"
                url_file.write(f"{proto}://{svc['ip']}:{svc['port']}/\n")

    print(f"\n  salida: {scan_path}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Fase 2: escaneo de puertos")
    parser.add_argument("--targets", required=True, help="archivo con los objetivos (uno por linea)")
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--output", required=True)
    parser.add_argument("--threads", type=int, default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    config = apply_thread_override(config, args.threads)
    os.makedirs(args.output, exist_ok=True)

    try:
        run_scan(args.targets, config, args.output)
    except KeyboardInterrupt:
        print("\n  [!] interrumpido")
        sys.exit(130)


if __name__ == "__main__":
    main()
