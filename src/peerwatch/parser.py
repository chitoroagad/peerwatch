import logging
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import NamedTuple

from pydantic import BaseModel, Field


class NormalisedData(BaseModel):
    mac_address: str = Field(default="unknown")
    ipv4: str = Field(default="unknown")
    ipv6: str = Field(default="unknown")
    os: str = Field(default="unknown")
    os_version: str = Field(default="unknown")
    distribution: str = Field(default="unknown")
    device_vendor: str = Field(default="unknown")
    open_ports: list[int] = Field(default=[])
    services: dict[int, str] = Field(default={})
    generated_at: datetime = Field(default_factory=datetime.now)


class NmapParser:
    class PortsInfo(NamedTuple):
        services: dict[int, str]
        open_ports: list[int]

    class PortInfo(NamedTuple):
        portid: int
        service: str
        open_port: bool

    class VendorAddresses(NamedTuple):
        vendor: str | None
        mac: str | None
        ipv4: IPv4Address | None
        ipv6: IPv6Address | None

    def __init__(self, host_data: dict):
        self.raw_data = host_data
        self.normalised_data = {}

    def parse(self) -> NormalisedData:
        self._extract_os_data()
        self._extract_device_vendor_and_address()
        self._extract_ports()
        self.normalised_data = {
            k: v for k, v in self.normalised_data.items() if v is not None
        }

        out = NormalisedData.model_validate(self.normalised_data, strict=True)

        return out

    def _first_item(self, val: dict | list | None) -> dict | None:
        if isinstance(val, list):
            return val[0] if val else None
        return val

    def _extract_os_data(self):
        os_data = self.raw_data.get("os")
        if not os_data:
            logging.warning("No 'os' key in input data")
        else:
            osmatch: dict | None = self._first_item(os_data.get("osmatch"))
            if not osmatch:
                logging.warning(f"No 'osmatch' key in {os_data}")
            else:
                osclass: dict | None = self._first_item(osmatch.get("osclass"))
                if not osclass:
                    logging.warning("No 'osclass' key in host_data['os']['osmatch']")
                else:
                    self.normalised_data.update(
                        {
                            "os": osclass.get("@vendor")
                            if osclass.get("@vendor")
                            else osclass.get("@osfamily"),
                            "os_type": osclass.get("@type"),
                            "os_version": osclass.get("@osgen"),
                            "distribution": osmatch.get("@name"),
                        }
                    )

    def _extract_device_vendor_and_address(self):
        address_field = self.raw_data.get("address")
        vendor = None
        mac = None
        ipv4 = None
        ipv6 = None
        if not address_field:
            logging.warning("No 'address' key in input data")
        else:
            vendor_address = self._find_device_vendor_and_address(address_field)
            if vendor_address is not None:
                vendor, mac, ipv4, ipv6 = vendor_address
        self.normalised_data["device_vendor"] = vendor
        self.normalised_data["mac_address"] = mac
        self.normalised_data["ipv4"] = str(ipv4) if ipv4 else None
        self.normalised_data["ipv6"] = str(ipv6) if ipv6 else None

    def _find_device_vendor_and_address(self, address) -> VendorAddresses | None:
        address_iter = address if isinstance(address, list) else [address]
        vendor = None
        mac = None
        ipv4 = None
        ipv6 = None
        for addr in address_iter:
            vendor_addresses = self._check_address_and_vendor(addr)
            if vendor_addresses is None:
                continue

            tmp_vendor, tmp_mac, tmp_ipv4, tmp_ipv6 = vendor_addresses
            vendor = tmp_vendor if tmp_vendor else vendor
            mac = tmp_mac if tmp_mac else mac
            ipv4 = tmp_ipv4 if tmp_ipv4 else ipv4
            ipv6 = tmp_ipv6 if tmp_ipv6 else ipv6

        if mac is None:
            logging.warning(f"No valid MAC address found for {address_iter}")
        return self.VendorAddresses(vendor, mac, ipv4, ipv6)

    def _check_address_and_vendor(self, addr: dict) -> VendorAddresses | None:
        addrtype = addr.get("@addrtype")
        if not addrtype:
            logging.warning(f"No '@addrtype' in address: {addr}")
            return None

        vendor = None
        mac = None
        ipv4 = None
        ipv6 = None
        if addrtype == "mac":
            vendor = addr.get("@vendor")
            if not vendor:
                logging.warning(f"No '@vendor' key in mac address: {addr}")
            mac = addr.get("@addr")
        if "ip" in addrtype:
            ip = addr.get("@addr")
            if not ip:
                logging.error("No IP address found")
                return None

            try:
                ip_parsed = ip_address(ip)
                if isinstance(ip_parsed, IPv4Address):
                    ipv4 = ip_parsed
                elif isinstance(ip_parsed, IPv6Address):
                    ipv6 = ip_parsed
            except ValueError as e:
                logging.error(f"Could not parse IP address: {ip}: {e}")

        return self.VendorAddresses(vendor, mac, ipv4, ipv6)

    def _extract_ports(self):
        # excludes the "extra ports" field
        ports = self.raw_data.get("ports")
        if not ports:
            logging.warning("No 'ports' field found in input data")
            return
        ports_list = ports.get("port")
        if not ports_list:
            logging.warning(f"No 'port' field found in ports map: {ports}")
            return

        services, open_ports = self._find_ports(ports_list)
        self.normalised_data.update({"open_ports": open_ports, "services": services})

    def _find_ports(self, ports: dict | list) -> PortsInfo:
        open_ports = []
        services = {}

        ports_iter = ports if isinstance(ports, list) else [ports]
        for port in ports_iter:
            portid, service, port_open = self._check_port(port)
            if not portid:
                logging.warning("Skipped a port with no portid")
                continue

            services[portid] = service
            if port_open:
                open_ports.append(portid)

        return self.PortsInfo(services, open_ports)

    def _check_port(self, port) -> PortInfo:
        portid = port.get("@portid")
        if not portid:
            logging.warning(f"No '@portid' found for port: {port}")
        portid = int(portid)

        state_map = port.get("state")
        state = None
        if state_map:
            state = state_map.get("@state")
        if not state:
            logging.warning(f"No 'state' found for port: {portid}")

        service_map = port.get("service")
        service_name = ""
        service_product = ""
        service = None
        if service_map:
            service_name = service_map.get("@name")
            service_product = service_map.get("@product")
            if service_name and service_product:
                service = service_name + "-" + service_product
            else:
                service = service_name if service_name else service_product
        if not service:
            logging.warning(f"No 'service' found for port: {portid}")

        open_port = False
        if state == "open":
            open_port = True
        return self.PortInfo(portid, service if service else "", open_port)
