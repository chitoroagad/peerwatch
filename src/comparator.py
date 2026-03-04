import json
import logging
import os
from datetime import datetime
from os import PathLike
from pathlib import Path
from typing import Iterator

from langchain_community.utils.math import cosine_similarity
from pydantic import BaseModel
from sortedcontainers import SortedDict

from embedder import Embedder, PeerEmbeddings
from parser import NmapParser, NormalisedData


class Comparator:
    class Similarities(BaseModel):
        os: float
        ports: float
        services: float

    class HostFingerprint:
        def __init__(
            self,
            mac_address: str | None,
            ipv4_address: str | None,
            ipv6_address: str | None,
        ):
            self.mac_address = mac_address
            self.ipv4_address = ipv4_address
            self.ipv6_address = ipv6_address

    def __init__(self, embedder: Embedder, data_path: str | PathLike):
        self.embedder = embedder
        self.data_path = data_path
        self.peer_store: dict[str, PeerEmbeddings] = {}
        self.time_to_hosts = self._load_data()
        self._set_time_to_embeddings()
        self._process_embeddings()

    def _load_data(self) -> dict[datetime, list[NormalisedData]]:
        data_iter = Path(self.data_path).glob("*.json")
        time_to_file = self._parse_datetime(data_iter)
        time_to_hosts = SortedDict()
        for time, file in time_to_file.items():
            with open(file) as f:
                hosts = json.load(f)
                time_to_hosts[time] = hosts
        time_to_hosts = {
            time: self._normalise(host) for time, host in time_to_hosts.items()
        }
        return time_to_hosts

    def _set_time_to_embeddings(self):
        time_to_embeddings_data: dict[
            datetime, list[tuple[NormalisedData, PeerEmbeddings | None]] | None
        ] = {time: None for time in self.time_to_hosts.keys()}
        for time, hosts in self.time_to_hosts.items():
            embeddings = []
            for host in hosts:
                embedded = self.embedder.embed(host)
                embeddings.append((host, embedded))
            time_to_embeddings_data[time] = embeddings

        self.time_to_embeddings_data = time_to_embeddings_data

    def _process_embeddings(self):
        for time, embeddings in self.time_to_embeddings_data.items():
            if not embeddings:
                logging.warning(f"No embeddings found for time: {time}, skipping")
                continue

            for raw_data, embedding in embeddings:
                if embedding is None:
                    print("Broke at no emebeddings")
                    logging.warning(
                        f"No embeddings found for host: {raw_data}\t skipping"
                    )
                    continue

                mac = raw_data.mac_address
                if mac == "unknown":
                    logging.warning(
                        f"Unknown mac address for host: {raw_data}\t skipping"
                    )
                    continue

                if mac not in self.peer_store:
                    # first instance of this mac address
                    self.peer_store[mac] = embedding
                    continue

                os_similarity = cosine_similarity(
                    [self.peer_store[mac].os], [embedding.os]
                )
                ports_similarity = cosine_similarity(
                    [self.peer_store[mac].port_set], [embedding.port_set]
                )
                services_similarity = cosine_similarity(
                    [self.peer_store[mac].services], [embedding.services]
                )
                print(raw_data.mac_address)
                print(
                    "OS:",
                    os_similarity,
                    "\nPORTS:",
                    ports_similarity,
                    "\nSERVICES:",
                    services_similarity,
                )

    def _parse_datetime(self, paths: Iterator[Path]) -> dict[datetime, str]:
        out = SortedDict()
        for path in paths:
            name = os.path.basename(path)
            timestamp_str = name.replace("scan_", "").replace(".json", "")
            dt = datetime.strptime(timestamp_str, "%Y-%m-%d_%H-%M-%S")
            out[dt] = path
        return out

    @staticmethod
    def _normalise(hosts):
        out = []
        for host in hosts:
            parser = NmapParser(host)
            out.append(parser.parse())
        return out


if __name__ == "__main__":
    embedder = Embedder("all-minilm:22m")
    c = Comparator(embedder, "./data/")
