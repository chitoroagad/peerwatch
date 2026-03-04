import logging
import threading
import uuid
from datetime import datetime, timezone

import numpy as np
from pydantic import BaseModel, Field

from peerwatch.embedder import PeerEmbeddings
from peerwatch.parser import NormalisedData

UNKNOWN_KEY = "unknown"
OS_SIMILARITY_THRESHOLD = 0.92
PORT_SIMILARITY_THRESHOLD = 0.80
SERVICE_SIMILARITY_THRESHOLD = 0.75


class IdentityEvent(BaseModel):
    timestamp: datetime
    event: str
    details: dict


class Peer(BaseModel):
    """
    Canonical representation of a network peer/device.
    """

    internal_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mac_address: str | None = None
    ips: set[str] = Field(default_factory=set)

    is_volatile: bool = True  # False if MAC is set
    suspicion_score: float = 0.0  # increases with conflicting observations

    metadata: NormalisedData
    embeddings: PeerEmbeddings

    metadata_history: list[NormalisedData] = Field(default_factory=list)
    identity_history: list[IdentityEvent] = Field(default_factory=list)

    def record_event(self, event: str, **details):
        self.identity_history.append(
            IdentityEvent(
                timestamp=datetime.now(timezone.utc),
                event=event,
                details=details,
            )
        )

    def __str__(self) -> str:
        return f"""id: {self.internal_id}, mac: {self.mac_address}, ips: {self.ips}
        is_volatile: {self.is_volatile}, suspicion_score: {self.suspicion_score}\n"""

    def __repr__(self) -> str:
        return self.__str__()


class PeerStore:
    """
    Secure peer identity store designed for network attack and spoofing detection.

    Identity resolution is conservative:
    - MAC addresses are treated as strong but *not absolute* identifiers
    - IP addresses are weak and may be shared or reassigned
    - Conflicts increase suspicion rather than being silently resolved

    The store preserves historical observations to support forensic analysis.
    """

    class EmbeddingComparison(BaseModel):
        os_similarity: float
        port_similarity: float
        service_similarity: float
        overall_score: float
        events: list[str]

    peers: dict[str, Peer]
    mac_to_id: dict[str, str]
    ip_to_id: dict[str, str]

    _lock: threading.Lock = threading.Lock()

    def __init__(self):
        self.peers = {}
        self.mac_to_id = {}
        self.ip_to_id = {}

    # --------------------
    # Public API
    # --------------------

    def get_peer(self, mac: str | None = None, ip: str | None = None) -> Peer | None:
        with self._lock:
            if mac and mac != UNKNOWN_KEY and mac in self.mac_to_id:
                return self.peers.get(self.mac_to_id[mac])

            if ip and ip != UNKNOWN_KEY and ip in self.ip_to_id:
                return self.peers.get(self.ip_to_id[ip])

            return None

    def add_or_update_peer(
        self, data: NormalisedData, embeddings: PeerEmbeddings
    ) -> Peer:
        """
        Checks peer for anomaly then adds/updates store
        """
        mac = self._normalise_mac(data.mac_address)
        ips = self._extract_ips(data)

        with self._lock:
            mac_id = self.mac_to_id.get(mac) if mac else None
            ip_ids = {self.ip_to_id[ip] for ip in ips if ip in self.ip_to_id}

            candidate_ids = set(filter(None, [mac_id])) | ip_ids

            if not candidate_ids:
                peer = self._create_peer(mac, ips, data, embeddings)
                return peer

            if len(candidate_ids) == 1:
                peer = self.peers[next(iter(candidate_ids))]
                suspicion = self._check_incoming_embeddings(peer, embeddings)
                self._update_peer(peer, mac, ips, data, embeddings)
                peer.suspicion_score += suspicion
                return peer

            # Multiple candidates → possible spoofing or identity collision
            peer = self._resolve_conflict(candidate_ids, mac, ips, data, embeddings)
            return peer

    def reset(self):
        logging.warning("Resetting Peer Store")
        with self._lock:
            self.peers = {}
            self.mac_to_id = {}
            self.ip_to_id = {}

    # --------------------
    # Internal helpers
    # --------------------

    def _check_incoming_embeddings(
        self, prev: Peer, incoming_embeddings: PeerEmbeddings
    ) -> float:
        comparison = self._compare_peers(prev.embeddings, incoming_embeddings)
        suspicion = prev.suspicion_score
        for event in comparison.events:
            prev.record_event(event)
        if "full_identity_shift" in comparison.events:
            suspicion += 2.0
        # else:
        #     if "os_fingerprint_changed" in comparison.events:
        #         suspicion += 1.0
        #     if "port_fingerprint_changed" in comparison.events:
        #         suspicion += 0.7
        #     if "service_fingerprint_changed" in comparison.events:
        #         suspicion += 0.5
        elif "os_fingerprint_changed" in comparison.events:
            suspicion += 1.0
        elif "overall_score" in comparison.events:
            suspicion += 0.5

        return suspicion

    def _create_peer(
        self,
        mac: str | None,
        ips: set[str],
        data: NormalisedData,
        embeddings: PeerEmbeddings,
    ) -> Peer:
        peer = Peer.model_construct(
            mac_address=mac,
            ips=set(ips),
            metadata=data,
            embeddings=embeddings,
            is_volatile=True if mac else False,
        )

        peer.record_event("peer_created", mac=mac, ips=list(ips))
        self.peers[peer.internal_id] = peer

        if mac:
            self.mac_to_id[mac] = peer.internal_id
        for ip in ips:
            self.ip_to_id[ip] = peer.internal_id

        return peer

    def _update_peer(
        self,
        peer: Peer,
        mac: str | None,
        ips: set[str],
        data: NormalisedData,
        embeddings: PeerEmbeddings,
    ):
        peer.metadata_history.append(peer.metadata)
        peer.metadata = data
        peer.embeddings = embeddings

        if mac and peer.mac_address and mac != peer.mac_address:
            peer.suspicion_score += 0.5
            peer.record_event("mac_conflict", old_mac=peer.mac_address, new_mac=mac)
            logging.warning(f"MAC conflict for peer {peer.internal_id}")

        if mac and not peer.mac_address:
            peer.mac_address = mac
            peer.is_volatile = False
            self.mac_to_id[mac] = peer.internal_id
            peer.record_event("mac_promoted", mac=mac)

        for ip in ips:
            if ip not in peer.ips:
                peer.ips.add(ip)
                peer.record_event("ip_added", ip=ip)
            self.ip_to_id[ip] = peer.internal_id

    def _resolve_conflict(
        self,
        candidate_ids: set[str],
        mac: str | None,
        ips: set[str],
        data: NormalisedData,
        embeddings: PeerEmbeddings,
    ) -> Peer:
        # Choose highest confidence peer as survivor
        peers = [self.peers[i] for i in candidate_ids]
        survivor = max(peers, key=lambda p: p.is_volatile)
        print(f"conflicting peers: {peers}")
        print("Check this as it might be broken")

        survivor.suspicion_score += 1
        survivor.record_event(
            "identity_conflict_detected", conflicting_peers=list(candidate_ids)
        )
        logging.warning(f"Identity conflict detected; survivor={survivor.internal_id}")

        for peer in peers:
            if peer.internal_id == survivor.internal_id:
                pass
            self._merge_peers(survivor, peer)

        print(f"Resolving conflict between {peers}")
        self._update_peer(survivor, mac, ips, data, embeddings)
        return survivor

    def _merge_peers(self, survivor: Peer, ghost: Peer):
        survivor.metadata_history.append(ghost.metadata)
        survivor.metadata_history.extend(ghost.metadata_history)

        survivor.identity_history.extend(ghost.identity_history)
        survivor.suspicion_score += ghost.suspicion_score

        for ip in ghost.ips:
            survivor.ips.add(ip)
            self.ip_to_id[ip] = survivor.internal_id

        if ghost.mac_address and not survivor.mac_address:
            survivor.mac_address = ghost.mac_address
            self.mac_to_id[survivor.mac_address] = survivor.internal_id

        survivor.record_event("peer_merged", ghost_id=ghost.internal_id)

        del self.peers[ghost.internal_id]

    @staticmethod
    def _compare_peers(
        prev: PeerEmbeddings, incoming: PeerEmbeddings
    ) -> PeerStore.EmbeddingComparison:  # noqa: F821
        os_sim = PeerStore._cosine_similarity(prev.os, incoming.os)
        port_sim = PeerStore._cosine_similarity(prev.port_set, incoming.port_set)
        service_sim = PeerStore._cosine_similarity(prev.services, incoming.services)

        events = []

        if os_sim < OS_SIMILARITY_THRESHOLD:
            events.append("os_fingerprint_changed")

        if port_sim < PORT_SIMILARITY_THRESHOLD:
            events.append("port_fingerprint_changed")

        if service_sim < SERVICE_SIMILARITY_THRESHOLD:
            events.append("service_fingerprint_changed")

        overall = 0.5 * os_sim + 0.3 * port_sim + 0.2 * service_sim

        if os_sim < 0.7 and port_sim < 0.7 and service_sim < 0.7:
            events.append("full_identity_shift")

        return PeerStore.EmbeddingComparison(
            os_similarity=os_sim,
            port_similarity=port_sim,
            service_similarity=service_sim,
            overall_score=overall,
            events=events,
        )

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))

    # --------------------
    # Normalization helpers
    # --------------------

    @staticmethod
    def _normalise_mac(mac: str | None) -> str | None:
        if not mac or mac == UNKNOWN_KEY:
            return None
        return mac

    @staticmethod
    def _extract_ips(data: NormalisedData) -> set[str]:
        ips = set()
        if data.ipv4 and data.ipv4 != UNKNOWN_KEY:
            ips.add(data.ipv4)
        if data.ipv6 and data.ipv6 != UNKNOWN_KEY:
            ips.add(data.ipv6)
        return ips

    def __str__(self) -> str:
        return (
            f"PeerStore({len(self.peers)} peers: "
            + ", ".join(str(p) for p in self.peers.values())
            + ")"
        )
