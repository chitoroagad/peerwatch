import logging
from datetime import datetime

from langchain_ollama import OllamaEmbeddings
from pydantic import BaseModel, Field

from parser import NormalisedData


class Embedder:
    class HostPreEmbedding(BaseModel):
        os: str
        port_set: str
        services: str

    class HostEmbedding(BaseModel):
        os: list[float]
        port_set: list[float]
        services: list[float]
        generated_at: datetime = Field(default_factory=datetime.now)

    def __init__(self, model_name: str):
        self.model = OllamaEmbeddings(model=model_name)

    def embed(self, normalised_host_data: NormalisedData) -> HostEmbedding | None:
        data = self._prep_to_embed(normalised_host_data)
        if data is None:
            logging.warning(f"Could not prep to embed {normalised_host_data}")
            return

        os_embedding = self.model.embed_query(data.os)
        ports_embedding = self.model.embed_query(data.port_set)
        services_embedding = self.model.embed_query(data.services)

        return self.HostEmbedding(
            os=os_embedding, port_set=ports_embedding, services=services_embedding
        )

    def _format_service_preembedding(self, port: int, service: str) -> str:
        service_split = service.split("-")
        if service == "":
            return ""
        if len(service_split) < 2:
            return f"port {port} runs {service} service\n"

        protocol = service_split[0]
        service = service_split[1]
        return f"port {port} runs {protocol} server {service}\n"

    def _prep_to_embed(self, host: NormalisedData):
        services = ""
        open_ports = f"open tcp ports: {host.open_ports}"
        os = f"this host is os: {host.os}\nversion: {host.os_version}\ndistribution: {host.distribution}\ndevice_vendor: {host.device_vendor}"

        for port, service in host.services.items():
            services += self._format_service_preembedding(port, service)

        return self.HostPreEmbedding(
            os=os,
            port_set=open_ports,
            services=services,
        )
