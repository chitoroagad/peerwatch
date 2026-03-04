#! /usr/bin/env python

import glob
import json
import logging
import os
from collections import defaultdict
from pathlib import Path
from pprint import pprint
from typing import List, TextIO

import xmltodict
from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage, SystemMessage

from peerwatch import Comparator, Embedder, NmapParser, PeerStore

UNIMPORTANT_NMAP_FIELDS = [
    "@starttime",
    "@endtime",
    "distance",
    "tcpsequence",
    "ipidsequence",
    "tcptssequence",
    "times",
    "hostnames",
]

CHAT_MODELS = [
    "smollm2:135m",
    "smollm2:360m",
    "smollm2:1.7b",
    "phi4-mini:latest",
    "phi4-mini-reasoning:latest",
    "qwen3:0.6b",
    "qwen3:1.7b",
    "gemma3:270m",
    "gemma3:1b",
    "deepseek-r1:1.5b",
]

EMBEDDING_MODELS = [
    "all-minilm:22m",
    "all-minilm:33m",
    "bge-m3:latest",
    "bge-large:latest",
]

SYSTEM_PROMPTS = []
prompt_dir = Path("./prompts/")
for file_path in prompt_dir.iterdir():
    with open(file_path, "r") as f:
        SYSTEM_PROMPTS.append((file_path.name, f.read()))


logging.basicConfig(
    filename="app.log",
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def say_hi_test():
    "Simple test to check what each chat model outputs based on the system prompt"
    output_dict = defaultdict(dict)
    for model in CHAT_MODELS:
        for prompt_name, prompt in SYSTEM_PROMPTS:
            init_model = init_chat_model(model, model_provider="ollama", temperature=0)

            messages = [
                SystemMessage(content=prompt),
                HumanMessage(content="Say hi as loud as you can"),
            ]
            output = init_model.invoke(messages).content
            output_dict[model][prompt_name[:-4]] = output
            print()
            print(prompt_name)
            print(model)
            pprint(output)
            print()

    with open("./data/say_hi.json", "w") as f:
        json.dump(output_dict, f, indent=2)


def jsonify(f: TextIO):
    """
    Takes an open nmap xml file and converts it to json while removing unnecessary fields
    """
    xml_data = f.read()
    try:
        dict_data: List[dict] = xmltodict.parse(xml_data)["nmaprun"]["host"]

        for item in dict_data:
            for field in UNIMPORTANT_NMAP_FIELDS:
                item.pop(field, None)

        json_data = json.dumps(dict_data, indent=2)
        new_file_path = os.path.join("data", parse_filename(f.name)) + ".json"
        with open(new_file_path, "w") as j:
            j.write(json_data)
    except Exception as e:
        print(e)
        print(f.name)


def parse_filename(name: str) -> str:
    "Splits the name by dir separator then shaves off xml file extension"
    return os.path.split(name)[1][:-4]


if __name__ == "__main__":
    # files = glob.glob("../home_nmap_logs/*.xml")
    # for file in files:
    #     with open(file) as f:
    #         jsonify(f)
    files = glob.glob("./data/*.json")
    peer_store = PeerStore()
    embedder = Embedder("all-minilm:22m")
    # comparator = Comparator(embedder, "./data/")
    for file in files:
        with open(file) as f:
            data = json.load(f)
            for host in data:
                parser = NmapParser(host)
                normalised_data = parser.parse()
                embeddings = embedder.embed(normalised_data)
                if embeddings is not None:
                    peer_store.add_or_update_peer(normalised_data, embeddings)
                    # print("added host to peer store")

    print(peer_store)
