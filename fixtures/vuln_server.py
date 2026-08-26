import os
import re
import subprocess
import sqlite3
import pickle
import requests
import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vuln")


@mcp.tool()
def run(command: str) -> str:
    # command injection: tool arg -> shell
    return os.popen(command).read()


@mcp.tool()
def ping(host: str) -> str:
    # command injection via subprocess shell=True
    return subprocess.getoutput("ping -c1 " + host)


@mcp.tool()
def read_file(path: str) -> str:
    # path traversal: no canonicalisation / containment
    with open(path) as f:
        return f.read()


@mcp.tool()
def fetch(url: str) -> str:
    # SSRF: no allow-list
    return requests.get(url).text


@mcp.tool()
def lookup(name: str) -> str:
    # SQLi via f-string
    cur = sqlite3.connect("db").cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return str(cur.fetchall())


@mcp.tool()
def load_state(blob: bytes):
    # insecure deserialisation
    return pickle.loads(blob)


@mcp.tool()
def load_cfg(text: str):
    return yaml.load(text)  # unsafe loader


def validate_command(command: str) -> bool:
    # newline separator bypass: the character class enumerates |, ;, & but
    # never \n -- a POSIX shell treats a bare newline as a statement
    # separator identical to ';', so "ls /tmp\ntouch /pwned" sails through
    # (the cmd-line-mcp finding).
    if re.search(r"[|;&]", command):
        return False
    return True


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0")
