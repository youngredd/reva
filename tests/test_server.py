"""The MCP server, driven over real stdio JSON-RPC."""
import json
import os
import subprocess
import sys

import pytest

from conftest import NOTEPAD, needs_notepad


class Client:
    """Minimal newline-delimited JSON-RPC client, so the test exercises the
    actual transport rather than calling the functions directly."""

    def __init__(self):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        self.p = subprocess.Popen(
            [sys.executable, "-m", "reva.server"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, text=True,
            encoding="utf-8", bufsize=1)
        self._id = 0
        r = self.send("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1"}})
        self.server_info = r["result"]["serverInfo"]
        self.send("notifications/initialized", {}, notify=True)

    def send(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._id += 1
            msg["id"] = self._id
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        if notify:
            return None
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError(
                    f"server exited.\nstderr:\n{self.p.stderr.read()[:3000]}")
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("id") == self._id:
                return r

    def tools(self):
        return self.send("tools/list", {})["result"]["tools"]

    def call(self, _tool, **args):
        r = self.send("tools/call", {"name": _tool, "arguments": args})
        res = r["result"]
        txt = "\n".join(c.get("text", "") for c in res["content"])
        if res.get("isError"):
            raise ToolFailed(txt)
        try:
            return json.loads(txt)
        except json.JSONDecodeError:
            return txt

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()


class ToolFailed(RuntimeError):
    pass


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("srv-projects")
    os.environ["REVA_PROJECT_DIR"] = str(d)
    c = Client()
    yield c
    c.close()


def test_server_advertises_its_tools(client):
    assert client.server_info["name"] == "reva"
    names = {t["name"] for t in client.tools()}
    for expected in ("open_binary", "triage", "disasm", "decompile",
                     "list_functions", "search", "annotate", "emulate",
                     "patch", "dbg_start", "dbg_control", "dbg_inspect"):
        assert expected in names
    # every tool must carry a description, or it is unusable by an agent
    for t in client.tools():
        assert t.get("description"), f"{t['name']} has no description"


def test_tool_errors_carry_their_reason(client):
    """Only ToolError messages reach the caller; anything else arrives as a
    generic crash, which makes the tool undiagnosable."""
    with pytest.raises(ToolFailed, match="no binary is open"):
        client.call("disasm", at="0x1000")


@needs_notepad
def test_full_flow(client):
    info = client.call("open_binary", path=NOTEPAD)
    assert info["counts"]["functions"] > 300

    t = client.call("triage", top_functions=3)
    assert t["identity"]["arch"] == "x86_64"
    assert len(t["start_here"]) == 3

    lf = client.call("list_functions", sort="risk", limit=3)
    assert len(lf["functions"]) == 3
    va = lf["functions"][0]["va"]

    # annotate, then prove the name is usable as an address everywhere else
    client.call("annotate", at=va, name="RevaTestName",
                pre_comment="noted by the test")
    fi = client.call("function_info", at="RevaTestName")
    assert fi["va"] == va
    assert fi["name"] == "RevaTestName"
    assert any("noted by the test" in c.get("pre", "")
               for c in fi["comments"].values())
    # addresses used as json keys must be hex, not decimal
    assert all(k.startswith("0x") for k in fi["comments"])

    txt = client.call("disasm", at=va, count=5)
    assert isinstance(txt, str) and len(txt.splitlines()) >= 5

    c = client.call("decompile", at=va)
    assert "lifted by reva" in c

    x = client.call("xrefs", at=va, direction="both")
    assert "xrefs_to" in x and "xrefs_from" in x


@needs_notepad
def test_bad_address_is_reported_precisely(client):
    client.call("open_binary", path=NOTEPAD)
    with pytest.raises(ToolFailed, match="cannot resolve address"):
        client.call("disasm", at="definitely_not_a_symbol", count=2)


@needs_notepad
def test_patch_round_trip_over_mcp(client):
    client.call("open_binary", path=NOTEPAD)
    a = client.call("assemble", asm="xor eax, eax; ret", at="0x1400019c0")
    assert a["bytes"] == "31c0c3"
    p = client.call("patch", at="0x1400019c0", asm="xor eax, eax", note="t")
    assert p["original"].startswith("4883")
    assert client.call("patch_control", action="list")["patches"]
    assert client.call("patch_control", action="revert_all")["reverted"] == 1
