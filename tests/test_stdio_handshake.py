"""MCP stdio smoke test: spawns the real server over stdio, checks the tool
list, and checks that instructive errors survive the trip to the agent
(MCPServer hides any exception that isn't a ToolError)."""

import os
import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "acpi_load",
    "acpi_tables",
    "acpi_table",
    "acpi_interrupt_routing",
    "acpi_find",
    "acpi_dump",
    "acpi_disassemble",
    "acpi_sets",
}

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "tables", "q35")


@pytest.mark.anyio
async def test_tools_and_a_session_over_stdio():
    params = StdioServerParameters(command=sys.executable, args=["-m", "acpi_mcp"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "acpi"
        names = {t.name for t in (await session.list_tools()).tools}
        assert names == EXPECTED_TOOLS, (names - EXPECTED_TOOLS, EXPECTED_TOOLS - names)

        res = await session.call_tool("acpi_load", {"name": "q", "path": FIX})
        assert not res.is_error and "MCFG" in res.content[0].text
        res = await session.call_tool("acpi_find", {"name": "q", "question": "reboot"})
        assert "0xcf9" in res.content[0].text


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent():
    params = StdioServerParameters(command=sys.executable, args=["-m", "acpi_mcp"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("acpi_tables", {"name": "nope"})
        assert res.is_error and "call acpi_load first" in res.content[0].text
        res = await session.call_tool("acpi_load", {"name": "x"})
        assert res.is_error and "exactly one of port=" in res.content[0].text
        await session.call_tool("acpi_load", {"name": "q", "path": FIX})
        res = await session.call_tool("acpi_table", {"name": "q", "signature": "SRAT"})
        assert res.is_error and "Tables present:" in res.content[0].text


@pytest.fixture
def anyio_backend():
    return "asyncio"
