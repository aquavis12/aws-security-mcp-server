#!/usr/bin/env python3
"""Simple test script to verify the AWS Security MCP Server works."""

import asyncio
import json
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from aws_security_mcp.server import AWSSecurityMCPServer

async def test_server():
    """Test the server initialization and tool listing."""
    try:
        print("Initializing AWS Security MCP Server...")
        server = AWSSecurityMCPServer()
        
        print("Getting available tools...")
        tools = server.get_available_tools()
        
        print(f"Successfully initialized server with {len(tools)} tools:")
        for tool in tools[:5]:  # Show first 5 tools
            print(f"  - {tool.name}: {tool.description}")
        
        if len(tools) > 5:
            print(f"  ... and {len(tools) - 5} more tools")
        
        print("\nServer is working correctly!")
        return True
        
    except Exception as e:
        print(f"Error testing server: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_server())
    sys.exit(0 if success else 1)