#!/usr/bin/env python3
"""Mock toonamiaftermath-cli for testing"""

import sys
import os
from pathlib import Path

def create_mock_m3u(output_path: str):
    """Create a mock M3U file for testing."""
    m3u_content = """#EXTM3U
#EXTINF:-1 tvg-id="toonami1" tvg-chno="1" tvg-name="Toonami Aftermath",Toonami Aftermath
https://video-weaver.fra05.hls.ttvnw.net/v1/segment/stream1.m3u8
#EXTINF:-1 tvg-id="toonami2" tvg-chno="2" tvg-name="Toonami Classics",Toonami Classics  
https://video-weaver.fra05.hls.ttvnw.net/v1/segment/stream2.m3u8
#EXTINF:-1 tvg-id="toonami3" tvg-chno="3" tvg-name="Toonami Movies",Toonami Movies
https://video-weaver.fra05.hls.ttvnw.net/v1/segment/stream3.m3u8
"""
    with open(output_path, 'w') as f:
        f.write(m3u_content)

def create_mock_xml(output_path: str):
    """Create a mock XMLTV file for testing."""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<tv>
  <channel id="toonami1">
    <display-name>Toonami Aftermath</display-name>
  </channel>
  <channel id="toonami2">
    <display-name>Toonami Classics</display-name>
  </channel>
  <channel id="toonami3">
    <display-name>Toonami Movies</display-name>
  </channel>
  <programme start="20250809120000 +0000" stop="20250809130000 +0000" channel="toonami1">
    <title>Current Programming</title>
    <desc>Live Toonami Aftermath stream</desc>
  </programme>
</tv>
"""
    with open(output_path, 'w') as f:
        f.write(xml_content)

def main():
    if len(sys.argv) < 2:
        print("Mock toonamiaftermath-cli v1.1.1")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "run":
        # Parse arguments
        m3u_output = "index.m3u"
        xml_output = "index.xml"
        
        for i, arg in enumerate(sys.argv):
            if arg == "-m" and i + 1 < len(sys.argv):
                m3u_output = sys.argv[i + 1]
            elif arg == "-x" and i + 1 < len(sys.argv):
                xml_output = sys.argv[i + 1]
        
        print(f"Generating M3U: {m3u_output}")
        print(f"Generating XML: {xml_output}")
        
        create_mock_m3u(m3u_output)
        create_mock_xml(xml_output)
        
        print("Files generated successfully")
        sys.exit(0)
    
    elif command == "--version":
        print("toonamiaftermath-cli v1.1.1 (mock)")
        sys.exit(0)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()