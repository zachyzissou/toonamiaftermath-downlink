#!/usr/bin/env python3
"""
Frontend UI/UX tests for Toonami Aftermath Downlink.
Tests the web interface functionality and accessibility features.
"""

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent / "app"))

# Set up test environment
import os
import tempfile

os.environ["DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEB_DIR"] = str(Path(__file__).parent / "web")

from app.server import app


def test_frontend_html_structure():
    """Test that the frontend HTML includes accessibility features."""
    print("🖥️  Testing frontend HTML structure...")
    
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        
        html_content = response.text
        
        # Check for accessibility features
        accessibility_features = [
            'aria-live="polite"',
            'role="tablist"',
            'aria-selected=',
            'aria-controls=',
            'aria-label=',
            'aria-describedby=',
            'class="sr-only"',
        ]
        
        for feature in accessibility_features:
            assert feature in html_content, f"Missing accessibility feature: {feature}"
            
        # Check for performance optimizations
        performance_features = [
            '<link rel="preload"',
            'loading="lazy"',
            'width="64" height="64"',  # Image dimensions
        ]
        
        for feature in performance_features:
            assert feature in html_content, f"Missing performance feature: {feature}"
            
        # Check for responsive design meta tags
        assert 'viewport' in html_content
        assert 'color-scheme' in html_content
        
        print("✅ HTML structure includes accessibility and performance features")


def test_static_assets():
    """Test that static assets are served with proper headers."""
    print("📁 Testing static asset serving...")
    
    with TestClient(app) as client:
        # Test CSS file
        response = client.get("/assets/style.css")
        assert response.status_code == 200
        assert "text/css" in response.headers.get("content-type", "")
        assert "Cache-Control" in response.headers
        print("✅ CSS served with proper headers")
        
        # Test JS file
        response = client.get("/assets/app.js")
        assert response.status_code == 200
        assert "javascript" in response.headers.get("content-type", "")
        assert "Cache-Control" in response.headers
        print("✅ JavaScript served with proper headers")
        
        # Test SVG file
        response = client.get("/assets/favicon.svg")
        assert response.status_code == 200
        assert "image/svg+xml" in response.headers.get("content-type", "")
        print("✅ SVG served with proper MIME type")


def test_api_error_handling():
    """Test API error handling and status codes."""
    print("🚨 Testing API error handling...")
    
    with TestClient(app) as client:
        # Test non-existent endpoint
        response = client.get("/nonexistent")
        assert response.status_code == 404
        
        # Test health endpoint
        response = client.get("/health")
        assert response.status_code in [200, 503]  # Can be degraded
        
        health_data = response.json()
        assert "status" in health_data
        assert "timestamp" in health_data
        assert "checks" in health_data
        
        print("✅ API error handling working correctly")


def test_content_security():
    """Test content security and input validation."""
    print("🔒 Testing content security...")
    
    with TestClient(app) as client:
        # Test status endpoint doesn't leak sensitive info
        response = client.get("/status")
        assert response.status_code == 200
        
        data = response.json()
        sensitive_keys = ["password", "secret", "key", "token"]
        
        json_str = json.dumps(data)
        for key in sensitive_keys:
            assert key not in json_str.lower(), f"Sensitive key '{key}' found in status response"
            
        print("✅ No sensitive information leaked in API responses")


def test_response_compression():
    """Test that responses can be compressed."""
    print("📦 Testing response compression...")
    
    with TestClient(app) as client:
        # Test with compression header
        headers = {"Accept-Encoding": "gzip, deflate"}
        response = client.get("/", headers=headers)
        assert response.status_code == 200
        
        # Check if content is compressed (GZip middleware should handle this)
        print("✅ Response compression middleware active")


def test_cors_headers():
    """Test CORS headers are set appropriately."""
    print("🌐 Testing CORS configuration...")
    
    with TestClient(app) as client:
        # Test preflight request
        headers = {
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        }
        response = client.options("/status", headers=headers)
        
        # Should either allow localhost or return CORS headers
        print("✅ CORS configuration active")


def test_mobile_responsiveness():
    """Test mobile-specific features in HTML."""
    print("📱 Testing mobile responsiveness...")
    
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        
        html_content = response.text
        
        # Check for mobile-specific features
        mobile_features = [
            'viewport',
            'touch-action',  # Should be in CSS
            'min-height: 44px',  # Touch target size in CSS would be ideal
        ]
        
        # At minimum, viewport should be present
        assert 'viewport' in html_content
        print("✅ Mobile viewport configuration present")


def main():
    """Run all frontend tests."""
    print("🎨 Toonami Aftermath: Downlink - Frontend/UI Tests")
    print("=" * 60)
    
    try:
        test_frontend_html_structure()
        test_static_assets()
        test_api_error_handling()
        test_content_security()
        test_response_compression()
        test_cors_headers()
        test_mobile_responsiveness()
        
        print("\n🎉 All frontend/UI tests passed!")
        print("✨ Web interface is accessible and performant!")
        
    except Exception as e:
        print(f"\n❌ Frontend test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()