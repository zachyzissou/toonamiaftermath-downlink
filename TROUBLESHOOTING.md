# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with Toonami Aftermath Downlink.

## 🚨 Common Issues

### Application Won't Start

**Symptoms**: Container fails to start or crashes immediately

**Possible Causes & Solutions**:

1. **Port already in use**
   ```bash
   # Check what's using port 7004
   sudo lsof -i :7004
   # or
   netstat -tulpn | grep 7004
   
   # Solution: Use a different port
   docker run -p 7005:7004 toonami-downlink
   ```

2. **Missing data directory**
   ```bash
   # Create data directory
   mkdir -p ./data
   chmod 755 ./data
   
   # Run with proper volume mount
   docker run -v $(pwd)/data:/data toonami-downlink
   ```

3. **CLI binary not found**
   ```bash
   # Check if binary exists in container
   docker run --rm toonami-downlink ls -la /usr/local/bin/
   
   # Rebuild image if binary is missing
   docker build --no-cache -t toonami-downlink .
   ```

4. **Container marked as unhealthy**
   ```bash
   # Check container health status
   docker ps
   docker inspect <container_name> | grep -A 10 Health
   
   # View health check logs (raw JSON, works without jq)
   docker inspect <container_name> --format='{{json .State.Health}}'
   
   # Optional: pretty-print with jq (install with your package manager, e.g. `sudo apt-get install jq`)
   # docker inspect <container_name> --format='{{json .State.Health}}' | jq
   
   # This issue is fixed in the latest version. If you're experiencing this,
   # ensure you're using the latest image:
   docker pull ghcr.io/zachyzissou/toonamiaftermath-downlink:latest
   ```

### No Channels Loading

**Symptoms**: Channel list shows "Loading..." or "No channels available"

**Debugging Steps**:

1. **Check CLI binary execution**
   ```bash
   # Run CLI manually in container
   docker exec -it <container_name> /usr/local/bin/toonamiaftermath-cli --help
   ```

2. **Check data directory permissions**
   ```bash
   # Ensure data directory is writable
   ls -la ./data/
   
   # Fix permissions if needed
   sudo chown -R 1000:1000 ./data/
   ```

3. **Check application logs**
   ```bash
   # View container logs
   docker logs <container_name>
   
   # Follow logs in real-time
   docker logs -f <container_name>
   ```

4. **Manual refresh**
   - Click "Refresh now" button in the UI
   - Or call the API: `curl -X POST http://localhost:7004/refresh`
   - If `APP_REFRESH_TOKEN` is configured: `curl -X POST -H "X-Admin-Token: <token>" http://localhost:7004/refresh`

### API Endpoints Not Working

**Symptoms**: 404 errors, failed requests

**Troubleshooting**:

1. **Check health endpoint**
   ```bash
   curl http://localhost:7004/health
   ```

2. **Verify container is running**
   ```bash
   docker ps
   docker inspect <container_name>
   ```

3. **Check port mapping**
   ```bash
   docker port <container_name>
   ```

### Xtreme Codes Authentication Issues

**Symptoms**: "Invalid credentials" errors

**Solutions**:

1. **Get current credentials**
   ```bash
   curl http://localhost:7004/credentials
   ```

2. **Regenerate credentials**
   ```bash
   # Stop container
   docker stop <container_name>
   
   # Remove credentials file
   rm ./data/credentials.json
   
   # Restart container (new credentials will be generated)
   docker start <container_name>
   ```

### Performance Issues

**Symptoms**: Slow response times, high resource usage

**Optimization Steps**:

1. **Check resource usage**
   ```bash
   docker stats <container_name>
   ```

2. **Monitor API response times**
   ```bash
   time curl http://localhost:7004/status
   time curl http://localhost:7004/channels
   ```

3. **Check cache efficiency**
   - Look for cache hits in logs
   - Verify TTL settings are appropriate

## 🔍 Diagnostic Tools

### Health Check

The application provides a comprehensive health endpoint:

```bash
curl http://localhost:7004/health | jq
```

**Response Codes**:
- `200`: Healthy
- `503`: Unhealthy (critical failures)
- `503`: Degraded (warnings but functional)

### Status Information

Get application status and statistics:

```bash
curl http://localhost:7004/status | jq
```

### Log Analysis

**Important log patterns to look for**:

```bash
# CLI execution issues
docker logs <container> 2>&1 | grep "CLI execution failed"

# File generation problems
docker logs <container> 2>&1 | grep "Failed to write"

# Network issues
docker logs <container> 2>&1 | grep "timeout"

# Permission errors
docker logs <container> 2>&1 | grep "Permission denied"
```

## 🐳 Docker-Specific Issues

### Build Failures

1. **Context too large**
   ```bash
   # Check .dockerignore
   cat .dockerignore
   
   # Verify build context size
   du -sh .
   ```

2. **Network issues during build**
   ```bash
   # Retry with --no-cache
   docker build --no-cache .
   
   # Use different DNS
   docker build --dns 8.8.8.8 .
   ```

### Container Networking

1. **Can't access from host**
   ```bash
   # Check port binding
   docker port <container_name>
   
   # Test from within container
   docker exec <container_name> curl http://localhost:7004/health
   ```

2. **DNS resolution issues**
   ```bash
   # Test DNS from container
   docker exec <container_name> nslookup google.com
   ```

## 📱 Frontend Issues

### JavaScript Errors

**Check browser console** (F12 → Console tab):

Common errors and solutions:

1. **"Failed to load /assets/app.js"**
   - Static files not served correctly
   - Check container logs for file serving errors

2. **"Copy to clipboard failed"**
   - HTTPS required for clipboard API
   - Test with localhost or add HTTPS

3. **"Failed to load /status"**
   - API endpoints not responding
   - Check backend health

### Mobile Issues

1. **Touch targets too small**
   - Zoom out/in to test responsiveness
   - Check CSS media queries

2. **Viewport issues**
   - Verify meta viewport tag
   - Test on various screen sizes

## 🔧 Environment-Specific Issues

### Alpine Linux

1. **Library compatibility**
   ```bash
   # Check if required libraries are installed
   docker exec <container> ldd /usr/local/bin/toonamiaftermath-cli
   
   # Install missing libraries
   docker exec <container> apk add libc6-compat gcompat libstdc++
   ```

### ARM64/Apple Silicon

1. **Architecture mismatch**
   ```bash
   # Build for specific platform
   docker build --platform linux/amd64 .
   
   # Or use buildx for multi-platform
   docker buildx build --platform linux/amd64,linux/arm64 .
   ```

### Windows

1. **Path separator issues**
   ```powershell
   # Use forward slashes in paths
   docker run -v ${PWD}/data:/data toonami-downlink
   ```

2. **Line ending issues**
   ```bash
   # Configure git to handle line endings
   git config core.autocrlf input
   ```

## 📊 Performance Monitoring

### Key Metrics to Monitor

1. **Response Times**
   ```bash
   # API endpoints
   curl -w "@curl-format.txt" -o /dev/null -s http://localhost:7004/status
   ```

2. **Memory Usage**
   ```bash
   docker stats --no-stream <container_name>
   ```

3. **Cache Hit Rates**
   - Check logs for cache effectiveness
   - Monitor channel parsing frequency

### Performance Optimization

1. **Increase cache TTL** (if data doesn't change frequently)
2. **Add more memory** to container if needed
3. **Use SSD storage** for data directory
4. **Monitor network latency** to external services

## 🚑 Emergency Recovery

### Container Won't Start

```bash
# Force remove and recreate
docker rm -f <container_name>
docker run -d --name toonami-downlink -p 7004:7004 -v $(pwd)/data:/data toonami-downlink

# Or start in interactive mode for debugging
docker run -it --rm toonami-downlink sh
```

### Complete Reset

```bash
# Backup data (optional)
cp -r ./data ./data-backup

# Remove all data
rm -rf ./data/*

# Remove container and image
docker rm -f <container_name>
docker rmi toonami-downlink

# Rebuild and restart
docker build -t toonami-downlink .
docker run -d --name toonami-downlink -p 7004:7004 -v $(pwd)/data:/data toonami-downlink
```

### Data Corruption

```bash
# Check file integrity
ls -la ./data/
file ./data/index.m3u ./data/index.xml

# Remove corrupted files (they'll be regenerated)
rm ./data/index.m3u ./data/index.xml ./data/state.json

# Force regeneration
curl -X POST http://localhost:7004/refresh
```

## 🆘 Getting Help

### Before Asking for Help

1. **Check this troubleshooting guide**
2. **Search existing issues** on GitHub
3. **Collect diagnostic information**:
   ```bash
   # System information
   docker version
   docker info
   uname -a
   
   # Application logs
   docker logs <container_name> > logs.txt
   
   # Health check
   curl http://localhost:7004/health > health.json
   ```

### When Reporting Issues

Include the following information:

- **Environment**: OS, Docker version, hardware
- **Setup**: docker-compose.yml or run command used
- **Error messages**: Full error logs
- **Steps to reproduce**: What actions led to the issue
- **Expected behavior**: What should have happened
- **Actual behavior**: What actually happened

### Support Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community support
- **Documentation**: Check README.md and other docs

---

**Remember**: Most issues are related to file permissions, network connectivity, or missing dependencies. Start with the basics before diving into complex debugging! 🔍✨
