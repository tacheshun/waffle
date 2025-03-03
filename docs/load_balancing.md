# Load Balancing in Waffle

Waffle includes a powerful load balancing feature that allows you to distribute traffic across multiple backend servers. This can improve reliability, performance, and scalability of your applications.

## Load Balancing Strategies

Waffle supports three load balancing strategies:

### 1. Round Robin (Default)

The round-robin strategy distributes requests sequentially across all available backend servers in a circular order. This is the simplest strategy and works well when all backend servers have similar capabilities and workloads.

```bash
waffle -listen :8080 -backends http://app1:3000,http://app2:3000 -lb-strategy round-robin
```

### 2. IP Hash

The IP hash strategy uses the client's IP address to determine which backend server should handle the request. This ensures that requests from the same client are consistently routed to the same backend server, which can be useful for maintaining session state.

```bash
waffle -listen :8080 -backends http://app1:3000,http://app2:3000 -lb-strategy ip-hash
```

### 3. Least Connections

The least connections strategy routes requests to the backend server with the fewest active connections. This can help distribute load more evenly, especially when some requests take longer to process than others.

```bash
waffle -listen :8080 -backends http://app1:3000,http://app2:3000 -lb-strategy least-connections
```

## Configuration

### Command Line Options

- `-backends`: A comma-separated list of backend server URLs
- `-lb-strategy`: The load balancing strategy to use (round-robin, ip-hash, or least-connections)

### Example

```bash
waffle -listen :8080 -backends http://app1:3000,http://app2:3000,http://app3:3000 -lb-strategy least-connections
```

## Combining with Other Features

Load balancing can be combined with other Waffle features:

### With TLS Termination

```bash
waffle -listen :443 -backends http://app1:3000,http://app2:3000 -lb-strategy round-robin -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem
```

### With Configuration File

```bash
waffle -backends http://app1:3000,http://app2:3000 -lb-strategy ip-hash -config config.yaml
```

## Health Checks and Failover

Currently, Waffle does not include automatic health checks or failover capabilities. If a backend server becomes unavailable, requests to that server may fail. Future versions of Waffle may include these features.

## Best Practices

1. **Similar Backend Configurations**: For best results with round-robin load balancing, ensure all backend servers have similar configurations and capabilities.

2. **Session Persistence**: If your application requires session persistence, use the IP hash strategy to ensure clients are consistently routed to the same backend.

3. **Monitoring**: Monitor the performance and health of all backend servers to ensure they're functioning properly.

4. **Scaling**: Add or remove backend servers as needed to handle changes in traffic volume.

## Limitations

- Waffle does not currently support weighted load balancing.
- Health checks and automatic failover are not currently supported.
- Sticky sessions based on cookies are not currently supported.

These features may be added in future versions of Waffle. 