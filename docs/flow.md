# Waffle System Architecture

This document illustrates how Waffle integrates into various application architectures to provide Web Application Firewall (WAF) protection.

## Architecture Overview

Waffle can be integrated into your application stack in two primary ways:
1. As a middleware component within your application
2. As a standalone reverse proxy in front of your application

The diagrams below illustrate both approaches.

## Middleware Integration

```mermaid
graph TD
    classDef client fill:#B2D3C2,stroke:#333,stroke-width:1px
    classDef waffle fill:#FF9966,stroke:#333,stroke-width:2px,color:black
    classDef app fill:#AED6F1,stroke:#333,stroke-width:1px
    classDef db fill:#D7BDE2,stroke:#333,stroke-width:1px
    
    A[Client/Browser] --> B[Load Balancer]
    B --> C[Application Server]
    C --> D[Waffle Middleware]:::waffle
    D -- Valid Requests --> E[Application Logic]
    D -- Blocked --> F[Block Handler]
    E --> G[(Database)]:::db
    E --> H[Cache]:::db
    E --> I[External Services]
    
    class A,B client
    class C,E,F app
    
    subgraph "Your Application"
        C
        D
        E
        F
    end
```

In this configuration, Waffle operates as middleware within your application, inspecting and filtering requests before they reach your application logic.

### Middleware Integration Examples

#### Standard Go HTTP Server

```mermaid
sequenceDiagram
    participant Client
    participant Server as HTTP Server
    participant Waffle as Waffle Middleware
    participant Handler as Request Handler
    participant DB as Database
    
    Client->>Server: HTTP Request
    Server->>Waffle: Forward Request
    
    alt Malicious Request
        Waffle->>Client: 403 Forbidden
    else Valid Request
        Waffle->>Handler: Forward Request
        Handler->>DB: Query Data
        DB->>Handler: Return Data
        Handler->>Client: HTTP Response
    end
```

#### Gin Framework Integration

```mermaid
sequenceDiagram
    participant Client
    participant Gin as Gin Router
    participant Waffle as Waffle Middleware
    participant Handlers as Gin Handlers
    participant DB as Database
    
    Client->>Gin: HTTP Request
    Gin->>Waffle: Process Request
    
    alt Malicious Request
        Waffle->>Gin: Abort with 403
        Gin->>Client: 403 Forbidden
    else Valid Request
        Waffle->>Gin: Continue
        Gin->>Handlers: Execute Handler Chain
        Handlers->>DB: Query Data
        DB->>Handlers: Return Data
        Handlers->>Client: HTTP Response
    end
```

## Standalone Proxy Mode

```mermaid
graph TD
    classDef client fill:#B2D3C2,stroke:#333,stroke-width:1px
    classDef waffle fill:#FF9966,stroke:#333,stroke-width:2px,color:black
    classDef app fill:#AED6F1,stroke:#333,stroke-width:1px
    classDef db fill:#D7BDE2,stroke:#333,stroke-width:1px
    
    A[Client/Browser] --> B[Load Balancer/CDN]
    B --> C[Waffle WAF]:::waffle
    C -- Valid Requests --> D[Application Servers]
    C -- Blocked --> Z[Blocked Response]
    D --> E[Web Server 1]:::app
    D --> F[Web Server 2]:::app
    D --> G[Web Server 3]:::app
    E & F & G --> H[(Database)]:::db
    E & F & G --> I[Cache]:::db
    E & F & G --> J[API Services]
    
    class A,B client
```

In this standalone configuration, Waffle operates as a reverse proxy in front of your application servers, filtering all incoming requests before they reach your application.

### Standalone Proxy Example

```mermaid
sequenceDiagram
    participant Client
    participant Waffle as Waffle Proxy
    participant App as Application Server
    participant DB as Database
    
    Client->>Waffle: HTTP Request
    
    alt Malicious Request
        Waffle->>Client: 403 Forbidden
    else Valid Request
        Waffle->>App: Forward Request
        App->>DB: Query Data
        DB->>App: Return Data
        App->>Waffle: HTTP Response
        Waffle->>Client: HTTP Response
    end
```

## Rate Limiting Behavior

```mermaid
sequenceDiagram
    participant Client
    participant Waffle
    participant App as Application
    
    Client->>Waffle: Request 1
    Waffle->>App: Forward Request
    App->>Waffle: Response
    Waffle->>Client: Response
    
    Client->>Waffle: Request 2
    Waffle->>App: Forward Request
    App->>Waffle: Response
    Waffle->>Client: Response
    
    Client->>Waffle: Request 3 (Rate Limit Exceeded)
    Waffle->>Client: 429 Too Many Requests
    Note over Waffle,Client: Includes Retry-After header
```

## Enterprise Deployment Example

For a more complex enterprise deployment, Waffle can be deployed at multiple layers:

```mermaid
graph TD
    classDef client fill:#B2D3C2,stroke:#333,stroke-width:1px
    classDef waffle fill:#FF9966,stroke:#333,stroke-width:2px,color:black
    classDef app fill:#AED6F1,stroke:#333,stroke-width:1px
    classDef db fill:#D7BDE2,stroke:#333,stroke-width:1px
    classDef network fill:#F9E79F,stroke:#333,stroke-width:1px
    
    A[Internet] --> B[CDN/Edge]
    B --> C[DDoS Protection]
    
    subgraph "DMZ"
        C --> D[Border Firewall]
        D --> E[Edge Load Balancer]
        E --> F[Waffle WAF Cluster]:::waffle
    end
    
    subgraph "Application Tier"
        F --> G[Internal Load Balancer]
        G --> H[API Gateway]
        H --> I[Service Mesh]
        
        subgraph "Web Services"
            I --> J[Web Service 1]:::app
            I --> K[Web Service 2]:::app
            J & K --> L[Waffle Middleware]:::waffle
        end
        
        subgraph "Microservices"
            I --> M[Service 1]:::app
            I --> N[Service 2]:::app
            I --> O[Service 3]:::app
        end
    end
    
    subgraph "Data Tier"
        L --> P[(Primary Database)]:::db
        L --> Q[Cache Cluster]:::db
        M & N & O --> P
        M & N & O --> Q
    end
    
    class A,B,C,D,E,G,H,I network
```

## Waffle Internal Architecture

Waffle's internal architecture is designed to be modular, efficient, and flexible. The following diagram illustrates the components that make up the Waffle WAF:

```mermaid
graph TD
    classDef core fill:#FF9966,stroke:#333,stroke-width:2px,color:black
    classDef module fill:#AED6F1,stroke:#333,stroke-width:1px
    classDef rules fill:#D7BDE2,stroke:#333,stroke-width:1px
    
    A[HTTP Request] --> B[Waffle Core]:::core
    
    subgraph "Waffle Engine"
        B --> C[Rules Engine]:::module
        C --> D[Default Rules]:::rules
        C --> E[Custom Rules]:::rules
        C --> F[Rule Groups]:::rules
        
        B --> G[Rate Limiter]:::module
        G --> H[Token Bucket]
        G --> I[IP Extraction]
        
        B --> J[Attack Detectors]:::module
        J --> K[SQL Injection]
        J --> L[XSS]
        J --> M[Path Traversal]
        J --> N[Command Injection]
        
        B --> O[Logger]:::module
        O --> P[Attack Logging]
        O --> Q[Request Logging]
        O --> R[Error Logging]
    end
    
    B --> S[Block Handler]
    B --> T[Next Handler]
    
    S --> U[Blocked Response]
    T --> V[Application Logic]
```

### Component Flow

The request processing flow in Waffle proceeds as follows:

```mermaid
sequenceDiagram
    participant Request
    participant Waffle as Waffle Core
    participant Limiter as Rate Limiter
    participant Rules as Rules Engine
    participant Detectors as Attack Detectors
    participant Logger
    participant Next as Next Handler
    
    Request->>Waffle: HTTP Request
    
    Waffle->>Logger: Log Request
    
    Waffle->>Limiter: Check Rate Limits
    alt Rate Limit Exceeded
        Limiter->>Waffle: Reject (429)
        Waffle->>Logger: Log Rate Limit Block
        Waffle->>Request: 429 Too Many Requests
    else Within Rate Limits
        Limiter->>Waffle: Allow
        
        Waffle->>Rules: Apply Rules
        alt Rules Match
            Rules->>Waffle: Block (403)
            Waffle->>Logger: Log Attack
            Waffle->>Request: 403 Forbidden
        else No Rule Matches
            Rules->>Waffle: Allow
            
            Waffle->>Detectors: Apply Detection
            alt Attack Detected
                Detectors->>Waffle: Block (403)
                Waffle->>Logger: Log Attack
                Waffle->>Request: 403 Forbidden
            else No Attack Detected
                Detectors->>Waffle: Allow
                Waffle->>Next: Forward Request
                Next->>Request: HTTP Response
            end
        end
    end
```

### Key Components

1. **Core Engine**: Orchestrates the request processing pipeline and integrates all components.

2. **Rules Engine**: 
   - Evaluates HTTP requests against configurable rules
   - Supports regex patterns, IP-based rules, and custom rule implementations
   - Organizes rules into logical groups for better management

3. **Rate Limiter**:
   - Implements token bucket algorithm for rate limiting
   - Supports per-IP rate limiting
   - Configurable rate and burst parameters

4. **Attack Detectors**:
   - Specialized modules for detecting specific attack vectors
   - SQL Injection detection
   - XSS detection
   - Path traversal detection
   - Command injection detection

5. **Logger**:
   - Detailed logging of attacks and suspicious activity
   - Request logging for audit trails
   - Error logging for troubleshooting

6. **Middleware Adapters**:
   - Standard HTTP middleware
   - Gin framework adapter
   - Echo framework adapter

7. **Proxy Mode**:
   - Standalone reverse proxy functionality
   - Configuration via YAML/JSON 