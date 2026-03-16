# Fund Transfer — Microservices Platform

A reactive microservices platform for fund transfer operations built with Spring Boot 3.x, WebFlux, R2DBC, gRPC, and RabbitMQ.

---

## Architecture Overview

```
                        ┌─────────────────────────────────────────────────────┐
                        │             CLIENT (Insomnia / Browser)             │
                        └───────────────────────────┬─────────────────────────┘
                                                    │ HTTP :8080
                                                    ▼
                        ┌──────────────────────────────────────────────────────┐
                        │                     API GATEWAY                      │
                        │   Port: 8080  │  Actuator: /internal/actuator        │
                        │   ThreatDetectionFilter + AuthorizationHeaderFilter  │
                        └──────────────────┬──────────────┬────────────────────┘
                                           │              │
                              lb://user-service    lb://bank-service
                                           │              │
                   ┌───────────────────────┘              └───────────────────────┐
                   ▼                                                               ▼
  ┌──────────────────────────────┐                             ┌──────────────────────────────┐
  │        USER SERVICE          │                             │        BANK SERVICE          │
  │  Port: 9090 (HTTP)           │ ──── gRPC :9191 ──────────▶ │  Port: 9091 (HTTP)           │
  │  Actuator: /internal/actuator│                             │  Port: 9191 (gRPC)           │
  │  Schema: user_service        │                             │  Actuator: /internal/actuator│
  └──────────────┬───────────────┘                             └──────────────┬───────────────┘
                 │                                                             │
                 └───────────────────────┬───────────────────────────────────┘
                                         │ Eureka registration
                                         ▼
                        ┌─────────────────────────────────────────────────────┐
                        │               DISCOVERY SERVICE (Eureka)            │
                        │   Port: 8761  │  Actuator: /internal/actuator       │
                        └─────────────────────────────────────────────────────┘


                        ┌─────────────────────────────────────────────────────┐
                        │                  OBSERVABILITY STACK                │
                        │                                                     │
                        │  Prometheus :3001 ──────────▶ Grafana :3000         │
                        │  Loki       :3100 ──────────▶ Grafana :3000         │
                        │  Promtail          ──────────▶ Loki                 │
                        └─────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Spring Boot 3.x |
| Web | Spring WebFlux (Reactive) |
| Database ORM | Spring Data R2DBC |
| Database | PostgreSQL 15 |
| Cache | Redis |
| Message Broker | RabbitMQ 3 |
| Service Communication | gRPC |
| Service Discovery | Netflix Eureka |
| DB Migration | Liquibase |
| Security | Spring Security + JWT (JJWT HS384) |
| Input Validation | @SafeInput (XSS, SQLi, Path Traversal, etc.) |
| Output Sanitization | @SafeOutput (role-based masking, HTML encode) |
| Threat Detection | ThreatDetectionFilter (15+ attack patterns) |
| Metrics | Micrometer + Prometheus |
| Visualization | Grafana |
| Log Aggregation | Loki + Promtail |
| Containerization | Docker + Docker Compose |

---

## Services

| Service | HTTP Port | gRPC Port | Schema | Role |
|---|---|---|---|---|
| discovery-service | 8761 | — | — | Eureka Server |
| user-service | 9090 | — | user_service | Auth, User Management |
| bank-service | 9091 | 9191 | banking_service | Bank Accounts, Transactions |
| api-gateway | 8080 | — | gateway_service | Routing, Security, Threat Detection |

---

## Prerequisites

```
Java       21+
Maven      3.9+
Docker     Desktop (latest)
PostgreSQL 15 (local)
Redis      (local)
IntelliJ   IDEA (recommended)
```

---

## Quick Start

### Step 1 — Start Infrastructure (Docker)

```bash
cd fund-transfer-docker
docker compose up -d
```

### Step 2 — Start Spring Boot Services (IntelliJ)

Start in this exact order — Eureka must be first:

```
1. FundTransferDiscoveryServer   → waits for nothing
2. FundTransferUserService       → registers with Eureka
3. FundTransferBankService       → registers with Eureka
4. FundTransferApiGateway        → registers last (needs all services up)
```

### Step 3 — Verify Everything is Running

```bash
# Docker containers
docker compose ps

# Eureka dashboard
http://localhost:8761

# Prometheus targets
http://localhost:3001/targets

# Loki ready check
http://localhost:3100/ready
```

---

## Service URLs

### API Gateway (Entry Point)
```
Base URL  : http://localhost:8080
Actuator  : http://localhost:8080/internal/actuator
Health    : http://localhost:8080/internal/actuator/health
Prometheus: http://localhost:8080/internal/actuator/prometheus
```

### User Service
```
Base URL  : http://localhost:9090
Actuator  : http://localhost:9090/internal/actuator
Health    : http://localhost:9090/internal/actuator/health
Prometheus: http://localhost:9090/internal/actuator/prometheus
```

### Bank Service
```
Base URL  : http://localhost:9091
gRPC      : localhost:9191
Actuator  : http://localhost:9091/internal/actuator
Health    : http://localhost:9091/internal/actuator/health
Prometheus: http://localhost:9091/internal/actuator/prometheus
```

### Discovery Service (Eureka)
```
Dashboard : http://localhost:8761
Actuator  : http://localhost:8761/internal/actuator
Health    : http://localhost:8761/internal/actuator/health
Prometheus: http://localhost:8761/internal/actuator/prometheus
```

---

## Infrastructure URLs

### Monitoring & Observability

```
Grafana    : http://localhost:3000
             Login : admin / admin
             Prometheus datasource : http://prometheus:9090
             Loki datasource       : http://loki:3100

Prometheus : http://localhost:3001
             Targets : http://localhost:3001/targets
             Query   : http://localhost:3001/graph

Loki       : http://localhost:3100
             Ready   : http://localhost:3100/ready
```

### Message Broker

```
RabbitMQ AMQP : localhost:5672
RabbitMQ UI   : http://localhost:15672
                Login : fundtransfer / fundtransfer
                VHost : fundtransfer
```

### Database

```
PostgreSQL : localhost:5432
             Database : fund-transfer
             User     : fund-transfer
             Password : fund-transfer

Schemas:
  user_service    → users, logins
  banking_service → banks, bank_accounts, transactions, bank_daily_summary
  gateway_service → security_audit_log
```

### Cache

```
Redis : localhost:6379
        Database index: 0
```

---

## API Endpoints (via Gateway :8080)

### Auth — Public (no JWT required)

```http
POST /user-service/auth/login
Content-Type: application/json

{
  "userName": "polas",
  "password": "123456"
}
```

```http
POST /user-service/auth/register
Content-Type: application/json

{
  "userName": "sabbir",
  "password": "123456",
  "email": "sabbir@example.com",
  "firstName": "Sabbir",
  "lastName": "Rahman",
  "phone": "+8801712345678",
  "gender": "Male",
  "dateOfBirth": "1990-05-15"
}
```

### User — Protected (JWT required)

```http
POST   /user-service/user          → Create user
PUT    /user-service/user          → Update user  (body must include "active": true)
GET    /user-service/user?id={id}  → User details
POST   /user-service/user/list     → User list (paginated)
DELETE /user-service/user?id={id}  → Soft delete user
```

### Required Headers (Protected Routes)

```
Authorization : Bearer {jwt_token}
Content-Type  : application/json
```

> `X-User-Id`, `X-User-Name`, `X-User-Role` are injected by gateway — do NOT send manually.

---

## Grafana Setup

### Step 1 — Add Data Sources

**Prometheus:**
```
Grafana → Connections → Data Sources → Add → Prometheus
URL: http://prometheus:9090
→ Save & Test → ✅
```

**Loki:**
```
Grafana → Connections → Data Sources → Add → Loki
URL: http://loki:3100
→ Save & Test → ✅
```

### Step 2 — Import Dashboards

```
Grafana → Dashboards → New → Import → Enter ID → Load → Select datasource → Import
```

| ID | Name | Data Source | Shows |
|---|---|---|---|
| `4701` | JVM (Micrometer) | Prometheus | Heap, GC, Threads, CPU |
| `19004` | Spring Boot Statistics | Prometheus | HTTP requests, Response time |
| `12900` | Spring Boot APM | Prometheus | Latency p95/p99, DB pool |
| `13639` | Loki Logs | Loki | Log analysis, ERROR tracking |

### Step 3 — Select Variables

After opening a dashboard select:
```
Application → user-service / bank-service / api-gateway / discovery-service
Instance    → host.docker.internal:9090 (or relevant port)
```

---

## Key Metrics (Prometheus)

### JVM
```promql
jvm_memory_used_bytes
jvm_memory_max_bytes
jvm_gc_pause_seconds_sum
jvm_threads_live_threads
process_cpu_usage
process_uptime_seconds
```

### HTTP
```promql
http_server_requests_seconds_count
http_server_requests_seconds_max
rate(http_server_requests_seconds_count[1m])
```

### R2DBC Pool
```promql
r2dbc_pool_acquired_connections
r2dbc_pool_idle_connections
r2dbc_pool_pending_connections
r2dbc_pool_max_connections
```

### RabbitMQ
```promql
rabbitmq_connections
rabbitmq_published_total
rabbitmq_consumed_total
```

---

## Log Queries (Loki / LogQL)

```logql
# All logs from a service
{service="user-service"}

# ERROR logs only
{service="api-gateway"} |= "ERROR"

# gRPC related
{service="bank-service"} |= "gRPC"

# Security threats
{service="api-gateway"} |= "BLOCKED"
{service="api-gateway"} |= "SQL injection"
{service="api-gateway"} |= "XSS"

# JWT
{service="user-service"} |= "JWT"

# Cache
{service="user-service"} |= "Cache HIT"
{service="user-service"} |= "Cache MISS"

# All ERROR logs across all services
{env="dev"} |= "ERROR"

# Slow requests
{service="api-gateway"} |= "Slow"
```

---

## Docker Compose Commands

```bash
# Start all
docker compose up -d

# Stop all
docker compose down

# Stop and remove volumes
docker compose down -v

# View logs
docker compose logs -f promtail
docker compose logs -f loki
docker compose logs -f prometheus
docker compose logs -f grafana

# Restart single service
docker compose restart prometheus
docker compose restart loki

# Status
docker compose ps
```

---

## Security

### JWT
```
Header    : Authorization: Bearer {token}
Algorithm : HS384
Expiry    : 24 hours (access) | 7 days (refresh)
Secret    : jwt.secret in application.properties
Claims    : userId, username, role
```

### Threat Detection (ThreatDetectionFilter)
```
Rate Limit  : 100 req/min per IP | 60 req/min per user
Max Payload : 10MB

Patterns:
  XSS, SQL Injection, NoSQL Injection
  Path Traversal, Command Injection, LDAP Injection
  XML/XXE, Template/SSTI, JSON Injection
  Log4Shell/JNDI, Deserialization, HTTP Smuggling
  SSRF, Open Redirect, Host Header Injection
  CRLF Injection, DDoS, Scanner Detection

Audit Log : gateway_service.security_audit_log
```

---

## Database Schemas

### user_service
```sql
users  (id, email, first_name, last_name, phone, gender,
        date_of_birth, image_url, download_url, active,
        created_by, created_at, updated_by, updated_at)

logins (id, user_id, user_name, password,
        created_by, created_at)
```

### banking_service
```sql
banks              (id, bank_name, bank_code, swift_code, active, ...)
bank_accounts      (id, user_id, bank_id, account_number, account_type,
                    account_holder_name, balance, currency, is_primary, active, ...)
transactions       (id, from_account_id, to_account_id, amount, currency,
                    transaction_type, transaction_status, reference_number, ...)
bank_daily_summary (id, bank_id, summary_date, total_transactions, total_amount, ...)
```

### gateway_service
```sql
security_audit_log (id, ip_address, user_agent, request_path, request_method,
                    threat_type, severity, status, blocked, block_reason,
                    username, user_role, suspicious_value, message,
                    service_id, detected_at, created_at, ...)
```

---

## Redis Cache Keys

```
AUTH_CACHE:{token}            → userId (TTL: 1 hour)
USER_DETAILS_CACHE:{userId}   → UserResponseDto JSON (TTL: 6 hours)
USER_LIST_CACHE:*             → paginated user list (TTL: 1 hour)
```

---

## RabbitMQ Queues

```
bank.account.save.queue    → new bank account (gRPC fallback)
bank.account.update.queue  → bank account update (gRPC fallback)
```

---

## Log Files

```
logs/
├── api-gateway.log       → routing, JWT, threat detection
├── user-service.log      → auth, user CRUD, Redis, gRPC client
├── bank-service.log      → bank accounts, gRPC server, RabbitMQ
└── discovery-server.log  → Eureka registrations, heartbeats

Rotation: 10MB per file | 30 days history
```

---

## Project Structure

```
FundTransfer/
├── fund-transfer-docker/
│   ├── docker-compose.yml
│   ├── prometheus.yml
│   ├── loki-config.yml
│   └── promtail-config.yml
│
├── FundTransferDiscoveryServer/
├── FundTransferUserService/
├── FundTransferBankService/
├── FundTransferApiGateway/
│
├── logs/                    ← gitignored
└── README.md
```

---

## Troubleshooting

### Prometheus targets DOWN
```bash
# Verify ports are listening
netstat -ano | findstr "9090"
netstat -ano | findstr "9091"
netstat -ano | findstr "8080"
netstat -ano | findstr "8761"

# Test actuator directly
curl http://localhost:9090/internal/actuator/health
curl http://localhost:9091/internal/actuator/health

# Restart Prometheus
docker compose restart prometheus
```

### Grafana shows N/A
```
→ Select Application and Instance in dashboard dropdowns
→ Verify data source URL: http://prometheus:9090
→ Test in Explore: jvm_memory_used_bytes
```

### Loki shows no logs
```bash
docker compose logs promtail    # check tailing files
curl http://localhost:3100/ready

# Test in Grafana Explore → Loki:
{env="dev"} |= "ERROR"
```

### Services not registering in Eureka
```
→ Start discovery-service FIRST
→ Wait 15-30 seconds before starting others
→ Check: http://localhost:8761
```

### JWT validation fails
```
→ Verify jwt.secret is identical across all services
→ Check token expiry (24 hours)
→ Format: Authorization: Bearer {token}
```

### gRPC connection refused
```
→ Ensure bank-service is running on port 9191
→ netstat -ano | findstr "9191"
→ On failure, events auto-fallback to RabbitMQ
```

### Update user returns empty body
```
→ Include "active": true in request body
→ Without it, active=false is sent and user becomes inactive
```

---

## Environment

```
Java       : 21 (LTS)
Spring Boot: 3.x
Profile    : dev (default) | prod
PostgreSQL : 15
Redis      : latest
RabbitMQ   : 3-management
```