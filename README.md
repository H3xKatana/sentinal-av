# Sentinel-AV

**Modern, Self-Hosted, Privacy-First Antivirus & Lightweight EDR**

Sentinel-AV is a next-generation, self-hosted antivirus and lightweight EDR platform.
It is designed to be **fast**, **open-source**, **multi-agent**, and **privacy-preserving**. Offering modern malware detection with YARA, heuristics, behavioral monitoring, and real-time protection across Linux, Windows, and macOS systems.

Think **ClamAV, but modern**, distributed, real-time, and developer-friendly.

---

## Features

### Multi-Platform Agents

* Written in Go, compiled statically for **Linux**, **Windows**, and **macOS**
* Lightweight footprint with semi-autonomous behaviour

### Advanced Detection Stack

* **YARA** signature scanning
* **Hash-based** signature matching (MD5/SHA256)
* **Heuristics & Behaviour Monitoring**:

  * Suspicious process creation
  * Unexpected persistence mechanisms
  * Suspicious network activity
  * File activity correlation rules

### Real-Time Protection

* Filesystem monitoring:

  * Linux: `inotify`
  * Windows: `ReadDirectoryChangesW`
  * macOS: FSEvents
* Blocking / Quarantine on detection

### Process & Network Monitoring

* Track running processes and detect suspicious ancestry patterns
* Detect unusual outbound connections
* Rule-driven alerts: regex, IOC match, YARA, behaviour scoring

### Secure Distributed Architecture

* gRPC + TLS secured communication
* Agents operate independently and sync signatures periodically
* Server handles orchestration, signature distribution, and dashboard

### Modern Web Dashboard

Authenticated Web UI with:

* Live scan queue & manual scan triggers
* Agents list & health metrics
* Signature database manager (view / upload / versioning)
* Quarantine management (restore / delete)
* Scan history & detection events
* Real-time logs
* File/URL drop-zone + full-disk scan interface
* System status & statistics overview

### Flexible Packaging

* Docker Compose deployment
* systemd unit
* Windows service
* macOS launchd integration

---

## Threat Model & Scope

### Sentinel-AV Protects Against

* Known malware signatures (YARA + hash)
* Trojans and common malicious binaries
* File-based threats (PE/ELF/Mach-O)
* Suspicious runtime behaviour
* Suspicious network behaviour
* Persistence and process anomalies

### Not in Scope

Sentinel-AV is **not** designed to replace full enterprise EDR/XDR solutions.
Out of scope:

* Advanced 0-day kernel/network exploit mitigation
* Memory introspection of arbitrary processes
* Ransomware rollback or hypervisor-level protections

The goal is a **fast, lightweight AV/mini-EDR hybrid** for servers, homelabs, and small organizations.

---

## Architecture Overview

```
+-----------------------------+         gRPC/TLS        +----------------------+
|       Sentinel Server       | <---------------------> |     Agents Fleet     |
|  (Postgres, API, Web UI)    |                         |  (Linux, Win, macOS) |
| - Signature manager         |                         | - FS watcher         |
| - Web UI (auth)             |                         | - Scanner (YARA,etc) |
| - Sync / Task scheduler     |                         | - Quarantine         |
| - DB: agents, scans, events |                         | - Local policy       |
+-----------------------------+                         +----------------------+
         ^         ^
         |         |
         |         +----- Admin Web UI (authenticated)
         |
     External (optional)
     Signature repo (git/S3)
```

---

## Project Directory Structure

```
sentinel-av/
├── .env.example
├── docker-compose.yml
├── Makefile
├── go.mod
├── LICENSE
├── README.md
│
├── docs/
│   ├── architecture.md
│   ├── developer-guide.md
│   ├── agent-protocol.md
│   └── ops.md
│
├── server/
│   ├── cmd/server/main.go
│   ├── api/                # Web UI handlers (REST/GraphQL)
│   ├── grpc/               # gRPC services + proto definitions
│   ├── internal/
│   │   ├── auth/           # UI sessions, JWT, permissions
│   │   ├── db/             # models, migrations
│   │   ├── models/         # shared types
│   │   ├── signatures/     # YARA + hash rule management
│   │   ├── sync/           # agent sync engine
│   │   └── scheduler/      # background tasks, heartbeat checks
│   └── Dockerfile
│
├── agent/
│   ├── cmd/agent/main.go
│   ├── internal/
│   │   ├── watcher/        # FS watchers: inotify/FSEvents/WinAPI
│   │   ├── scanner/        # YARA engine + hashing
│   │   ├── monitor/        # process & network monitoring
│   │   ├── quarantine/     # isolation & secure storage
│   │   ├── communicator/   # gRPC/TLS client layer
│   │   ├── config/         # local config & policy
│   │   └── updater/        # rules updater (pull from server)
│   └── Dockerfile
│
├── web/                # Next.js or embedded UI build
│
├── signatures/
│   ├── yara/               # YARA rules
│   ├── hashes/             # hash lists & metadata
│   └── metadata.json
│
└── scripts/                # CI/build/release/test scripts
```

---

## Quickstart (Developer)

### 1. Clone the repository

```bash
git clone https://github.com/0xA1M/sentinal-av
cd sentinel-av
```

### 2. Configure environment variables

Create a `.env` file based on `.env.example` and set your environment variables:

```bash
cp .env.example .env
# Edit .env to add your VT_KEY (VirusTotal API key)
```

### 3. Start the complete system (Postgres, server, dashboard, and agent)

```bash
docker compose up --build
```

This will start all components as a unit:
- PostgreSQL database
- Sentinel server (API and gRPC)
- Web dashboard
- Agent (connected to the server)

### 4. Access the Web UI

```
http://localhost:8080
```

Initial admin credentials are printed on first startup.

Full developer documentation is located in `docs/`.

---

## Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Add tests (especially for scanning logic & YARA behaviour)
4. Open a Pull Request

If contributing detection logic:

* Include YARA rule tests
* Provide sample files or hashes (sanitized)
* Add behavioural test cases if applicable

---

## License

Sentinel-AV is open-source under the **MIT License**.
See the [LICENSE](LICENSE) file for full details.
