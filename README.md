## 📖 Description

**BVDU-SecQuery** (an evolution of the *SecQL* architecture) is a lightweight, zero-cost endpoint security scanner and threat intelligence aggregator developed under the **BVDU Projects** series.

Designed for performance and portability, **BVDU-SecQuery** bridges local database indexing with real-time cloud threat feeds to inspect files, detect malicious payloads, and safely isolate infected binaries—all without relying on expensive infrastructure or paid security subscriptions.

---

### ⚡ How It Works (Multi-Layered Detection Pipeline)

Instead of relying on a single scanning method, **BVDU-SecQuery** passes files through a 4-tier threat evaluation pipeline:

1. **Local Signature Hash Matching**: Computes sub-millisecond **SHA-256** and **MD5** file hashes and queries an indexed, embedded **SQLite3** signature database.
2. **Cloud Threat Intelligence Fallback**: If a file is unknown locally, the engine queries free public REST APIs (**VirusTotal Community Tier** & **MalwareBazaar**) for real-time reputation scores.
3. **YARA Heuristic Pattern Inspection**: Scans raw binary structures, suspicious byte sequences, embedded strings, and malformed headers to catch modified or zero-day malware.
4. **Encrypted Quarantine Isolation**: Encrypts flagged malicious binaries using **XOR encoding** and safely isolates them into a restricted vault to prevent accidental execution on the host operating system.

---

### 🛡️ Core Highlights

* **Zero Infrastructure Cost**: Built entirely on free, open-source threat feeds and community API tiers.
* **Automated Daily Updates**: Features a built-in signature synchronization daemon to fetch fresh malware hash dumps automatically.
* **Safety First**: Implements reversible XOR vault encryption for quarantined threats.
* **Modern Terminal Interface**: Renders real-time scan progress bars, color-coded threat alerts, and detailed reports via a Python `rich` CLI.
  
