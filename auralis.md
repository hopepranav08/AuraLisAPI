# AuralisAPI: Architecting an Autonomous Zero-Trust Perimeter through eBPF-Driven Zombie API Discovery and Agentic Remediation

The contemporary landscape of software engineering is defined by a paradoxical relationship between deployment velocity and infrastructural visibility. As organizations aggressively pursue digital transformation through the transition from monolithic architectures to highly distributed microservices, the proliferation of Application Programming Interfaces (APIs) has scaled beyond the capacity of traditional governance frameworks.<sup>1</sup> This architectural shift, while prioritizing agility and decoupled service delivery, has inadvertently fragmented asset ownership and created a silent crisis of visibility.<sup>1</sup> Within this ecosystem, the accumulation of unmanaged, undocumented, and unsecured endpoints has given rise to the "Zombie API" phenomenon-a failure of lifecycle management where deprecated or abandoned endpoints remain functional and tethered to production data stores, yet operate entirely outside the active security monitoring purview.<sup>1</sup>

AuralisAPI is proposed as a comprehensive, autonomous governance platform designed to neutralize this threat. By integrating Extended Berkeley Packet Filter (eBPF) technology for zero-overhead, kernel-level observability with agentic reasoning via Large Language Models (LLMs) and the LangGraph framework, AuralisAPI bridges the "semantic gap" between high-level developer intent and low-level system behavior.<sup>1</sup> This report provides an exhaustive technical analysis of the AuralisAPI architecture, exploring the exploitation loopholes inherent in stale endpoints, the mathematical models required for drift detection, and the programming path necessary to build a hackathon-winning, production-ready solution that delivers systemic structural resilience.

## The Epistemology of API Sprawl and the Zombie Pandemic

The hidden attack surface of modern enterprise environments is typically categorized into three distinct threats: Shadow APIs, Rogue APIs, and Zombie APIs.<sup>1</sup> A Shadow API refers to an active endpoint operating without the knowledge of central IT governance, often born from developer shortcuts or temporary testing environments.<sup>1</sup> Rogue APIs represent malicious endpoints deployed by compromised insiders or external actors to facilitate continuous data exfiltration.<sup>1</sup> In contrast, a Zombie API is a legacy endpoint that was once officially sanctioned and documented but was never decommissioned during the retirement phase of the software lifecycle.<sup>1</sup>

Because Zombie APIs were once legitimate components of the infrastructure, they often retain original access privileges, active connections to production databases, and functional routing configurations.<sup>1</sup> As frontend services are updated to utilize newer API versions, these legacy paths fall out of the patching and security update cycle, creating dormant but highly functional backdoors.<sup>1</sup> The distinction is critical: Shadow APIs represent a failure of governance at the start of the lifecycle, while Zombie APIs represent a failure at the end.<sup>1</sup>

### The Security Deficit of Deprecated Endpoints

Zombie APIs are functionally "frozen in time," remaining associated with the security protocols prevalent at their birth.<sup>1</sup> While an organization may modernize its active infrastructure with OAuth2, JSON Web Tokens (JWTs), and advanced rate limiting, the deprecated endpoints continue to accept requests using outdated security schemas.<sup>1</sup> Attackers specifically target these legacy versions (e.g., /api/v1/ instead of /api/v3/), anticipating a lack of modern encryption, robust authentication, and comprehensive logging.<sup>1</sup>

The Open Worldwide Application Security Project (OWASP) recognizes this systemic failure under API9:2023 - Improper Inventory Management.<sup>1</sup> This classification underscores that the risk is less a direct technical flaw and more a process failure that creates critical technical blind spots.<sup>1</sup>

| **OWASP 2023 Classification** | **Exploitation Loophole via Zombie APIs** | **Defensive Implications** |
| --- | --- | --- |
| API1:2023 & API3:2023 - BOLA/BOPLA | Older endpoints frequently fail to validate whether an authenticated user has explicit authorization to access a specific data object or property.<sup>1</sup> | Attackers manipulate object identifiers in Zombie API request payloads to access other users' data, exploiting patches missing in the deprecated path.<sup>1</sup> |
| --- | --- | --- |
| API4:2023 - Unrestricted Resource Consumption | Deprecated paths often lack the strict rate limiting and concurrency caps established on modern API gateways.<sup>1</sup> | Facilitates application-layer Denial of Service (DoS) attacks, exhausting database connection pools by flooding unmonitored legacy endpoints.<sup>1</sup> |
| --- | --- | --- |
| API5:2023 - Broken Function Level Authorization (BFLA) | Legacy administrative endpoints remain exposed without rigorous role-based access control (RBAC) checks.<sup>1</sup> | Attackers elevate privileges by directly calling hidden administrative functions that were supposed to be decommissioned.<sup>1</sup> |
| --- | --- | --- |
| API6:2023 - Unrestricted Access to Sensitive Business Flows | Zombie APIs expose sensitive logic without appropriate restrictions or holistic oversight.<sup>1</sup> | Attackers leverage these forgotten endpoints to bypass bot-protection mechanisms, executing credential stuffing or mass data scraping.<sup>1</sup> |
| --- | --- | --- |
| API9:2023 - Improper Inventory Management | The foundational flaw allowing shadow and zombie endpoints to exist outside the official registry.<sup>1</sup> | Requires continuous API discovery, rigorous documentation, and lifecycle management tied to backing services.<sup>1</sup> |
| --- | --- | --- |

### Real-World Exploitation and Causal Analysis

The catastrophic potential of Zombie APIs is demonstrated by the September 2022 Optus breach, which resulted in the exposure of nearly 10 million customer records.<sup>1</sup> The attack vector was an undocumented, unauthenticated API endpoint that the organization failed to decommission.<sup>1</sup> Because the security team was unaware of its existence, the endpoint lacked rate limits and active monitoring, functioning as an open, unmonitored door into the core database.<sup>1</sup>

In another sophisticated pattern, threat actors targeting e-commerce platforms like WooCommerce and WordPress utilized a deprecated Stripe API endpoint to optimize malicious operations.<sup>1</sup> Instead of attempting to exfiltrate all raw credit card data immediately-which often yields invalid numbers that trigger fraud alerts-the attackers routed the data through the Zombie API to validate the cards in real-time.<sup>1</sup> Only the validated, active cards were exfiltrated, demonstrating how attackers leverage forgotten infrastructural capabilities to enhance their own malicious efficiencies.<sup>1</sup>

Academic research indicates that technical debt is the primary driver of this trend.<sup>1</sup> Studies show that only 22% of outdated API usages are eventually upgraded, as developers prioritize new features over the time-consuming process of applying replacement APIs.<sup>1</sup> Consequently, maintainers are forced to keep deprecated endpoints alive to prevent breaking legacy client applications, resulting in permanent Zombie APIs.<sup>1</sup>

## Technological Foundations: The eBPF Observability Revolution

To achieve the visibility required for AuralisAPI, traditional discovery mechanisms like inline proxies or log ingestion are insufficient due to their latency overhead and operational complexity.<sup>1</sup> The platform mandates out-of-band, agentless network telemetry powered by Extended Berkeley Packet Filter (eBPF) technology.<sup>1</sup>

### Kernel-Level Telemetry and Zero-Overhead Observability

eBPF enables the execution of sandboxed programs within the Linux kernel without modifying the kernel source code or loading unstable modules.<sup>1</sup> By hooking into the network stack at the kernel level using kprobes, uprobes, and tracepoints, AuralisAPI achieves several advantages:

- **Zero-Overhead:** Native kernel execution captures live traffic across development and production environments without the latency of user-space proxies.<sup>1</sup>
- **Universal Visibility:** eBPF monitors all inter-service (East-West) and external (North-South) traffic, successfully identifying internal Zombie APIs hidden behind firewalls.<sup>1</sup>
- **Payload Extraction:** Sensors extract critical metadata, including endpoint URLs, HTTP methods, headers, and authentication status, effectively reverse-engineering the operational schema of the network.<sup>1</sup>

Platforms such as Levo.ai or Hubble utilize eBPF to compare live traffic observed at the kernel level against static code repositories.<sup>1</sup> A Zombie API is definitively identified when an endpoint present in the source code or historical documentation is observed to be unused in actual traffic, or conversely, when a flagged deprecated endpoint registers anomalous activity.<sup>1</sup>

### TLS Inspection via Uprobes and Memory Decoding

A critical challenge in API discovery is inspecting TLS-encrypted traffic without breaking the encryption chain or modifying the application.<sup>17</sup> AuralisAPI utilizes eBPF uprobes to hook into SSL/TLS libraries like OpenSSL, GnuTLS, or BoringSSL.<sup>17</sup> By attaching probes to functions like SSL_write and SSL_read, the platform captures plaintext data directly before encryption or after decryption.<sup>17</sup>

For applications written in Go, which use an internal static implementation of TLS (crypto/tls), the platform must calculate specific memory offsets to instrument the Read and Write functions of the \*tls.Conn object.<sup>21</sup> Since Go 1.17+, the compiler utilizes a register-based calling convention (using RAX, RBX, RCX, etc.), necessitating a systematic approach to extract function arguments.<sup>22</sup> AuralisAPI's discovery engine identifies the virtual address of the target function using symbol table analysis and attaches uprobes to the calculated offset, enabling deep observability of statically linked binaries without application restarts.<sup>21</sup>

## Mathematical Models for API Drift and Behavioral Anomaly Detection

Runtime protection requires the identification of "API Drift"-unauthorized or unexpected changes in functionality where endpoints morph beyond their original design parameters.<sup>1</sup> This discrepancy is detected through automated systems leveraging concept drift detection and statistical distribution tests.<sup>1</sup>

### Drift Detection Methodologies

Treating API request structures, payload sizes, and parameter frequencies as continuous data streams, AuralisAPI implements the following mathematical models:

- **Page-Hinkley Test:** Effective for identifying sudden spikes in traffic to an endpoint that previously exhibited zero activity-a classic signature of Zombie API discovery by an attacker.<sup>1</sup> The test accumulates differences between observed values and the estimated mean, triggering an alert when evidence exceeds a threshold ![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA0AAAAfCAYAAAA89UfsAAABXUlEQVR4AeyTPUtCURzGrxFR0RBBLS0NtQR9gIKiqIgigiBqDRprivoA0dQQ0SdobqmGloZoD0EXFQfB1TfUTXTQ33PwXrxvgg4uKs/vPMdz/4/33P+5jll9fIYhtEtf6pCFC4iAT95G/FKxChPwDEvgkzekggzDDyzCBvgUFGpS9Q7yU3wcXAoKqSDGkIYdWAGXwkJ5qvR8c/gWuBQW0ta+qJSf4JPgKCykgjhDCtSMZdxRt1CJKgVn8W1wFBbSod5SdQTa4jE+BUZBITtwRcU+aIubuA4dsyxvKMLqNdzBJURBDZnG98CoM2QHnrhyA/8gfTPofTzEZ8C5kx14YfEBPsBWkokOex1fAxNS4Jwvr/AGCurhmRpVGT9BL/EBbkLzTB7hD+6hAV5pi0UWz2BBz1RgolurrfpVvvqUYEXvoP5vZYW0FR1kjQvdVOFiDhoK4b1pFGr3a3CNaAEAAP//MAUK9wAAAAZJREFUAwBiTzg//XIP3QAAAABJRU5ErkJggg==).<sup>1</sup>
- **ADWIN (Adaptive Windowing):** Automatically adjusts the data window size to detect both sudden and gradual drift, ensuring bursts of malicious traffic on forgotten endpoints are isolated.<sup>1</sup>
- **Population Stability Index (PSI):** Measures the shift in the distribution of API request variables over time.<sup>1</sup> High PSI scores indicate structural drift in payloads, suggesting an endpoint is being utilized in a novel, potentially hostile manner.<sup>1</sup>
- **Kolmogorov-Smirnov (KS) Test:** A nonparametric test that compares cumulative distributions of HTTP response codes or latencies against known baselines to isolate unmanaged legacy endpoints.<sup>1</sup>

### Heuristics for Sensitive Data and PII Detection

Identifying a Zombie API is the first step; assessing severity requires understanding the data it processes.<sup>1</sup> AuralisAPI deploys deep payload inspection heuristics using regular expression matching and entropy analysis to detect Personally Identifiable Information (PII), Payment Card Industry (PCI) data, and Protected Health Information (PHI).<sup>1</sup> If an endpoint is identified as a Zombie API and simultaneously flags high on PII exposure, it is categorized as a tier-one security incident requiring immediate quarantine.<sup>1</sup>

## Agentic Reasoning: The Brain of AuralisAPI via LangGraph

The uniqueness of AuralisAPI lies in its autonomous remediation core, powered by the LangGraph framework.<sup>1</sup> While traditional systems only alert, AuralisAPI uses agentic workflows to diagnose, plan, and execute decommissioning strategies.<sup>32</sup>

### Bridging the Semantic Gap with AgentSight

Modern software increasingly relies on LLM agents for maintenance (e.g., Claude Code, Gemini-CLI), creating a "semantic gap" between the agent's intent (prompts) and its actions (syscalls).<sup>2</sup> An application-level monitor might see a legitimate "execute script" call, while the system monitor sees a shell writing to /etc/passwd. AuralisAPI implements "boundary tracing" to bridge this gap.<sup>2</sup> It intercepts TLS-encrypted LLM traffic to extract semantic intent, monitors kernel events for system effects, and causally correlates these streams across process boundaries using secondary LLM analysis.<sup>2</sup> This detects prompt injection attacks or expensive reasoning loops where an agent burns tokens by repeating failing commands.<sup>3</sup>

### Stateful Workflows for Incident Response

LangGraph allows AuralisAPI to define its execution flow as a directed graph with typed state and conditional edges.<sup>31</sup> This enables the platform to:

- **Resume after Crashes:** Persistence mechanisms allow the agent to pick up where it left off.<sup>37</sup>
- **Human-in-the-Loop:** Explicit interrupt points are added for high-impact actions like decommissioning a core banking endpoint.<sup>31</sup>
- **Parallel Tool Use:** The agent can simultaneously query Shodan for exposed services, scan code for vulnerabilities, and analyze network traffic patterns.<sup>37</sup>

The multi-agent pattern utilized by AuralisAPI includes specialized agents for reconnaissance, vulnerability checking, and reporting, all coordinated by a supervisor that routes tasks based on the evolving state of the investigation.<sup>37</sup>

## Defensive Deception: API Honeypots and Synchronized Decoys

AuralisAPI adopts a proactive defense posture by deploying API Honeypots designed to mimic the behavior of Zombie or Shadow APIs.<sup>1</sup> These decoys attract attackers during the reconnaissance phase, allowing the platform to neutralize threats before they reach production data.<sup>1</sup>

### Implementation and Orchestration

AuralisAPI utilizes the "Deception-as-Code" paradigm, where deception policies describe traps as structured documents.<sup>40</sup>

- **Koney Operator:** A Kubernetes operator that facilitates the automated setup, rotation, and removal of traps without modifying application source code.<sup>40</sup>
- **Look-alike Decoys:** The framework analyzes the organization's Infrastructure-as-Code (IaC) files to build new container images that replicate structural elements while replacing logic with a honeypot.<sup>42</sup> This ensures the deception environment evolves alongside the production system, maintaining realism.<sup>41</sup>
- **Tar-pitting and Intelligence:** Decoys like HellPot return infinite data streams to exhaust attacker resources, while others log IP addresses and payload structures to feed the Threat Intelligence Engine.<sup>1</sup>

| **Honeypot Project** | **Interaction Level** | **Technical Focus** |
| --- | --- | --- |
| OpenCanary | High | Multi-protocol network daemon; low resource requirements; supports various alert mechanisms.<sup>1</sup> |
| --- | --- | --- |
| Riotpot | Medium | Focused on API and web-decoy services; designed to log unauthorized access attempts.<sup>1</sup> |
| --- | --- | --- |
| Express Honeypot | Low | trap LFI and RFI scanners using a NodeJS/Express application.<sup>1</sup> |
| --- | --- | --- |
| HellPot | High | Designed to crash malicious bots by tar-pitting them with infinite data streams.<sup>1</sup> |
| --- | --- | --- |

## Modern Defensive Architectures and Gateway Enforcement

The Enforcement Plane of AuralisAPI relies on declarative API Gateway architectures to programmatically quarantine threats.<sup>1</sup>

### API Gateway Aggregation and BFF Layers

By utilizing the Gateway Aggregation pattern and creating Backend-for-Frontend (BFF) layers, AuralisAPI decouples client-facing APIs from underlying microservices.<sup>1</sup> When a Zombie API is detected, the gateway configuration is seamlessly updated to sever the route to the deprecated backend, ensuring the endpoint is physically unreachable from external networks.<sup>1</sup>

| **Gateway Feature** | **KrakenD** | **Kong (Community)** | **Tyk** |
| --- | --- | --- | --- |
| Architecture | Stateless design in Go; reads configuration from a single file.<sup>1</sup> | NGINX-based; requires centralized database for persistence.<sup>1</sup> | Go-based; features a graphical dashboard and hybrid deployment.<sup>1</sup> |
| --- | --- | --- | --- |
| API Aggregation | Parallel aggregation of multiple microservices directly in the core.<sup>1</sup> | Not natively supported in Community Edition.<sup>1</sup> | Supported via JS middleware or scripting engine.<sup>1</sup> |
| --- | --- | --- | --- |
| Configuration | GitOps oriented; immutable configuration.<sup>1</sup> | Admin API driven; mutable state.<sup>1</sup> | Dashboard and API driven management.<sup>1</sup> |
| --- | --- | --- | --- |

### Formal Sunsetting Standards and the 410 Gone Protocol

When an API must be retired, AuralisAPI leverages standard HTTP response headers defined in IETF RFC 8594.<sup>1</sup>

- **Deprecation Header:** Signals that an API is no longer recommended but remains functional.<sup>1</sup>
- **Sunset Header:** Specifies the exact date when the endpoint will become unresponsive.<sup>1</sup>
- **410 Gone Protocol:** Once the sunset date passes, AuralisAPI configures the gateway to return an HTTP 410 Gone status code.<sup>1</sup> This explicitly communicates that the resource was intentionally removed, instructing client applications to cease future requests permanently.<sup>1</sup>

## AuralisAPI: The Hackathon Implementation Blueprint

Building a standout project requires a modular, end-to-end system that bridges discovery, analysis, and enforcement.

### Phase 1: Data Ingestion and Sidecar Telemetry (The Sensor)

The system utilizes Out-of-Band Network Traffic Mirroring to achieve deep visibility without latency.<sup>1</sup>

- **Deployment:** A lightweight eBPF sensor (or Envoy-based sidecar) is deployed within the target cluster.<sup>1</sup>
- **Metadata Extraction:** A custom Python addon (utilizing mitmdump logic) extracts HTTP methods, URL paths, response codes, and payload schemas.<sup>1</sup>
- **Queueing:** Metadata is pushed to a central Redis queue, simulating enterprise event ingestion.<sup>1</sup>

### Phase 2: The Heuristic Differential Engine (The Analyzer)

This module acts as the logic core, identifying drift and calculating risk.<sup>1</sup>

- **Spec Generation:** Live traffic is converted into an OpenAPI 3.0 specification using mitmproxy2swagger.<sup>1</sup>
- **Contract Diffing:** The system pulls the official spec from the organization's GitHub and performs a continuous diff using AI-powered validators or tools like Frouros.<sup>1</sup>
- **Zombie Classification:**
  - **Shadow API:** Endpoint exists in traffic but is absent from the Git specification.<sup>1</sup>
  - **Active Zombie API:** Endpoint exists in traffic and spec but is marked with deprecated: true.<sup>1</sup>
  - **Dormant Zombie API:** Endpoint in spec but has zero traffic over a defined threshold (measured via Page-Hinkley tests).<sup>1</sup>
- **Risk Scoring:** Payload analysis for PII upgrades the API severity to "Critical".<sup>1</sup>

### Phase 3: Autonomous Quarantine and GitOps Enforcement (The Enforcer)

The system moves from observation to autonomous enforcement.<sup>1</sup>

- **GitOps Integration:** The system programmatically generates a pull request to the API Gateway configuration repository (e.g., KrakenD's krakend.json).<sup>1</sup>
- **Quarantine Routing:** The updated configuration explicitly terminates connections to identified Zombie APIs with a 410 Gone response.<sup>1</sup>
- **Deception Spin-up:** Optionally, the system triggers a webhook to spin up a Dockerized OpenCanary instance listening on the quarantined path.<sup>1</sup>

## Feasibility, Commercial Viability, and Hackathon Strategy

AuralisAPI addresses a critical market need, where 57% of organizations have experienced an API-related breach in the last two years.<sup>1</sup> By automating the discovery and removal of forgotten endpoints, the platform reduces the average \$4 million cost of API-related breaches.<sup>1</sup>

### Technical Stack Summary

- **Backend:** Python (FastAPI) for agentic reasoning and AI integration.<sup>1</sup>
- **Discovery:** Go for kernel-level eBPF tracing using cilium/ebpf.<sup>1</sup>
- **Frontend:** Next.js/React for the API Intelligence Dashboard, featuring D3.js dependency graphs.<sup>1</sup>
- **Drift Detection:** Frouros and scikit-multiflow for real-time mathematical monitoring.<sup>1</sup>
- **Orchestration:** LangGraph for defining stateful, self-healing incident response workflows.<sup>31</sup>

### The Winning Edge: "Agentic Readiness"

To win in the 2026 hackathon market, the pitch must emphasize "Agentic Readiness"-the ability for autonomous agents to manage operational chains with "Scoped Consent".<sup>64</sup> AuralisAPI proves this by:

- **Replacing Operational Chains:** Automating the entire lifecycle from discovery to PR-based remediation, radically reducing costs.<sup>64</sup>
- **Technological Honesty:** Proving impact through kernel-deep telemetry rather than flashy UI-only "wrappers".<sup>64</sup>
- **Systemic Resilience:** Moving from reactive firefighting to a learning organism that evolves its deception environment alongside its production code.<sup>42</sup>

## Conclusion

The proliferation of Zombie APIs represents a fundamental convergence of technical debt and architectural complexity within modern software engineering. As organizations accelerate digital iteration, the legacy code left in the wake of progress transforms from a functional asset into a severe, unmonitored liability. Defending against this invisible threat requires an abandonment of the assumption that API security ends at deployment.

AuralisAPI establishes a definitive architecture for continuous, full-lifecycle governance. By combining zero-overhead, kernel-level eBPF telemetry with rigorous mathematical drift detection and agentic reasoning via LangGraph, the platform achieves absolute visibility and autonomous remediation. The integration of proactive deception via honeypots and standard-compliant sunsetting via 410 Gone status codes ensures that legacy endpoints are not merely abandoned, but securely decommissioned. For enterprise banking and high-volume microservices infrastructures, AuralisAPI offers a blueprint for systemic structural resilience, ensuring that the digital perimeter remains intelligent, self-healing, and perpetually secure.

#### Works cited

- Zombie API Discovery and Defense.docx
- AgentSight: System-Level Observability for AI Agents Using eBPF - arXiv.org, accessed on March 7, 2026, <https://arxiv.org/html/2508.02736v1>
- AgentSight: System-Level Observability for AI Agents Using eBPF - ResearchGate, accessed on March 7, 2026, <https://www.researchgate.net/publication/394322099_AgentSight_System-Level_Observability_for_AI_Agents_Using_eBPF>
- API Gateway Security: Best Practices | Mulesoft, accessed on March 7, 2026, <https://www.mulesoft.com/api/security/api-gateway-security>
 - Frouros, accessed on March 7, 2026, <https://frouros.readthedocs.io/>
- How to Deploy KrakenD API Gateway for High-Performance API Aggregation - OneUptime, accessed on March 7, 2026, <https://oneuptime.com/blog/post/2026-02-09-krakend-api-gateway-aggregation/view>
- API Gateway Comparison: Apache APISIX vs. Kong vs. Traefik vs. KrakenD vs. Tyk - API7.ai, accessed on March 7, 2026, <https://api7.ai/learning-center/api-gateway-guide/api-gateway-comparison-apisix-kong-traefik-krakend-tyk>
- Building Scalable, Agile, and Secure APIs with Kubernetes and Microservices | CNCF, accessed on March 7, 2026, <https://www.cncf.io/blog/2025/03/18/building-scalable-agile-and-secure-apis-with-kubernetes-and-microservices/>
- eBPF for the Infrastructure Platform - Linux Foundation, accessed on March 7, 2026, <https://www.linuxfoundation.org/hubfs/eBPF/The_State_of_eBPF25_111925.pdf>
- eBPF: Kernel-LevelObservability.Superpowers for Linux - Java Code Geeks, accessed on March 7, 2026, <https://www.javacodegeeks.com/2026/03/ebpf-kernel-levelobservability-superpowers-for-linux.html>
- Best of 2025: eBPF: The Silent Power Behind Cloud Native's Next Phase, accessed on March 7, 2026, <https://cloudnativenow.com/editorial-calendar/best-of-2025/ebpf-the-silent-power-behind-cloud-natives-next-phase-2/>
- eBPF - Introduction, Tutorials & Community Resources, accessed on March 7, 2026, <https://ebpf.io/>
- How to Write eBPF Programs in Go with cilium/ebpf - OneUptime, accessed on March 7, 2026, <https://oneuptime.com/blog/post/2026-01-07-ebpf-go-cilium-ebpf/view>
- ControlPlane - eBPF Security Threat Model - Linux Foundation, accessed on March 7, 2026, <https://www.linuxfoundation.org/hubfs/eBPF/ControlPlane%20%E2%80%94%20eBPF%20Security%20Threat%20Model.pdf>
- OpenTelemetry eBPF Instrumentation Marks the First Release, accessed on March 7, 2026, <https://opentelemetry.io/blog/2025/obi-announcing-first-release/>
- Securing East-West Traffic in Kubernetes With Service Mesh API Controls - Software Plaza, accessed on March 7, 2026, <https://www.softwareplaza.com/it-magazine/securing-east%E2%80%93west-traffic-in-kubernetes-with-service-mesh-api-controls>
- Debugging with eBPF Part 3: Tracing SSL/TLS connections | Pixie Labs Blog, accessed on March 7, 2026, <https://blog.px.dev/ebpf-openssl-tracing/>
- eBPF Ecosystem Progress in 2024-2025: A Technical Deep Dive - eunomia, accessed on March 7, 2026, <https://eunomia.dev/blog/2025/02/12/ebpf-ecosystem-progress-in-20242025-a-technical-deep-dive/>
- OpenAPI/Swagger Generation - Enterprise Edition | KrakenD API ..., accessed on March 7, 2026, <https://www.krakend.io/docs/enterprise/v1.3/endpoints/openapi/>
- How to Inspect SSL/TLS Traffic with eBPF - OneUptime, accessed on March 7, 2026, <https://oneuptime.com/blog/post/2026-01-07-ebpf-ssl-tls-inspection/view>
- Under the Hood with Go TLS and eBPF - Speedscale, accessed on March 7, 2026, <https://speedscale.com/blog/ebpf-go-design-notes-1/>
- 04 - eBPF Uprobes: Tracing gRPC Headers by Unpacking Go Function Internals, accessed on March 7, 2026, <https://dev.to/maheshrayas/04-ebpf-uprobes-decoding-go-function-arguments-registers-memory-layout-to-parse-grpc-headers-6n8>
- eBPF-based TLS interception without certificate management or proxies - technical deep dive : r/devops - Reddit, accessed on March 7, 2026, <https://www.reddit.com/r/devops/comments/1lfgi03/ebpfbased_tls_interception_without_certificate/>
- Frouros: an open-source Python library for drift detection in machine learning systems. - GitHub, accessed on March 7, 2026, <https://github.com/IFCA-Advanced-Computing/frouros>
- Page-Hinkley Method - GeeksforGeeks, accessed on March 7, 2026, <https://www.geeksforgeeks.org/artificial-intelligence/page-hinkley-method/>
- PageHinkley - River, accessed on March 7, 2026, <https://riverml.xyz/0.16.0/api/drift/PageHinkley/>
- How to Detect Model Drift and Set Up Real-Time Alerts for AI Systems - Dev.to, accessed on March 7, 2026, <https://dev.to/kuldeep_paul/how-to-detect-model-drift-and-set-up-real-time-alerts-for-ai-systems-332l>
- Concept drift - - Frouros - Read the Docs, accessed on March 7, 2026, <https://frouros.readthedocs.io/en/v0.5.1/>
- 10 Best Cyber Security Hackathon Project Ideas - 2026 - Placement Preparation, accessed on March 7, 2026, <https://www.placementpreparation.io/blog/hackathon-project-ideas-for-cyber-security/>
- 30+ Top Hackathon Project Ideas: Build, Innovate, & Win - upGrad, accessed on March 7, 2026, <https://www.upgrad.com/blog/hackathon-project-ideas/>
- LangGraph: Agent Orchestration Framework for Reliable AI Agents - LangChain, accessed on March 7, 2026, <https://www.langchain.com/langgraph>
- (PDF) From Streaming to Self-Healing: LLM-Based Autonomous Remediation in Kafka Snowflake Pipelines for Healthcare Big Data - ResearchGate, accessed on March 7, 2026, <https://www.researchgate.net/publication/399858133_From_Streaming_to_Self-Healing_LLM-Based_Autonomous_Remediation_in_Kafka_Snowflake_Pipelines_for_Healthcare_Big_Data>
- An Intelligent Fault Self-Healing Mechanism for Cloud AI Systems via Integration of Large Language Models and Deep Reinforcement Learning - arXiv, accessed on March 7, 2026, <https://arxiv.org/html/2506.07411v1>
- Self-Healing APIs: The AI Doctors Saving Your Digital Ecosystem - FAUN.dev(), accessed on March 7, 2026, <https://faun.pub/self-healing-apis-the-ai-doctors-saving-your-digital-ecosystem-467d76969c28>
- AgentSight: Keeping Your AI Agents Under Control with eBPF-Powered System Observability - eunomia, accessed on March 7, 2026, <https://eunomia.dev/en/blog/posts/agentsight_paper/>
- Agentic Design Patterns: The 2026 Guide to Building Autonomous Systems - SitePoint, accessed on March 7, 2026, <https://www.sitepoint.com/the-definitive-guide-to-agentic-design-patterns-in-2026/>
- Building Your First Cybersecurity AI Agent with LangGraph | by Arun Nair - Medium, accessed on March 7, 2026, <https://medium.com/seercurity-spotlight/building-your-first-cybersecurity-ai-agent-with-langgraph-d27107ac872a>
- What Is an API Honeypot? - - Prophaze, accessed on March 7, 2026, <https://www.prophaze.com/learn/what-is-an-api-honeypot/>
- HoneyKube: Designing and Deploying a Microservices-based Web Honeypot - Thijs van Ede, accessed on March 7, 2026, <https://thijsvane.de/static/homepage/papers/honeykube.pdf>
- HoneyKube: Designing and Deploying a Microservices-based Web Honeypot | Request PDF - ResearchGate, accessed on March 7, 2026, <https://www.researchgate.net/publication/372673704_HoneyKube_Designing_and_Deploying_a_Microservices-based_Web_Honeypot>
- Koney: A Cyber Deception Orchestration Framework for Kubernetes - arXiv, accessed on March 7, 2026, <https://arxiv.org/html/2504.02431v2>
- A Self-Synchronizing Cyber Deception Framework via Infrastructure as Code Reflection, accessed on March 7, 2026, <https://www.computer.org/csdl/proceedings-article/prdc/2025/451300a146/2bU9OLp22GI>
- The eBPF Foundation's 2025 Year in Review, accessed on March 7, 2026, <https://ebpf.foundation/the-ebpf-foundations-2025-year-in-review/>
- Stellar Startup Security Technology Vendors To Know In 2025 - CRN, accessed on March 7, 2026, <https://www.crn.com/news/security/2025/stellar-startup-security-technology-vendors-to-know-in-2025>
- KubeArmor In 2025: Securing IoT And Edge Workloads With EBPF - AccuKnox, accessed on March 7, 2026, <https://accuknox.com/blog/protecting-edge-workloads-with-kubearmor>
- AI-powered self-healing enterprise applications: A new era of autonomous systems - | World Journal of Advanced Research and Reviews, accessed on March 7, 2026, <https://journalwjarr.com/sites/default/files/fulltext_pdf/WJARR-2025-1682.pdf>
- KrakenD: High-performance Open Source API Gateway, accessed on March 7, 2026, <https://www.krakend.io/>
- API Gateway Performance Benchmark | by Zahid Çakıcı | Code&Beyond | Medium, accessed on March 7, 2026, <https://medium.com/code-beyond/api-gateway-performance-benchmark-407500194c76>
- Evaluating API Aggregation with Kong Gateway, KrakenD & Tyk Gateway | by Behind the Code: A Software Engineer's Struggle | Medium, accessed on March 7, 2026, <https://medium.com/@sarthakkar1999/evaluating-api-aggregation-with-kong-gateway-krakend-tyk-gateway-6788589ce620>
- Building Autonomous AI Agents with LangGraph | Coursera, accessed on March 7, 2026, <https://www.coursera.org/learn/packt-building-autonomous-ai-agents-with-langgraph-oyjym>
- Workflows and agents - Docs by LangChain, accessed on March 7, 2026, <https://docs.langchain.com/oss/python/langgraph/workflows-agents>
- Using eBPF with OpenTelemetry: Zero-Code Auto-Instrumentation - OneUptime, accessed on March 7, 2026, <https://oneuptime.com/blog/post/2025-12-10-ebpf-with-opentelemetry-auto-instrumentation/view>
- Gateway - OpenAPI Tooling, accessed on March 7, 2026, <https://tools.openapis.org/categories/gateway.html>
- Getting started with Tyk Operator - Tyk.io, accessed on March 7, 2026, <https://tyk.io/docs/4.0/tyk-stack/tyk-operator/getting-started-tyk-operator/>
- Automation Tools - Tyk.io, accessed on March 7, 2026, <https://tyk.io/docs/5.6/api-management/automations/>
- oapi-krakend is a command-line tool to convert an OpenAPI specification into KrakenD configurations. - GitHub, accessed on March 7, 2026, <https://github.com/gbaski/oapi-krakend>
- Analyzing Cloud Traffic for Web Honeypot using Microservice-based Architecture and XGBoost algorithm - IOE Graduate Conference, accessed on March 7, 2026, <https://conference.ioe.edu.np/publications/ioegc14/IOEGC-14-163-PS1-021-278.pdf>
- Tyk Operator, accessed on March 7, 2026, <https://tyk.io/docs/5.0/tyk-operator/>
- Tyk Operator - API Management in Kubernetes - Tyk Documentation, accessed on March 7, 2026, <https://tyk.io/docs/api-management/automations/operator>
- How to Make a Cybersecurity Pitch Deck \[That Connects with Investors\], accessed on March 7, 2026, <https://www.inknarrates.com/post/cybersecurity-pitch-deck>
- LangChain Python Tutorial: 2026's Complete Guide | The PyCharm Blog, accessed on March 7, 2026, <https://blog.jetbrains.com/pycharm/2026/02/langchain-tutorial-2026/>
- Building AI Agents with LangGraph (2026 Edition): A Step-by-Step Guide - AI Advances, accessed on March 7, 2026, <https://ai.gopubby.com/building-ai-agents-with-langgraph-2026-edition-a-step-by-step-guide-494d36e801f9>
- Concept Drift: 8 Detection Methods - Coralogix, accessed on March 7, 2026, <https://coralogix.com/ai-blog/concept-drift-8-detection-methods/>
- How to Create a Pitch Deck for Investors | 2026 Startup Strategy - Emerline, accessed on March 7, 2026, <https://emerline.com/blog/how-to-pitch-to-vc-as-tech-startup>
- The 2026 Pitch Deck Guide: Web3 & AI Fundraising - InnMind Blog, accessed on March 7, 2026, <https://blog.innmind.com/fundraising-pitch-deck-web3-ai-2026/>
- How LLMs are Building Self-Healing IT Infrastructure - Turabit, accessed on March 7, 2026, <https://turabit.com/how-llms-are-building-self-healing-it-infrastructure/>