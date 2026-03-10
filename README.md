# 🛡️ AIDEFEND: An AI Defense Framework

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg?style=for-the-badge)](https://creativecommons.org/licenses/by/4.0/)
[![Live Demo](https://img.shields.io/badge/Live-Demo-brightgreen?style=for-the-badge)](https://aidefend.net)

> AIDEFEND (Artificial Intelligence Defense Framework) is an open, AI-focused knowledge base of defensive countermeasures designed to help security professionals protect AI/ML systems from emerging threats.

---

### 🚀 Framework Website

**[Go to the AIDEFEND framework site](https://aidefend.net)**

---

### 💡 Key Features

* **Four Strategic Views**: Organize and explore defenses from multiple perspectives to suit different roles and use cases:
    * **Tactics View**: Aligned with the seven high-level tactics of MITRE D3FEND.
    * **Pillars View**: Organized by technology stack components (Data, Model, Infrastructure, Application).
    * **Phases View**: Structured around the AI development and operational lifecycle.
    * **Frameworks View**: Browse defenses mapped to specific threat frameworks (OWASP LLM/ML/Agentic Top 10, MAESTRO, MITRE ATLAS, NIST AML, Cisco AI Security).
* **Comprehensive Technique Details**: Each defensive technique includes a detailed description, implementation strategies with code examples, and lists of relevant open-source and commercial tools.
* **Threat Mapping**: Techniques are explicitly mapped to known threats from established frameworks like **MITRE ATLAS**, **MAESTRO**, the **OWASP Top 10** for LLMs, ML, and Agentic Applications, **Cisco Integrated AI Security and Safety Framework**, and **NIST Adversarial Machine Learning 2025**.
* **WebMCP Support**: With a [WebMCP](https://webmachinelearning.github.io/webmcp/)-capable browser, AI agents can browse and query AIDEFEND's defense knowledge base directly — just ask questions in any language and get answers.
* **Interactive Interface**: A clean, responsive UI with powerful search functionality to quickly find relevant techniques and threats.
* **Four Themes**: Dark, Light, High Contrast, and The Matrix — a comfortable viewing experience for any environment.

---

### 🏛️ The Framework Views

AIDEFEND allows you to view the defensive landscape through four distinct lenses, helping you answer key strategic questions.

#### **1. Tactics View**
> **Question:** *What high-level approach and concept is being used for this defense?*

This view organizes techniques by their strategic security function, aligned with the seven defensive tactics: **Model, Harden, Detect, Isolate, Deceive, Evict, and Restore**. It is ideal for security strategists and architects designing a defense-in-depth plan.

#### **2. Pillars View**
> **Question:** *What part (component) of the AI system is being protected?*

This view organizes defenses by the technology stack component they secure: **Data, Model, Infrastructure, or Application**. This component-centric view helps technical roles like ML Engineers and Cloud Security Engineers find controls relevant to their work.

#### **3. Phases View**
> **Question:** *When (what stage) in the AI lifecycle should this defense be applied?*

This view organizes defenses by the development stage where they are most relevant, from initial **Design & Scoping** through **Building, Validation, Operation, Incident Response, and Restoration**. This process-driven view helps MLOps and DevSecOps teams embed security throughout the entire AI lifecycle.

#### **4. Frameworks View**
> **Question:** *What known threats from established frameworks does this defense address?*

This view lets you browse defenses mapped to specific threat frameworks — **OWASP Top 10 for LLM Applications (2025)**, **OWASP ML Top 10 (2023)**, **OWASP Agentic AI Top 10 (2026)**, **MAESTRO**, **MITRE ATLAS**, **NIST Adversarial Machine Learning (2025)**, and **Cisco AI Security**. Each framework page includes a brief description, a link to the official source, and an organized breakdown of its threat categories with corresponding AIDEFEND defensive techniques.

---

### ⚙️ How to Use This Tool

1.  **Select a View**: Use the "View by:" switcher at the top of the page to choose between Tactics, Pillars, Phases, or Frameworks.
2.  **Explore Techniques**: Click on any column header to learn more about that tactic, pillar, or phase. Click on any individual defensive technique to open a detailed modal view. In Frameworks view, use the dropdown to switch between threat frameworks.
3.  **Search Everything**: Use the search bar to filter all content by keywords, technique IDs, or threat mappings (e.g., "Prompt Injection", "AID-H-002", "MAESTRO", "LLM01").

4.  **AIDEFEND MCP/REST API Service**: Now available! A 100% Local, private RAG system for the AIDEFEND framework. [Try it now](https://github.com/edward-playground/aidefend-mcp).
5.  **Ask AI Agents (WebMCP)**: Use a WebMCP-capable browser to let AI agents query the framework for you:
    1. Open [aidefend.net](https://aidefend.net) in a WebMCP-capable browser (e.g., Chrome 146+ with WebMCP flag enabled, or Microsoft Edge with upcoming WebMCP support). **Keep the tab open** — the AI agent can only access AIDEFEND tools while the page is active.
    2. Ask your AI agent (e.g., Gemini, ChatGPT, Claude) a question in any language — e.g., "What defenses exist for prompt injection?" or "如何防禦模型投毒？"
    3. The AI agent searches the framework, retrieves matching techniques, and returns implementation guidance.
---

### 📚 Acknowledgments & Disclaimer

This work is a personal initiative led by Edward Lee. It is intended for informational and educational purposes only.

**Please note:** This work was inspired by, and references, numerous incredible open-source security frameworks. However, **AIDEFEND is not affiliated with, endorsed by, or otherwise connected to The MITRE Corporation, the Cloud Security Alliance (creator of the MAESTRO framework), Google, OWASP, Cisco, or NIST.**

The framework synthesizes concepts and knowledge from the following foundational resources:
* [MAESTRO Framework](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro/)
* [MITRE D3FEND™](https://d3fend.mitre.org/)
* [MITRE ATLAS™](https://atlas.mitre.org/)
* [MITRE ATT&CK®](https://attack.mitre.org/)
* [Google Secure AI Framework (SAIF)](https://saif.google/)
* [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
* [OWASP Top 10 for Machine Learning Security](https://owasp.org/www-project-machine-learning-security-top-10/)
* [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
* [Cisco Integrated AI Security and Safety Framework](https://learn-cloudsecurity.cisco.com/ai-security-framework)
* [NIST Adversarial Machine Learning 2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)

---

### 📬 Contact

This work is led by **Edward Lee**. You can [connect with me on LinkedIn](https://www.linkedin.com/in/go-edwardlee/).

### 📜 License

This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).
