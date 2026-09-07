export const aidefendVersion = "1.20260907";

export const aidefendIntroduction = {
    "mainTitle": "About AIDEFEND™ - An AI Defense Framework",
    "sections": [
        {
            "title": "What is AIDEFEND™?",
            "paragraphs": [
                "AIDEFEND™ (Artificial Intelligence Defense Framework) is a knowledge base of defensive countermeasures designed to protect AI/ML systems. Inspired by cybersecurity frameworks like MITRE D3FEND™, MITRE ATT&CK®, and MITRE ATLAS™, AIDEFEND™ complements MITRE ATLAS™ by focusing on AI defense.<br><br><strong>Please note: <u>This work is a personal initiative.</u></strong> It was inspired by resources including MITRE's frameworks (D3FEND, ATT&CK, ATLAS), the MAESTRO Threat Modeling framework by Ken Huang (Cloud Security Alliance Research Fellow), Google's Secure AI Framework (SAIF), OWASP Top 10 lists (LLM Applications 2026, ML Security 2023, Agentic Applications 2026), Cisco Integrated AI Security and Safety Framework, NIST Adversarial Machine Learning 2025, and Databricks AI Security Framework (DASF) 3.0. However, <u><strong>this work is not affiliated with, endorsed by, or otherwise connected to the MITRE Corporation, the creator of the MAESTRO framework (Ken Huang), Google, OWASP, Cisco, NIST, or Databricks.</u></strong>"
            ]
        },
        {
            "title": "What has been developed?",
            "paragraphs": [
                "Organized across seven defensive tactics (Model, Harden, Detect, Isolate, Deceive, Evict, and Restore), AIDEFEND provides practical implementation strategies and code examples for protecting AI/ML systems. Parent techniques organize coherent defensive families; standalone techniques and leaf sub-techniques describe actionable technical controls. Guidance entries describe implementation paths within their owning control. The framework can be viewed by Tactic, technology Pillar, or lifecycle Phase, and relates its defenses to threats and risks from 9 major AI security frameworks: MITRE ATLAS, MAESTRO, OWASP Top 10 for LLM, ML, and Agentic Applications, NIST Adversarial ML, Cisco AI Security, Google SAIF, and Databricks DASF."
            ]
        },
        {
            "title": "Who is behind this initiative?",
            "paragraphs": [
                "This work is led by Edward Lee. I'm passionate about Cybersecurity, AI and emerging technologies, and will always be a learner. <a href=\"https://www.linkedin.com/in/go-edwardlee/\" target=\"_blank\" rel=\"noopener noreferrer\">Connect with me on LinkedIn</a>."
            ]
        },
        {
            "title": "Version & Date",
            "paragraphs": [
                `Version: ${aidefendVersion}`,
                "Last Updated: August 30, 2026 (Taipei Time, UTC+8)"
            ]
        },
        {
            "title": "Frameworks & Resources Referenced",
            "paragraphs": [
                "MAESTRO Framework: An Agentic AI threat modeling framework created by Ken Huang.",
                "MITRE D3FEND™ Framework: A knowledge graph of cybersecurity countermeasure techniques developed by MITRE.",
                "MITRE ATT&CK® Framework: A globally accessible knowledge base of adversary tactics and techniques based on real-world observations developed by MITRE.",
                "MITRE ATLAS™ Framework: A threat modeling framework for AI systems, cataloging adversary behaviors specific to machine learning developed by MITRE.",
                "OWASP Top 10 for LLM Applications 2026: A curated list of the most critical security risks to large language model applications.",
                "OWASP Top 10 for Machine Learning Security 2023: A security awareness and risk prioritization guide addressing common vulnerabilities in ML systems.",
                "OWASP Top 10 for Agentic Applications 2026: A comprehensive guide identifying the most critical security risks specific to autonomous AI agents and multi-agent systems.",
                "Cisco Integrated AI Security and Safety Framework: A structured framework addressing security and safety considerations across the AI lifecycle, from development to deployment.",
                "NIST Adversarial Machine Learning 2025: NIST's guidance on understanding and mitigating adversarial attacks on machine learning systems.",
                "Google Secure AI Framework (SAIF): A structured approach to safely design, deploy, and manage AI, ensuring the integrity of data, infrastructure, model and application.",
                "Databricks AI Security Framework (DASF) 3.0: A comprehensive risk-based framework addressing AI/ML security across the full data and model lifecycle, with detailed coverage of agentic AI and MCP ecosystem risks."
            ]
        }
    ]
};
