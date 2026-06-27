# Contributing to AIDEFEND: An AI Defense Framework

Thank you for your interest in contributing to the AIDEFEND (Artificial Intelligence Defense Framework) project! This document provides guidelines for contributing to this open, AI-focused knowledge base of defensive countermeasures.

## 🎯 Project Overview

AIDEFEND is an interactive framework that helps security professionals protect AI/ML systems from emerging threats. It organizes defensive techniques across three strategic views:
- **Tactics View**: Based on MITRE D3FEND's seven defensive tactics
- **Pillars View**: Organized by technology stack components (Data, Model, Infrastructure, Application)
- **Phases View**: Aligned with AI development and operational lifecycle stages

## 🤝 How You Can Contribute

### 1. Content Contributions
- **New Defensive Techniques**: Add techniques following the AID-[TACTIC]-[NUMBER] naming convention
- **Enhanced Technique Details**: Improve descriptions, implementation strategies, or code examples
- **Threat Mapping Updates**: Add or refine mappings to MITRE ATLAS, MAESTRO, OWASP frameworks
- **Tool Recommendations**: Add open-source or commercial tools for existing techniques

### 2. Technical Improvements
- **User Interface Enhancements**: Improve search functionality, responsiveness, or accessibility
- **Performance Optimizations**: Optimize loading times or interactivity
- **Browser Compatibility**: Ensure cross-browser functionality
- **Mobile Experience**: Enhance mobile device usability

### 3. Documentation & Community
- **Documentation Improvements**: Enhance README, add tutorials, or create user guides
- **Translation**: Translate content to other languages
- **Bug Reports**: Report issues with content accuracy or technical functionality
- **Feature Requests**: Suggest new features or improvements

## 📋 Contribution Process

### Before You Start
1. **Check existing issues/PRs** to avoid duplicate work
2. **Review the live demo** at https://edward-playground.github.io/aidefense-framework/
3. **Understand the framework structure** by examining the codebase

### Making Changes

#### For Content Updates:
1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/add-new-technique`
3. **Update relevant files**:
   - For new techniques: Add to appropriate tactic files in `/tactics/` directory
   - Follow existing JSON structure and ID conventions
   - Include comprehensive threat mappings (ATLAS, MAESTRO, OWASP)
4. **Test your changes** by running the framework locally
5. **Commit with clear messages**: `git commit -m "Add AID-H-023: New LLM Safety Technique"`

#### For Technical Changes:
1. **Test thoroughly** across different browsers and devices
2. **Ensure no breaking changes** to existing functionality
3. **Follow existing code style** and conventions
4. **Update documentation** if adding new features

### Pull Request Guidelines

#### PR Title Format:
- Content: `[CONTENT] Add/Update/Fix: Brief description`
- Technical: `[TECH] Feature/Fix: Brief description`
- Documentation: `[DOCS] Update/Add: Brief description`

#### PR Description Should Include:
- **Clear description** of changes made
- **Justification** for new techniques or modifications
- **Testing performed** (browsers tested, functionality verified)
- **Related issues** (if applicable)
- **Screenshots** (for UI changes)

#### For New Defensive Techniques:
- **Technique ID**: Follow AID-[TACTIC_CODE]-[NUMBER] format
- **Complete Details**: Description, implementation strategies, tools
- **Threat Mappings**: At least one mapping to established frameworks
- **Evidence Base**: Include references to research papers or industry reports when possible

## 🏗️ Project Structure

```
aidefense-framework/
├── tactics/           # Individual tactic definition files
│   ├── model.js      # AID-M-* techniques
│   ├── harden.js     # AID-H-* techniques
│   ├── detect.js     # AID-D-* techniques
│   ├── isolate.js    # AID-I-* techniques
│   ├── deceive.js    # AID-DV-* techniques
│   ├── evict.js      # AID-E-* techniques
│   └── restore.js    # AID-R-* techniques
├── index.html        # Main framework interface
├── main.js           # Core application logic
├── intro.js          # Framework data and definitions
└── README.md         # Project documentation
```

## 📚 Research & References

When contributing new techniques, please reference:
- **Academic Research**: Peer-reviewed papers on AI security
- **Industry Reports**: Threat intelligence from security companies
- **Framework Alignment**: MITRE ATLAS, MAESTRO, OWASP mappings
- **Real-World Examples**: Documented attacks or defenses in production

## 🔍 Quality Standards

### Content Quality:
- **Accuracy**: Ensure technical accuracy of all information
- **Completeness**: Provide comprehensive implementation guidance
- **Relevance**: Focus on practical, deployable countermeasures
- **Clarity**: Use clear, jargon-free language where possible

### Technical Quality:
- **Functionality**: All features must work as intended
- **Performance**: Maintain fast loading and responsive interface
- **Accessibility**: Follow WCAG guidelines for accessibility
- **Security**: No introduction of security vulnerabilities

## ❓ Questions & Support

- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Discussions**: Engage in GitHub Discussions for questions and ideas
- **Contact**: Reach out to project maintainer Edward Lee via [LinkedIn](https://www.linkedin.com/in/go-edwardlee/)

## 📄 License

By contributing to AIDEFEND, you agree that your contributions will be licensed under the [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).

## 🙏 Recognition

All contributors will be recognized in the project documentation. Significant contributions may be highlighted in release notes and project communications.

---

Thank you for helping make AI systems more secure! Your contributions help the entire community defend against evolving AI threats.
