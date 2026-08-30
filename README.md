# VibeCheck
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/ebc8112e-32fd-4b4c-8e00-fb73067628b1" />
A local, AI-assisted code security analysis application that combines **local LLM-based code review** with **Semgrep SAST analysis** to identify security vulnerabilities, bugs, and reliability issues in source code.

The application is designed to run locally, keeping submitted source code and AI analysis on the user's machine rather than sending code to an external AI service.

---

## Overview

Modern development tools often separate AI-assisted code review from traditional Static Application Security Testing (SAST).

This project combines both approaches into a single local application:

* **AI Code Review** using a locally hosted Ollama model
* **SAST Analysis** using Semgrep community rules
* **Automatic Programming Language Detection**
* **Language-specific Semgrep rule selection**
* **Evidence-based vulnerability reporting**
* **Finding correlation and duplicate reduction**
* **Local-first architecture**

The goal is to combine the reasoning capabilities of an LLM with the deterministic pattern-based analysis of a SAST engine.

---

## Architecture

```text
                    ┌──────────────────────┐
                    │      User Code       │
                    │   Paste / Type Code  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  Language Detector   │
                    │                      │
                    │ Python / Java / C++  │
                    │ JS / TS / Go / Rust  │
                    │ PHP / Ruby / etc.    │
                    └──────────┬───────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
                    ▼                     ▼
          ┌──────────────────┐   ┌──────────────────┐
          │   Ollama / LLM   │   │     Semgrep      │
          │                  │   │                  │
          │ AI Code Review   │   │ Language-specific│
          │                  │   │ SAST Rules       │
          └────────┬─────────┘   └────────┬─────────┘
                   │                      │
                   ▼                      ▼
          ┌────────────────────────────────────┐
          │       Finding Correlation           │
          │                                    │
          │ Evidence validation                │
          │ Duplicate reduction                │
          │ Finding combination                │
          └──────────────────┬─────────────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │   Security Report   │
                  │                     │
                  │ Severity            │
                  │ Evidence            │
                  │ Impact              │
                  │ Remediation         │
                  │ Source              │
                  │ Line Numbers        │
                  └─────────────────────┘
```

---

## Key Features

### 🤖 Local AI Code Review

The application uses **Ollama** to run a local coding-focused language model.

The AI reviews source code for issues such as:

* Command injection
* Unsafe code execution
* SQL injection
* Unsafe deserialization
* Hardcoded secrets
* Path traversal
* Dangerous file permissions
* Runtime errors
* Logic problems
* Resource-management issues
* Other security and reliability problems

Because the model runs locally, source code does not need to be sent to a cloud AI provider.

---

### 🔍 Static Application Security Testing

The application uses **Semgrep** as its deterministic SAST engine.

Instead of running Semgrep's entire automatic rule collection for every scan, the application selects a **language-specific community rule configuration** based on the detected programming language.

For example:

```text
Python      → p/python
Java        → p/java
JavaScript  → p/javascript
C           → p/c
C++         → p/cpp
Go          → p/go
Rust        → p/rust
Ruby        → p/ruby
PHP         → p/php
...
```

This significantly reduces unnecessary rule processing and improves scan performance compared with running a large general-purpose rule collection.

---

### 🌐 Automatic Language Detection

The application detects the programming language from the source code itself.

It does not depend on the user selecting a language manually.

Detection uses characteristics such as:

* Language-specific keywords
* Imports
* Function declarations
* Syntax patterns
* Language-specific APIs
* Shebangs
* Other distinctive source-code characteristics

The detector currently supports multiple programming languages, including:

* Python
* JavaScript
* TypeScript
* Java
* C
* C++
* C#
* Go
* Rust
* PHP
* Ruby
* Kotlin
* Swift

When the detector cannot confidently identify the language, it can return `unknown` instead of making an unsafe guess.

---

### 🧠 Dual Analysis

The project intentionally uses two different analysis approaches.

#### AI

The LLM provides:

* Contextual reasoning
* Explanations
* Impact descriptions
* Remediation suggestions
* Identification of issues that may require broader reasoning

#### Semgrep

Semgrep provides:

* Deterministic static analysis
* Established security rules
* Exact source locations
* Pattern-based vulnerability detection
* Language-specific security checks

Using both allows the application to compare and combine two different forms of analysis.

---

### 🔗 Finding Correlation

AI and Semgrep may identify the same vulnerability independently.

The application therefore includes a correlation stage intended to:

* Compare findings
* Identify duplicates
* Preserve useful evidence
* Combine information from different analysis sources
* Prevent the final report from becoming unnecessarily repetitive

For example:

```text
AI:
Command Injection
Line 12

Semgrep:
OS Command Injection
Line 12

              ↓

        Correlation

              ↓

Combined finding
```

---

### 📌 Evidence Validation

AI-generated findings are not blindly trusted.

The application validates whether the evidence provided by the AI actually exists in the submitted source code.

This helps prevent situations where an LLM:

* Invents code
* Reports code that was not submitted
* Produces incorrect line numbers
* Generates a vulnerability without concrete source evidence

The goal is to make AI findings more reliable before they are included in the final analysis.

---

## Technology Stack

| Component            | Technology              |
| -------------------- | ----------------------- |
| Programming Language | Python                  |
| GUI                  | PySide6                 |
| AI Runtime           | Ollama                  |
| AI Model             | Qwen2.5-Coder           |
| SAST                 | Semgrep                 |
| Validation           | Pydantic                |
| HTTP Client          | Requests                |
| Platform             | Local / Offline-capable |

---

## Project Structure

```text
DEVSECOPS/
│
├── backend/
│   ├── analysis_service.py
│   ├── language_detector.py
│   ├── ollama_client.py
│   ├── review_service.py
│   ├── semgrep_service.py
│   └── models.py
│
├── desktop/
│   └── main.py
│
├── tests/
│   └── ...
│
├── semgrep_rules/
│   └── ...
│
├── requirements.txt
└── README.md
```

> The exact structure may change as development continues.

---

## Requirements

Before running the application, install:

* Python 3
* Ollama
* Semgrep
* Required Python packages

A coding model must also be available through Ollama.

For example:

```bash
ollama pull qwen2.5-coder:7b
```

---

## Installation

### 1. Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd DEVSECOPS
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it:

#### Linux / macOS

```bash
source venv/bin/activate
```

#### Windows

```powershell
venv\Scripts\activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install and start Ollama

Make sure Ollama is installed and running.

Verify that the model is available:

```bash
ollama list
```

If necessary:

```bash
ollama pull qwen2.5-coder:7b
```

### 5. Verify Semgrep

```bash
semgrep --version
```

---

## Running the Application

From the project root:

```bash
python -m desktop.main
```

The application should launch the desktop interface.

You can then paste or type source code into the editor.

The application will:

```text
Code entered
     ↓
Detect language
     ↓
Run AI review
     ↓
Run language-specific Semgrep rules
     ↓
Correlate findings
     ↓
Display results
```

---

## Example

Given code containing an unsafe shell command:

```python
import subprocess

filename = input("Enter filename: ")
subprocess.run("cat " + filename, shell=True)
```

The system can potentially identify the issue through both:

```text
AI Analysis
    +
Semgrep SAST
```

The resulting report can include:

```text
Title
Severity
Category
Evidence
Impact
Remediation
Source
Line Number
```

---

## Why Use Both AI and SAST?

AI and traditional static analysis have different strengths.

### Traditional SAST

Advantages:

* Deterministic
* Fast
* Reproducible
* Rule-based
* Strong at known vulnerability patterns

Limitations:

* Depends on available rules
* Can miss unusual logic problems
* May have difficulty understanding developer intent

### AI Analysis

Advantages:

* Can reason about code context
* Can explain vulnerabilities
* Can identify certain logic and reliability problems
* Can provide human-readable remediation

Limitations:

* Can produce false positives
* Can misunderstand code
* Can hallucinate evidence
* Results can vary between models

This project attempts to combine their strengths while reducing the weaknesses of AI through evidence validation and correlation.

---

## Privacy

The project is designed around a local-first workflow.

Source code is processed locally through:

* The desktop application
* Ollama
* Semgrep

No external AI API is required for the core analysis pipeline.

This makes the architecture suitable for experimenting with security analysis where sending source code to third-party AI services is undesirable.

---

## Current Limitations

This project is still under development.

Current limitations include:

* Language detection is heuristic-based.
* Very short or ambiguous code snippets may not be detected correctly.
* AI analysis depends on the capabilities of the selected local model.
* Semgrep coverage depends on the available community rules.
* Some vulnerabilities require program-wide or cross-file context that cannot be reliably determined from a single pasted snippet.
* Local AI inference can be significantly slower on CPU-only systems.

---

## Future Improvements

Possible future development includes:

* Support for additional programming languages
* Improved language detection
* Better AI/SAST finding correlation
* More advanced duplicate detection
* Configurable security policies
* File and folder scanning
* Project-level analysis
* Git integration
* Commit-level security analysis
* Improved vulnerability explanations
* Performance optimization
* Additional SAST rule sources
* Security report export
* IDE integration

---

## Project Goals

The primary goal is to explore how **local AI reasoning and traditional SAST techniques can complement each other** in software security analysis.

Rather than replacing SAST with AI, the project treats AI as an additional analysis layer and attempts to combine both sources into a more useful security review.

---

## Disclaimer

This project is intended for **educational, research, and development purposes**.

Automated security analysis should not be considered a substitute for professional security review, penetration testing, or comprehensive software testing.

---

## License

License information will be added as the project develops.

