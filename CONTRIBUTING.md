# Contributing to KnightEye-Timeline

KnightEye-Timeline is not a typical security project.

It is an evidence-first incident reconstruction engine focused on forensic integrity, behavioral understanding, and investigation reasoning.

If you are interested in how cyber incidents should be reconstructed, not just detected, you are in the right place.

---

## △ What Kind of Project This Is

KnightEye-Timeline is being built as:

- a DFIR and evidence reconstruction engine  
- a research framework for incident modeling  
- a foundation for future security products  

This means contributions are expected to value:

- correctness over convenience  
- clarity over cleverness  
- reproducibility over speed  
- systems thinking over scripts  

KnightEye is not a dashboard project.  
KnightEye is not an alerting engine.  
KnightEye is not a “quick feature” codebase.

KnightEye is an investigation engine.

---

## △ Contribution Tracks

KnightEye welcomes contributions across three main tracks.

You do not need to be an expert in all three.  
You should care deeply about at least one.

---

### DFIR Track — Forensics & Reconstruction

Focus areas:

- evidence modeling  
- forensic data handling  
- timeline construction logic  
- integrity verification  
- reconstruction quality  

Examples:

- improving evidence chain design  
- refining incident formation logic  
- strengthening timeline compression  
- improving traceability from narrative to evidence  

If you think in terms of investigations, not tools, this track is for you.

---

### Research Track — Reasoning & Modeling

Focus areas:

- correlation engines  
- storyline reconstruction  
- causality modeling  
- scoring and prioritization  
- evaluation methods  

Examples:

- new storyline builders  
- attack progression models  
- reconstruction quality metrics  
- replay and benchmarking systems  

If you care about *how machines can assist investigation thinking*, this track is for you.

---

### Engineering Track — Systems & Platform

Focus areas:

- architecture  
- performance  
- APIs  
- storage  
- extensibility  
- testing  

Examples:

- formalizing engine interfaces  
- improving determinism and reproducibility  
- building export pipelines  
- hardening evidence storage  
- improving scalability  

If you enjoy building serious foundations, this track is for you.

---

## △ Core Contribution Principles

All contributions to KnightEye should respect the following:

### Evidence is sacred  
Raw telemetry must remain immutable.  
Derived intelligence must always be traceable back to evidence.

---

### Reconstruction over detection  
Changes should improve clarity of timelines, incidents, or narratives, not alert volume.

---

### Determinism matters  
The same input should produce the same output.

If a change introduces randomness, it must be explicit, controlled, and justified.

---

### Heuristics are engines  
Reasoning logic should move toward being modular, testable, and replaceable.

---

### Design is part of the contribution  
Architecture, documentation, and explanation are as important as code.

---

## △ How to Get Started

1. Read the README and understand the project doctrine.
2. Explore the codebase with the investigation model in mind:
   - evidence
   - incidents
   - timelines
   - storylines
   - narratives
3. Check GitHub Issues and look for:
   - `good-first-issue`
   - `dfir`
   - `research`
   - `engine`
4. If no issue fits, open a discussion with:
   - what you want to work on  
   - which track it aligns with  
   - what problem it solves  

Thoughtful proposals are welcome.

---

## △ Setting Up a Development Environment

General expectations:

- Python 3.x  
- virtual environment  
- ability to run the backend and investigation pipeline  
- ability to replay or ingest telemetry  

Setup instructions will evolve as KnightEye stabilizes.  
Early contributors are encouraged to improve setup clarity.

---

## △ Pull Request Guidelines

A good pull request should:

- clearly state *what investigation problem it improves*  
- explain *why the change matters for reconstruction*  
- document any new reasoning logic  
- preserve or improve evidence traceability  
- include tests where feasible  

Pull requests may be reviewed for:

- forensic implications  
- architectural consistency  
- determinism  
- clarity of intent  

This is normal for this project.

---

## △ Research Contributions

Research-oriented contributions are strongly encouraged.

This includes:

- experimental engines  
- alternative correlation models  
- evaluation harnesses  
- dataset tooling  
- documentation of findings  

If your contribution is exploratory, label it clearly and document assumptions.

KnightEye is meant to support investigation research, not hide it.

---

## △ Engineering Standards

Over time, KnightEye aims to establish:

- stable internal schemas  
- defined engine interfaces  
- reproducible pipelines  
- explicit investigation stages  

If you are contributing engineering work, design notes are expected.

Code without explanation is considered incomplete.

---

## △ Communication & Culture

KnightEye is built around:

- curiosity  
- rigor  
- patience  
- intellectual honesty  

There is no rush culture here.

We are trying to model how cyber investigations *should* be supported.

Respectful technical disagreement is welcome.  
Hand-wavy contributions are not.

---

## △ Final Note

KnightEye is not trying to win dashboards.

KnightEye is trying to win understanding.

If you care about understanding incidents; how they form, how they unfold, how they should be reconstructed; your contribution will matter here.
