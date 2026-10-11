# CyberDetect — Threat Intelligence

A drag-and-drop cybersecurity workflow builder developed during a hackathon to simplify product risk assessment through customizable, plugin-based AI workflows.

## Key Features

* **Visual Workflow Builder:** Assemble risk assessment workflows using a drag-and-drop interface.
* **Plugin-Based Analysis:** Integrate Product Profiling, CVE Analysis, Vendor Analysis, and Compliance checks.
* **Dynamic Workflows:** User-defined layouts are converted into executable LangGraph workflows without fixed routing.
* **Human-in-the-Loop:** Add approval checkpoints for manual review and decision-making.
* **Parallel Execution:** Support fan-out and fan-in patterns for concurrent analysis.
* **Automated Risk Aggregation:** Automatically attach a Risk Aggregator after every fan-in to consolidate assessment results.

## Tech Stack

Python · FastAPI · LangGraph · LLMs · Plugin-Based Architecture

## Overview

CyberDetect enables users to build flexible product risk assessment pipelines visually, combining threat intelligence, vulnerability analysis, compliance checks, and human oversight into a unified workflow.
