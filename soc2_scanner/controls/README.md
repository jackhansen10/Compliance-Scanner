SOC 2 controls analysis

Each control (CC1–CC8) is implemented as a dedicated module:

- cc1.py: Control Environment
- cc2.py: Communication and Information
- cc3.py: Risk Assessment
- cc4.py: Monitoring Activities
- cc5.py: Control Activities
- cc6.py: Logical and Physical Access
- cc7.py: System Operations
- cc8.py: Change Management

Each module exposes:
- CONTROL_ID
- TITLE
- SOURCES
- evaluate(context)

Shared helpers live in:
- context.py: EvidenceContext, get_cached, status_from_findings
