# Mini-NIDS

Streaming Python network intrusion detection with manually parsed protocol
headers and contextual rules. Academic specification: local Mini-NIDS.pdf.

Implementation is under development. See PROJECT_PLAN.md, REQUIREMENTS.md and
IMPLEMENTATION_STATUS.md for scope and validation boundaries.

## Development

Python 3.11 or newer. Create a virtual environment, then install with
`python -m pip install -e ".[dev]"`. Run `python -m pytest` and
`python -m ruff check .` from the workspace.

The mandatory analyzer uses no runtime protocol-dissection library. Scapy is a
development reference and optional capture adapter only. Never commit datasets,
credentials or local virtual environments.
