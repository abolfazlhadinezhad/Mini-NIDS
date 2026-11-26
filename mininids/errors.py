"""Expected input errors, separate from programming defects."""


class CaptureError(ValueError):
    """Invalid or unsupported capture envelope."""


class ParseError(ValueError):
    """A packet header cannot safely be decoded."""

    def __init__(self, message: str, *, truncated: bool = False):
        super().__init__(message)
        self.truncated = truncated


def need(data: bytes, count: int, label: str) -> None:
    if len(data) < count:
        raise ParseError(f"short {label}: need {count}, have {len(data)}", truncated=True)
