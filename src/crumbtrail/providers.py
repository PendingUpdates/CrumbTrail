"""Explicit provider/channel/event interpretation policy; no evidence inference."""


# These are the existing interpreted events plus the two imported boundaries.
# Provider names are compared case-insensitively, never rewritten in evidence.
SUPPORTED_EVENTS = {
    ("Security", 4624): ("Microsoft-Windows-Security-Auditing", "logon.success"),
    ("Security", 4625): ("Microsoft-Windows-Security-Auditing", "logon.failure"),
    ("Security", 4688): ("Microsoft-Windows-Security-Auditing", "process"),
    ("Security", 4697): ("Microsoft-Windows-Security-Auditing", "service"),
    ("Security", 4698): ("Microsoft-Windows-Security-Auditing", "task"),
    ("Security", 4634): ("Microsoft-Windows-Security-Auditing", "event"),
    ("Security", 4608): ("Microsoft-Windows-Security-Auditing", "event"),
    ("Security", 1102): ("Microsoft-Windows-Eventlog", "log.clear"),
    ("System", 104): ("Microsoft-Windows-Eventlog", "log.clear"),
    ("System", 7045): ("Service Control Manager", "service"),
    ("Microsoft-Windows-Sysmon/Operational", 1): ("Microsoft-Windows-Sysmon", "process"),
    ("Microsoft-Windows-Sysmon/Operational", 3): ("Microsoft-Windows-Sysmon", "network"),
    ("Microsoft-Windows-Sysmon/Operational", 11): ("Microsoft-Windows-Sysmon", "file"),
    ("Microsoft-Windows-Sysmon/Operational", 15): ("Microsoft-Windows-Sysmon", "file"),
    ("Microsoft-Windows-PowerShell/Operational", 4104): ("Microsoft-Windows-PowerShell", "script"),
    ("Microsoft-Windows-Windows Defender/Operational", 1116): ("Microsoft-Windows-Windows Defender", "detection"),
    ("Microsoft-Windows-Windows Defender/Operational", 1117): ("Microsoft-Windows-Windows Defender", "detection"),
}
_PROVIDERS = frozenset(provider.casefold() for provider, _ in SUPPORTED_EVENTS.values())
_REASONS = {
    "supported": "Provider, channel and event ID combination is supported.",
    "missing-provider": "Provider name is missing.",
    "unsupported-provider": "Provider name is not supported.",
    "unsupported-event": "Provider, channel and event ID combination is not supported.",
}


def classify(channel, provider, event_code):
    """Classify supplied identity fields without guessing a provider or schema."""
    if provider is None or isinstance(provider, str) and not provider.strip():
        status = "missing-provider"
    elif not isinstance(provider, str) or provider.casefold() not in _PROVIDERS:
        status = "unsupported-provider"
    else:
        expected = SUPPORTED_EVENTS.get((channel, event_code)) if isinstance(channel, str) and type(event_code) is int else None
        status = "supported" if expected and provider.casefold() == expected[0].casefold() else "unsupported-event"
    return dict(status=status, reason=_REASONS[status])


def event_classification(event):
    """Re-evaluate source identity rather than trusting cached interpretation."""
    return classify(event.get("channel"), event.get("provider"), event.get("event_code"))


def supported_kind(event):
    """Return the registered base kind, or None for an unclassified event."""
    if event_classification(event)["status"] != "supported":
        return None
    return SUPPORTED_EVENTS[(event["channel"], event["event_code"])][1]


def unclassified_label(channel, event_code, classification):
    return f"Unclassified {channel} event {event_code}: {classification['reason']}"
