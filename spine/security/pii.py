"""
MCP Spine — PII Detection & Scrambling

Uses Microsoft Presidio Analyzer for detection and Presidio Anonymizer custom
operators for replacement. Replacement values come from Faker where possible
and deterministic local generators where Faker could produce real routable
values.

By default, Presidio's NLP-backed analyzer is used for broader entity
coverage. That path may download a spaCy model on first use depending on the
runtime environment. Servers can opt out with scramble_pii_use_nlp = false.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from typing import Any, Iterable

os.environ.setdefault(
    "TLDEXTRACT_CACHE",
    os.path.join(tempfile.gettempdir(), "mcp-spine-tldextract"),
)


class PiiScramblerUnavailable(RuntimeError):
    """Raised when PII scrambling is enabled without the optional dependencies."""


class _NoOpNlpEngine:
    """Minimal Presidio NLP engine for non-NER recognizers."""

    def load(self) -> None:
        return None

    def is_loaded(self) -> bool:
        return True

    def process_text(self, text: str, language: str):
        from presidio_analyzer.nlp_engine import NlpArtifacts

        return NlpArtifacts(
            entities=[],
            tokens=[],
            tokens_indices=[],
            lemmas=[],
            nlp_engine=self,
            language=language,
        )

    def process_batch(
        self,
        texts: Iterable[str],
        language: str,
        batch_size: int = 1,
        n_process: int = 1,
        **kwargs: Any,
    ):
        for text in texts:
            yield text, self.process_text(text, language)

    def is_stopword(self, word: str, language: str) -> bool:
        return False

    def is_punct(self, word: str, language: str) -> bool:
        return False

    def get_supported_entities(self) -> list[str]:
        return []

    def get_supported_languages(self) -> list[str]:
        return ["en"]


def _stable_int(value: str, modulo: int) -> int:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return int(digest[:12], 16) % modulo


def _reserved_ipv4(value: str) -> str:
    return f"203.0.113.{_stable_int(value, 254) + 1}"


def _reserved_ipv6(value: str) -> str:
    return f"2001:db8::{_stable_int(value, 65_535):x}"


def _fake_identifier(fake: Any, prefix: str) -> str:
    return f"{prefix}{fake.numerify('#########')}"


def _fake_value(entity_type: str, value: str) -> str:
    try:
        from faker import Faker
    except ImportError as exc:
        raise PiiScramblerUnavailable(
            "PII scrambling requires Faker for Presidio custom anonymizers. "
            "Install the optional dependencies with `pip install mcp-spine[pii]`."
        ) from exc

    fake = Faker("en_US")
    fake.seed_instance(_stable_int(f"{entity_type}:{value}", 1_000_000_000))

    if entity_type == "EMAIL_ADDRESS":
        return fake.safe_email()
    if entity_type == "PHONE_NUMBER":
        return fake.phone_number()
    if entity_type == "CREDIT_CARD":
        return fake.credit_card_number()
    if entity_type == "IP_ADDRESS":
        return _reserved_ipv6(value) if ":" in value else _reserved_ipv4(value)
    if entity_type == "MAC_ADDRESS":
        return fake.mac_address()
    if entity_type in {"POSTAL_CODE", "UK_POSTCODE"}:
        return fake.postcode()
    if entity_type == "URL":
        return fake.url()
    if entity_type == "IBAN_CODE":
        return fake.iban()
    if entity_type == "CRYPTO":
        return "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty"
    if entity_type == "DATE_TIME":
        return fake.date()
    if entity_type == "PERSON":
        return fake.name()
    if entity_type == "LOCATION":
        return fake.city()
    if entity_type == "ORGANIZATION":
        return fake.company()
    if entity_type == "NRP":
        return fake.country()
    if entity_type == "AGE":
        return str(fake.random_int(min=18, max=89))
    if entity_type == "US_SSN":
        return fake.ssn()
    if entity_type == "US_ITIN":
        return (
            f"9{fake.random_int(min=10, max=99)}-"
            f"7{fake.random_int(min=0, max=9)}-{fake.numerify('####')}"
        )
    if "PASSPORT" in entity_type:
        return _fake_identifier(fake, "P")
    if "DRIVER_LICENSE" in entity_type or "LICENSE" in entity_type:
        return _fake_identifier(fake, "D")
    if "BANK" in entity_type or "IBAN" in entity_type:
        return fake.bban()
    if any(
        token in entity_type
        for token in ("NHS", "NPI", "MEDICAL", "MEDICARE", "MBI")
    ):
        return _fake_identifier(fake, "M")
    if any(token in entity_type for token in ("VEHICLE", "REGISTRATION")):
        return fake.license_plate()
    return _fake_identifier(fake, "ID")


def _build_postal_recognizer():
    try:
        from presidio_analyzer import Pattern, PatternRecognizer
    except ImportError as exc:
        raise PiiScramblerUnavailable(
            "PII scrambling requires Microsoft Presidio. "
            "Install the optional dependencies with `pip install mcp-spine[pii]`."
        ) from exc

    return PatternRecognizer(
        supported_entity="POSTAL_CODE",
        name="PostalCodeRecognizer",
        patterns=[
            Pattern(
                "Labeled US ZIP",
                r"(?i)(?<=\b(?:zip|postal)(?:\s+code)?\s*[:=#]?\s*)\d{5}(?:-\d{4})?",
                0.85,
            ),
            Pattern("US ZIP+4", r"\b\d{5}-\d{4}\b", 0.65),
            Pattern(
                "Canadian postal code",
                r"\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z][ -]?\d[ABCEGHJ-NPRSTV-Z]\d\b",
                0.75,
            ),
        ],
    )


def _build_pattern_only_analyzer():
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.recognizer_registry import RecognizerRegistry
    except ImportError as exc:
        raise PiiScramblerUnavailable(
            "PII scrambling requires Microsoft Presidio. "
            "Install the optional dependencies with `pip install mcp-spine[pii]`."
        ) from exc

    registry = RecognizerRegistry(supported_languages=["en"])
    registry.load_predefined_recognizers(languages=["en"], nlp_engine=_NoOpNlpEngine())
    registry.add_recognizer(_build_postal_recognizer())
    return AnalyzerEngine(
        registry=registry,
        nlp_engine=_NoOpNlpEngine(),
        supported_languages=["en"],
        default_score_threshold=0.35,
    )


def _build_presidio_analyzer(use_nlp: bool):
    try:
        from presidio_analyzer import AnalyzerEngine
    except ImportError as exc:
        raise PiiScramblerUnavailable(
            "PII scrambling requires Microsoft Presidio. "
            "Install the optional dependencies with `pip install mcp-spine[pii]`."
        ) from exc

    if not use_nlp:
        return _build_pattern_only_analyzer()

    try:
        analyzer = AnalyzerEngine(default_score_threshold=0.35)
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        raise PiiScramblerUnavailable(
            "Presidio NLP analyzer initialization failed. It may need to download "
            "a spaCy model on first use; install the model ahead of time or set "
            "`scramble_pii_use_nlp = false` for pattern/checksum-only detection."
        ) from exc

    analyzer.registry.add_recognizer(_build_postal_recognizer())
    return analyzer


def _build_presidio_anonymizer():
    try:
        from presidio_anonymizer import AnonymizerEngine
    except ImportError as exc:
        raise PiiScramblerUnavailable(
            "PII scrambling requires Presidio Anonymizer. "
            "Install the optional dependencies with `pip install mcp-spine[pii]`."
        ) from exc

    return AnonymizerEngine()


def _build_operator_config(entity_type: str):
    from presidio_anonymizer.entities import OperatorConfig

    def replace_with_fake(value: str) -> str:
        return _fake_value(entity_type, value)

    return OperatorConfig("custom", {"lambda": replace_with_fake})


def _build_anonymizer_operators(entity_types: Iterable[str]) -> dict[str, Any]:
    from presidio_anonymizer.entities import OperatorConfig

    operators = {
        "DEFAULT": OperatorConfig(
            "custom",
            {"lambda": lambda value: _fake_value("ID", value)},
        ),
    }
    for entity_type in entity_types:
        operators[entity_type] = _build_operator_config(entity_type)
    return operators


_SENSITIVE_ID_KEYS = {
    "library_card_number",
    "cultural_pass_number",
    "reset_password_token",
    "otp_secret",
    "tokens",
}

_SENSITIVE_FREE_TEXT_KEYS = {
    "notes",
    "customized_filters",
}

_STRUCTURED_CONTEXT_KEYS = tuple(
    sorted(
        {
            "address",
            "birth",
            "birthdate",
            "card_number",
            "city",
            "country",
            "credit_card",
            "crypto_wallet",
            "current_sign_in_ip",
            "cultural_pass_number",
            "customized_filters",
            "date_of_birth",
            "dob",
            "email",
            "email_address",
            "fax",
            "homepage_url",
            "iban",
            "ip_address",
            "last_sign_in_ip",
            "library_card_number",
            "login",
            "mac_address",
            "mobile",
            "notes",
            "otp_secret",
            "parent_email_address",
            "phone",
            "phone_number",
            "postal_code",
            "postcode",
            "province",
            "reset_password_token",
            "social_security",
            "social_security_number",
            "ssn",
            "state",
            "tokens",
            "username",
            "zip",
            "zipcode",
        },
        key=len,
        reverse=True,
    )
)


def _entity_for_context_key(key: str) -> str | None:
    normalized = key.lower()
    if normalized in {"login", "username"}:
        return "ID"
    if normalized in _SENSITIVE_ID_KEYS or normalized in _SENSITIVE_FREE_TEXT_KEYS:
        return "ID"
    if "email" in normalized:
        return "EMAIL_ADDRESS"
    if "phone" in normalized or "mobile" in normalized or "fax" in normalized:
        return "PHONE_NUMBER"
    if "credit_card" in normalized:
        return "CREDIT_CARD"
    if "ip_address" in normalized or normalized.endswith("_ip"):
        return "IP_ADDRESS"
    if "mac_address" in normalized:
        return "MAC_ADDRESS"
    if "url" in normalized:
        return "URL"
    if "iban" in normalized:
        return "IBAN_CODE"
    if "crypto" in normalized:
        return "CRYPTO"
    if "ssn" in normalized or "social_security" in normalized:
        return "US_SSN"
    if "zip" in normalized or "postal" in normalized or "postcode" in normalized:
        return "POSTAL_CODE"
    if "address" in normalized or normalized in {"city", "state", "province", "country"}:
        return "LOCATION"
    if "birth" in normalized or normalized in {"dob", "date_of_birth"}:
        return "DATE_TIME"
    if normalized == "card_number" or normalized.endswith(("_card_number", "_pass_number")):
        return "ID"
    return None


def _replace_keyed_value(label: str, value: str) -> str:
    entity_type = _entity_for_context_key(label)
    if not entity_type or not value.strip():
        return value
    return _fake_value(entity_type, value)


def _scramble_structured_text(text: str) -> str:
    """
    Scramble values in common serialized row formats before NLP runs.

    Database MCP servers often return rows as text like:
      {'column_name': 'last_name', 'value': 'Smith'}
      {'email': 'jane@example.com', 'zipcode': '90210'}

    Presidio sees that as one free-form sentence and can miss short ZIP codes
    or app-specific identifiers. This pass keeps the output shape intact but
    uses nearby field names as context for replacement.
    """
    key_pattern = r"(?:" + "|".join(re.escape(key) for key in _STRUCTURED_CONTEXT_KEYS) + r")"

    column_value_pattern = re.compile(
        rf"(?P<prefix>['\"]column_name['\"]\s*:\s*['\"](?P<label>{key_pattern})['\"]"
        rf"\s*,\s*['\"]value['\"]\s*:\s*['\"])(?P<value>.*?)(?P<suffix>['\"])",
        flags=re.IGNORECASE,
    )

    def replace_column_value(match: re.Match) -> str:
        return (
            match.group("prefix")
            + _replace_keyed_value(match.group("label"), match.group("value"))
            + match.group("suffix")
        )

    text = column_value_pattern.sub(replace_column_value, text)

    direct_key_pattern = re.compile(
        rf"(?P<prefix>['\"](?P<label>{key_pattern})['\"]\s*:\s*['\"])"
        rf"(?P<value>.*?)(?P<suffix>['\"])",
        flags=re.IGNORECASE,
    )

    def replace_direct_key(match: re.Match) -> str:
        return (
            match.group("prefix")
            + _replace_keyed_value(match.group("label"), match.group("value"))
            + match.group("suffix")
        )

    text = direct_key_pattern.sub(replace_direct_key, text)

    sql_literal_pattern = re.compile(
        r"(?P<prefix>(?:\b[a-z_][a-z0-9_]*\.)?\"?(?P<label>[a-z_][a-z0-9_]*)\"?"
        r"\s*(?:=|!=|<>|like|ilike)\s*')"
        r"(?P<value>(?:''|[^'])*)"
        r"(?P<suffix>')",
        flags=re.IGNORECASE,
    )

    def replace_sql_literal(match: re.Match) -> str:
        return (
            match.group("prefix")
            + _replace_keyed_value(match.group("label"), match.group("value"))
            + match.group("suffix")
        )

    return sql_literal_pattern.sub(replace_sql_literal, text)


class _PresidioPiiScrambler:
    def __init__(self, use_nlp: bool) -> None:
        self._analyzer = _build_presidio_analyzer(use_nlp=use_nlp)
        self._anonymizer = _build_presidio_anonymizer()
        self._entities = sorted(
            entity
            for entity in self._analyzer.get_supported_entities(language="en")
            if entity != "PERSON"
        )
        self._operators = _build_anonymizer_operators(self._entities)

    def analyze(self, text: str) -> list[Any]:
        return self._analyzer.analyze(
            text=text,
            language="en",
            entities=self._entities,
            score_threshold=0.35,
        )

    def scramble_text(self, text: str, context_key: str | None = None) -> str:
        if context_key:
            prefix = f"{context_key.replace('_', ' ')}: "
            scrambled = self.scramble_text(f"{prefix}{text}")
            if scrambled.startswith(prefix):
                return scrambled[len(prefix):]
            return scrambled

        text = _scramble_structured_text(text)
        results = self.analyze(text)
        if not results:
            return text
        return self._anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=self._operators,
        ).text


_SCRAMBLERS: dict[bool, _PresidioPiiScrambler] = {}


def _get_scrambler(use_nlp: bool = True) -> _PresidioPiiScrambler:
    if use_nlp not in _SCRAMBLERS:
        _SCRAMBLERS[use_nlp] = _PresidioPiiScrambler(use_nlp=use_nlp)
    return _SCRAMBLERS[use_nlp]


def scramble_pii(text: str, use_nlp: bool = True) -> str:
    """Replace likely PII in text with deterministic fake values."""
    return _get_scrambler(use_nlp=use_nlp).scramble_text(text)


def contains_pii(text: str, use_nlp: bool = True) -> bool:
    """Quick check: does this string contain likely PII?"""
    return bool(_get_scrambler(use_nlp=use_nlp).analyze(text))


def scramble_pii_value(
    value: Any,
    context_key: str | None = None,
    use_nlp: bool = True,
) -> Any:
    """Deep-scramble PII in string values while preserving container shape."""
    if isinstance(value, str):
        return _get_scrambler(use_nlp=use_nlp).scramble_text(
            value,
            context_key=context_key,
        )
    if (
        context_key
        and isinstance(value, (int, float))
        and not isinstance(value, bool)
        and _entity_for_context_key(context_key)
    ):
        return _fake_value(_entity_for_context_key(context_key) or "ID", str(value))
    if isinstance(value, dict):
        return {
            key: scramble_pii_value(item, context_key=str(key), use_nlp=use_nlp)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [scramble_pii_value(item, use_nlp=use_nlp) for item in value]
    if isinstance(value, tuple):
        return tuple(scramble_pii_value(item, use_nlp=use_nlp) for item in value)
    return value
