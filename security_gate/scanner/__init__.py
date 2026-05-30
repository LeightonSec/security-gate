from .base import Finding, Severity
from .outbound import OutboundScanner
from .path_manip import PathManipScanner
from .deps import DepsScanner
from .secrets import SecretsScanner
from .retention import RetentionScanner
from .validation import ValidationScanner
from .ai_ml import AiMlScanner
from .web_app import WebAppScanner
from .security_tool import SecurityToolScanner
from .sca import ScaScanner
from .crypto import CryptoScanner
from .llm_injection import LlmInjectionScanner
from .git_history import GitHistoryScanner
from .bare_suppress import BareSuppressScanner

ALL_SCANNERS = [
    OutboundScanner,
    PathManipScanner,
    DepsScanner,
    SecretsScanner,
    RetentionScanner,
    ValidationScanner,
    AiMlScanner,
    LlmInjectionScanner,
    WebAppScanner,
    SecurityToolScanner,
    ScaScanner,
    CryptoScanner,
    GitHistoryScanner,
    BareSuppressScanner,
]
