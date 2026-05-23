from .base import Finding, Severity
from .outbound import OutboundScanner
from .path_manip import PathManipScanner
from .deps import DepsScanner
from .secrets import SecretsScanner
from .retention import RetentionScanner
from .validation import ValidationScanner
from .ai_ml import AiMlScanner
from .web_app import WebAppScanner

ALL_SCANNERS = [
    OutboundScanner,
    PathManipScanner,
    DepsScanner,
    SecretsScanner,
    RetentionScanner,
    ValidationScanner,
    AiMlScanner,
    WebAppScanner,
]
