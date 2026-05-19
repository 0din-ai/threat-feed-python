from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SEVERE = "severe"


class SecurityBoundary(str, Enum):
    GUARDRAIL_JAILBREAK = "guardrail_jailbreak"
    PROMPT_EXTRACTION = "prompt_extraction"
    INTERPRETER_JAILBREAK = "interpreter_jailbreak"
    UNBOUNDED_CONSUMPTION = "unbounded_consumption"
    CONTENT_MANIPULATION = "content_manipulation"
    WEIGHTS_AND_LAYERS_DISCLOSURE = "weights_and_layers_disclosure"
    PROMPT_INJECTION = "prompt_injection"
    OTHER = "other"


class AasmState(str, Enum):
    SUBMITTED = "submitted"
    ASSIGNED = "assigned"
    ODIN_DECLINED = "odin_declined"
    OFFERED = "offered"
    RESEARCHER_DECLINED = "researcher_declined"
    ACCEPTED_OFFER = "accepted_offer"
    DISCLOSED = "disclosed"
    PUBLISHED = "published"
    CLOSED = "closed"


class Interface(str, Enum):
    WEB_APP = "web_app"
    WEB_APP_PRIVATE_TEMPORARY = "web_app_private_temporary"
    MOBILE_APP = "mobile_app"
    API = "api"
    LOCAL = "local"
    API_SYSTEM_PROMPT = "api_system_prompt"


class Source(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
