from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from .enums import Interface, SecurityBoundary, Severity
from .taxonomy import TaxonomyTriplet


class DetectionSignature(BaseModel):
    version: str
    signature: str


class Vendor(BaseModel):
    name: str


class ThreatFeedModel(BaseModel):
    id: int
    name: str
    vendor: Vendor


class ThreatFeedMessage(BaseModel):
    prompt: str
    response: str
    model_id: int | None = None
    interface: Interface | None = None


class TestType(BaseModel):
    id: int
    name: str


class TestResult(BaseModel):
    result: float
    temperature: float
    model_id: int | None = None
    test_type: TestType


class Metadatum(BaseModel):
    type: str
    result: Any


class ReferenceUrl(BaseModel):
    id: int
    url: str


class VariantPromptEntry(BaseModel):
    key_changes: str | None = None
    rationale: str | None = None
    industry_id: int | None = None
    prompt: str | None = None


class SubIndustry(BaseModel):
    subindustry: str
    industry_id: int
    prompts: list[VariantPromptEntry] = []


class IndustryVariant(BaseModel):
    industry: str | None = None
    subindustries: list[SubIndustry] = []


class ThreatFeed(BaseModel):
    uuid: str
    title: str
    summary: str | None = None
    detail: str | None = None
    severity: Severity
    security_boundary: SecurityBoundary
    source: str | None = None
    disclosed_at: datetime | None = None
    published_at: datetime | None = None
    updated_at: datetime | None = None
    detection_signatures: list[DetectionSignature] = []
    models: list[ThreatFeedModel] = []
    messages: list[ThreatFeedMessage] = []
    taxonomies: list[TaxonomyTriplet] = []
    test_results: list[TestResult] = []
    metadata: list[Metadatum] = []
    reference_urls: list[ReferenceUrl] = []
    variant_prompts: list[IndustryVariant] = []


class InstructionTuningEntry(BaseModel):
    instruction: str
    input: str
    output: str
