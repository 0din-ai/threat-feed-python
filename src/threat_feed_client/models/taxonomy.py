from pydantic import BaseModel


class TaxonomyTriplet(BaseModel):
    category: str
    strategy: str
    technique: str


class TaxonomyTripletWithId(BaseModel):
    id: int
    category: str
    strategy: str
    technique: str
