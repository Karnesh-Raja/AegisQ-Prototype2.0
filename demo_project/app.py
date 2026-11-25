"""Synthetic MediVault demo shell. It contains no real patient records."""

def get_synthetic_record(record_id: str):
    return {"id": record_id, "patient": "SYNTHETIC PATIENT", "note": "Demo only"}
