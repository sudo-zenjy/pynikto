# New file: statistics.py
from dataclasses import dataclass, field
from typing import Dict

@dataclass
class ScanStatistics:
    """Track scan statistics like original Nikto"""
    items_tested: int = 0
    items_found: int = 0
    errors: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    info: int = 0
    
    def increment_tested(self, count: int = 1):
        self.items_tested += count
    
    def increment_found(self):
        self.items_found += 1
    
    def increment_error(self):
        self.errors += 1
    
    def add_finding(self, risk: str):
        self.increment_found()
        if risk == "high":
            self.high_risk += 1
        elif risk == "medium":
            self.medium_risk += 1
        else:
            self.info += 1
    
    def to_dict(self) -> Dict:
        return {
            "items_tested": self.items_tested,
            "items_found": self.items_found,
            "errors": self.errors,
            "high_risk": self.high_risk,
            "medium_risk": self.medium_risk,
            "info": self.info,
        }
