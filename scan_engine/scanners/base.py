from abc import ABC, abstractmethod
from typing import List
from scan_engine.models import Vulnerability

class BaseScanner(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def scan(self, target_path: str) -> List[Vulnerability]:
        """
        Scans the target path and returns a list of normalized Vulnerability objects.
        """
        pass
