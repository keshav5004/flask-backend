import csv
import os
from urllib.parse import urlparse
from typing import Set

class BaseChecker:
    """
    Base interface for website safety checkers.
    This design makes it easy to extend the system with other validation methods
    such as Machine Learning models, VirusTotal API, or other threat intelligence sources.
    """
    def is_malicious(self, url: str) -> bool:
        """
        Check if a URL is malicious.
        
        Args:
            url (str): The URL/domain to verify.
            
        Returns:
            bool: True if malicious, False if safe.
        """
        raise NotImplementedError("Subclasses must implement the is_malicious method.")


class CSVBlacklistChecker(BaseChecker):
    """
    URL safety checker that compares the normalized domain of a URL
    against a locally stored CSV file containing a list of blacklisted domains.
    """
    def __init__(self, csv_path: str):
        """
        Initialize the checker and load the blacklist from the CSV file.
        
        Args:
            csv_path (str): Absolute or relative path to the CSV file.
        """
        self.csv_path = csv_path
        self.blacklist: Set[str] = set()
        self._load_blacklist()

    def _load_blacklist(self) -> None:
        """
        Loads and parses the CSV blacklist file.
        All loaded URLs are normalized and stored in a memory-efficient set 
        to ensure O(1) constant-time lookup.
        """
        if not os.path.exists(self.csv_path):
            raise FileNotFoundError(f"Blacklist CSV file not found at path: {self.csv_path}")

        try:
            with open(self.csv_path, mode='r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                # Check for the required 'url' column header case-insensitively
                url_col = None
                label_col = None
                for col in reader.fieldnames or []:
                    if col.lower() == 'url':
                        url_col = col
                    elif col.lower() == 'label':
                        label_col = col
                
                if not url_col:
                    raise ValueError("CSV file must contain a 'url' (case-insensitive) column header.")
                
                for row in reader:
                    raw_url = row.get(url_col)
                    if not raw_url:
                        continue
                    
                    # If there's a label column, only load bad/malicious rows
                    if label_col:
                        label = row.get(label_col, '').strip().lower()
                        if label not in ('bad', 'malicious', 'phishing'):
                            continue
                            
                    # Normalize each URL from the CSV before adding to the blacklist
                    normalized = self.normalize_url(raw_url)
                    if normalized:
                        self.blacklist.add(normalized)
        except Exception as e:
            # Re-raise as an IOError for clean catching by the web application layer
            raise IOError(f"Failed to read malicious URLs dataset: {str(e)}")

    @staticmethod
    def normalize_url(url: str) -> str:
        """
        Normalizes a URL by removing scheme, 'www.', ports, paths, and query parameters.
        Example: "https://www.badsite.com:8080/malware?id=1" -> "badsite.com"
        
        Args:
            url (str): The raw input URL.
            
        Returns:
            str: The normalized domain name in lowercase, or empty string if invalid.
        """
        if not url:
            return ""
            
        url = url.strip()
        
        # Ensure we have a scheme prepended so urllib.parse can reliably extract the netloc.
        # If urlparse receives "example.com/path", it parses "example.com" as a path, not netloc.
        if not url.startswith(('http://', 'https://')):
            url_for_parsing = 'http://' + url
        else:
            url_for_parsing = url

        try:
            parsed = urlparse(url_for_parsing)
            # Use netloc if parsed correctly, fall back to path parsing for simple strings
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            # Split off the port if it exists (e.g. "example.com:8080" -> "example.com")
            domain = domain.split(':')[0]
            
            # Remove the 'www.' prefix if it exists
            if domain.lower().startswith('www.'):
                domain = domain[4:]
                
            return domain.lower()
        except Exception:
            # In case of any parsing exception, return the lowercase stripped input
            return url.lower()

    def is_malicious(self, url: str) -> bool:
        """
        Determines whether the given URL is present in the malicious domain blacklist.
        Includes a whitelist bypass for verified popular brand domains to avoid false positives.
        
        Args:
            url (str): The URL to test.
            
        Returns:
            bool: True if the domain is malicious, False otherwise.
        """
        normalized = self.normalize_url(url)
        
        # Whitelist check for trusted popular domains to prevent false positives
        from services.similarity_checker import POPULAR_DOMAINS
        if (normalized in POPULAR_DOMAINS or 
            normalized in ("localhost", "127.0.0.1", "onrender.com", "render.com", "webshield.com") or 
            normalized.endswith((".localhost", ".local", ".onrender.com", ".render.com", ".webshield.com"))):
            return False
            
        return normalized in self.blacklist
