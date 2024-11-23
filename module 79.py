import re
import yaml
import urllib.parse
import numpy as np
from typing import List, Dict, Any
from sklearn.ensemble import IsolationForest

class CustomTestGenerator:
    """Generate custom test cases based on user-defined scenarios."""
    
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.test_patterns = self.config.get('test_patterns', {})
        self.ml_model = self._initialize_ml_model()
    
    def _initialize_ml_model(self):
        """Initialize ML model for intelligent test case generation."""
        return IsolationForest(contamination=0.1, random_state=42)
    
    def generate_test_cases(self, context: Dict[str, Any]) -> List[str]:
        """Generate context-aware test cases."""
        base_cases = self._generate_base_cases(context)
        intelligent_cases = self._apply_ml_augmentation(base_cases)
        return self._combine_and_prioritize(base_cases, intelligent_cases)
    
    def _generate_base_cases(self, context: Dict[str, Any]) -> List[str]:
        """Generate base test cases from patterns."""
        cases = []
        for pattern_type, pattern_config in self.test_patterns.items():
            if self._matches_context(pattern_type, context):
                patterns = pattern_config.get('patterns', [])
                for pattern in patterns:
                    cases.extend(self._apply_pattern_mutations(pattern))
        return cases

    def _matches_context(self, pattern_type: str, context: Dict[str, Any]) -> bool:
        """Check if pattern type matches the current context."""
        return True  # Always true for simplicity; enhance with custom logic if needed

    def _apply_pattern_mutations(self, pattern: str) -> List[str]:
        """Apply various mutations to a pattern to generate more test cases."""
        mutations = []
        mutations.append(pattern)  # Original pattern
        
        # Case mutations
        mutations.append(pattern.upper())
        mutations.append(pattern.lower())
        
        # URL encoding mutations
        mutations.append(urllib.parse.quote(pattern))
        mutations.append(urllib.parse.quote_plus(pattern))
        
        # Basic evasion techniques
        mutations.append(pattern.replace(' ', '+'))
        mutations.append(pattern.replace(' ', '%20'))
        
        # Add some common prefixes/suffixes
        mutations.append(f"1 AND {pattern}")
        mutations.append(f"{pattern} #")
        mutations.append(f"{pattern} --")
        
        return list(set(mutations))  # Remove duplicates

    def _extract_features(self, cases: List[str]) -> np.ndarray:
        """Extract numerical features from test cases for ML analysis."""
        features = []
        for case in cases:
            features.append([
                len(case),  # Length
                case.count("'"),  # Single quotes
                case.count('"'),  # Double quotes
                case.count(' '),  # Spaces
                len(re.findall(r'\d+', case)),  # Numbers
                len(re.findall(r'[<>]', case)),  # Angle brackets
                case.count('('),  # Parentheses
                bool(re.search(r'(SELECT|INSERT|UPDATE|DELETE)', case, re.I)),  # SQL keywords
                bool(re.search(r'(script|alert|eval|onclick)', case, re.I)),  # XSS keywords
                bool(re.search(r'(\.\./|\%2e\%2e/)', case, re.I))  # Path traversal
            ])
        
        return np.array(features) if features else np.empty((0, 10))  # 10 features

    def _apply_ml_augmentation(self, base_cases: List[str]) -> List[str]:
        """Use machine learning to generate additional intelligent cases."""
        if not base_cases:
            print("No base cases available for augmentation.")
            return []

        features = self._extract_features(base_cases)
        if features.size == 0:
            print("No features extracted from base cases.")
            return []

        # Ensure the feature array has the correct shape for IsolationForest
        features = features.reshape(-1, features.shape[1]) if features.ndim == 1 else features

        predictions = self.ml_model.fit_predict(features)

        # Select only cases flagged as anomalies for further testing
        intelligent_cases = [case for case, pred in zip(base_cases, predictions) if pred == -1]
        return intelligent_cases

    def _combine_and_prioritize(self, base_cases: List[str], intelligent_cases: List[str]) -> List[str]:
        """Combine and prioritize test cases based on potential impact."""
        all_cases = base_cases + intelligent_cases
        
        # Remove duplicates while preserving order
        seen = set()
        unique_cases = []
        for case in all_cases:
            if case not in seen:
                seen.add(case)
                unique_cases.append(case)
        
        # Sort cases by potential impact (length and complexity as simple heuristics)
        scored_cases = [(case, self._calculate_impact_score(case)) for case in unique_cases]
        scored_cases.sort(key=lambda x: x[1], reverse=True)
        
        return [case for case, score in scored_cases]

    def _calculate_impact_score(self, case: str) -> float:
        """Calculate potential impact score of a test case."""
        score = 0.0
        
        # Length score (longer cases might be more complex)
        score += len(case) * 0.1
        
        # Presence of important keywords
        sql_keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE']
        xss_keywords = ['script', 'alert', 'eval', 'onload', 'onerror']
        cmd_keywords = ['ping', 'cat', 'ls', 'pwd', 'whoami']
        
        for keyword in sql_keywords + xss_keywords + cmd_keywords:
            if keyword.lower() in case.lower():
                score += 1.0
        
        # Special characters score
        special_chars = ['\'', '"', ';', '<', '>', '|', '&']
        for char in special_chars:
            if char in case:
                score += 0.5
        
        return score

# Usage Example
if __name__ == "__main__":
    # Create a YAML configuration file named `config.yaml` with test patterns.
    context = {"target_url": "skit.ac.in"}
    config_path = "config.yaml"
    
    generator = CustomTestGenerator(config_path)
    test_cases = generator.generate_test_cases(context)
    
    for i, case in enumerate(test_cases, start=1):
        print(f"Test Case {i}: {case}")
