"""
Rule-based Scoring Engine Module
Thực hiện scoring dựa trên các rules được định nghĩa trước
"""

import re
import math
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from modules.exceptions import RuleScoringError


@dataclass
class RuleResult:
    """Kết quả của một rule cụ thể"""
    rule_name: str
    triggered: bool
    score_contribution: float
    confidence: float
    evidence: List[str]
    reasoning: str


@dataclass
class RuleBasedScore:
    """Kết quả tổng hợp của rule-based scoring"""
    base_score: float
    rule_breakdown: Dict[str, float]
    triggered_rules: List[str]
    confidence: float
    reasoning: List[str]
    rule_results: List[RuleResult]
    total_rules_evaluated: int
    high_confidence_rules: int


class RuleBasedScoringEngine:
    """Engine để thực hiện rule-based scoring cho AML"""

    def __init__(self, config):
        self.config = config
        self.rules = self._initialize_rules()

    def _initialize_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize tất cả scoring rules"""
        return {
            # === FINANCIAL CRIME RULES ===
            'high_value_transactions': {
                'threshold': 1000000,  # $1M
                'score_impact': 30,
                'category': 'money_laundering',
                'confidence_weight': 0.9,
                'description': 'Large financial transactions indicating potential money laundering'
            },

            'very_high_value_transactions': {
                'threshold': 10000000,  # $10M
                'score_impact': 50,
                'category': 'money_laundering',
                'confidence_weight': 0.95,
                'description': 'Very large transactions with extreme AML risk'
            },

            'structuring_patterns': {
                'patterns': [9999, 9500, 9000, 8000, 7500],
                'score_impact': 25,
                'category': 'structuring',
                'confidence_weight': 0.85,
                'description': 'Transaction amounts suggesting structuring to avoid reporting'
            },

            'round_amounts': {
                'pattern': r'(\$|USD\s*)?(\d+[05])0{3,}',
                'score_impact': 15,
                'category': 'suspicious_pattern',
                'confidence_weight': 0.7,
                'description': 'Round dollar amounts suggesting artificial transactions'
            },

            'rapid_transaction_sequence': {
                'threshold': 5,  # 5+ transactions mentioned
                'score_impact': 20,
                'category': 'velocity',
                'confidence_weight': 0.8,
                'description': 'Multiple transactions in short timeframe'
            },

            # === ENTITY-BASED RULES ===
            'sanctioned_entities': {
                'score_impact': 100,  # Maximum score
                'category': 'sanctions',
                'confidence_weight': 1.0,
                'description': 'Involvement of sanctioned individuals or entities'
            },

            'pep_involvement': {
                'score_impact': 40,
                'category': 'pep',
                'confidence_weight': 0.9,
                'description': 'Politically Exposed Person involvement'
            },

            'criminal_organizations': {
                'patterns': {
                    'mafia': 60,
                    'crime family': 60,
                    'cartel': 70,
                    'terrorist': 90,
                    'gang': 40,
                    'syndicate': 50
                },
                'category': 'criminal_organization',
                'confidence_weight': 0.95,
                'description': 'Known criminal organization involvement'
            },

            'multiple_criminal_entities': {
                'threshold': 2,  # 2+ criminal entities
                'score_impact': 35,
                'category': 'criminal_network',
                'confidence_weight': 0.9,
                'description': 'Multiple criminal entities suggesting organized activity'
            },

            # === GEOGRAPHIC RULES ===
            'high_risk_jurisdictions': {
                'countries': [
                    'afghanistan', 'iran', 'myanmar', 'north korea',
                    'syria', 'venezuela', 'cuba', 'russia'
                ],
                'score_impact': 25,
                'category': 'geographic_risk',
                'confidence_weight': 0.8,
                'description': 'Activity in high-risk jurisdictions'
            },

            'offshore_jurisdictions': {
                'jurisdictions': [
                    'cayman', 'bermuda', 'british virgin', 'panama',
                    'seychelles', 'bahamas', 'malta', 'cyprus'
                ],
                'score_impact': 20,
                'category': 'offshore_risk',
                'confidence_weight': 0.75,
                'description': 'Offshore financial centers involvement'
            },

            # === TEMPORAL RULES ===
            'recent_activity': {
                'days_threshold': 30,
                'score_multiplier': 1.3,
                'category': 'temporal_risk',
                'confidence_weight': 0.85,
                'description': 'Recent suspicious activity increases risk'
            },

            'long_term_operation': {
                'years_threshold': 5,
                'score_impact': 25,
                'category': 'operation_scale',
                'confidence_weight': 0.9,
                'description': 'Long-term criminal operation'
            },

            # === SPECIFIC CRIME TYPES ===
            'money_laundering_keywords': {
                'keywords': [
                    'money laundering', 'laundering money', 'wash money',
                    'clean money', 'dirty money', 'placement', 'layering',
                    'integration', 'smurfing'
                ],
                'score_impact': 45,
                'category': 'money_laundering',
                'confidence_weight': 0.95,
                'description': 'Explicit money laundering activity'
            },

            'fraud_indicators': {
                'keywords': [
                    'fraud', 'fraudulent', 'embezzlement', 'theft',
                    'stolen', 'forged', 'counterfeit', 'fake'
                ],
                'score_impact': 35,
                'category': 'fraud',
                'confidence_weight': 0.9,
                'description': 'Fraud-related criminal activity'
            },

            'racketeering_indicators': {
                'keywords': [
                    'racketeering', 'extortion', 'protection money',
                    'illegal gambling', 'loan sharking', 'rico'
                ],
                'score_impact': 40,
                'category': 'racketeering',
                'confidence_weight': 0.92,
                'description': 'Racketeering and organized crime'
            },

            # === SOURCE QUALITY RULES ===
            'high_credibility_source': {
                'threshold': 0.9,
                'score_multiplier': 1.2,
                'category': 'source_adjustment',
                'confidence_weight': 1.0,
                'description': 'High credibility source increases confidence'
            },

            'low_credibility_source': {
                'threshold': 0.5,
                'score_multiplier': 0.7,
                'category': 'source_adjustment',
                'confidence_weight': 0.6,
                'description': 'Low credibility source reduces score'
            },

            # === VIOLENCE AND THREATS ===
            'violence_threats': {
                'keywords': [
                    'kill', 'murder', 'hurt', 'harm', 'threaten',
                    'violence', 'assault', 'intimidation'
                ],
                'score_impact': 30,
                'category': 'violence',
                'confidence_weight': 0.85,
                'description': 'Violence and threats indicating serious criminal activity'
            }
        }

    def calculate_score(self, processed_data: Dict[str, Any]) -> RuleBasedScore:
        """Calculate rule-based score từ processed NER data"""
        try:
            rule_results = []
            total_score = 0.0
            triggered_rules = []
            reasoning = []
            rule_breakdown = {}

            # Evaluate từng rule
            for rule_name, rule_config in self.rules.items():
                try:
                    result = self._evaluate_rule(rule_name, rule_config, processed_data)
                    rule_results.append(result)

                    if result.triggered:
                        total_score += result.score_contribution
                        triggered_rules.append(rule_name)
                        reasoning.append(result.reasoning)
                        rule_breakdown[rule_name] = result.score_contribution

                except Exception as e:
                    print(f"Error evaluating rule {rule_name}: {e}")
                    continue

            # Apply source credibility adjustment
            total_score = self._apply_source_adjustment(total_score, processed_data)

            # Calculate overall confidence
            overall_confidence = self._calculate_overall_confidence(rule_results, processed_data)

            # Normalize score to 0-100
            final_score = min(100.0, max(0.0, total_score))

            return RuleBasedScore(
                base_score=final_score,
                rule_breakdown=rule_breakdown,
                triggered_rules=triggered_rules,
                confidence=overall_confidence,
                reasoning=reasoning,
                rule_results=rule_results,
                total_rules_evaluated=len(self.rules),
                high_confidence_rules=sum(1 for r in rule_results if r.triggered and r.confidence > 0.8)
            )

        except Exception as e:
            raise RuleScoringError(f"Failed to calculate rule-based score: {str(e)}")

    def _evaluate_rule(self, rule_name: str, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate một rule cụ thể"""

        if rule_name == 'high_value_transactions':
            return self._evaluate_high_value_transactions(rule_config, data)
        elif rule_name == 'very_high_value_transactions':
            return self._evaluate_very_high_value_transactions(rule_config, data)
        elif rule_name == 'structuring_patterns':
            return self._evaluate_structuring_patterns(rule_config, data)
        elif rule_name == 'round_amounts':
            return self._evaluate_round_amounts(rule_config, data)
        elif rule_name == 'sanctioned_entities':
            return self._evaluate_sanctioned_entities(rule_config, data)
        elif rule_name == 'pep_involvement':
            return self._evaluate_pep_involvement(rule_config, data)
        elif rule_name == 'criminal_organizations':
            return self._evaluate_criminal_organizations(rule_config, data)
        elif rule_name == 'multiple_criminal_entities':
            return self._evaluate_multiple_criminal_entities(rule_config, data)
        elif rule_name == 'money_laundering_keywords':
            return self._evaluate_keyword_rule(rule_config, data, 'custom_entities')
        elif rule_name == 'fraud_indicators':
            return self._evaluate_fraud_indicators(rule_config, data)
        elif rule_name == 'racketeering_indicators':
            return self._evaluate_racketeering_indicators(rule_config, data)
        elif rule_name == 'violence_threats':
            return self._evaluate_violence_threats(rule_config, data)
        elif rule_name == 'recent_activity':
            return self._evaluate_recent_activity(rule_config, data)
        elif rule_name == 'long_term_operation':
            return self._evaluate_long_term_operation(rule_config, data)
        elif rule_name == 'high_risk_jurisdictions':
            return self._evaluate_geographic_risk(rule_config, data, 'high_risk')
        elif rule_name == 'offshore_jurisdictions':
            return self._evaluate_geographic_risk(rule_config, data, 'offshore')
        else:
            return RuleResult(rule_name, False, 0.0, 0.0, [], f"Rule {rule_name} not implemented")

    def _evaluate_high_value_transactions(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate high value transaction rule"""
        threshold = rule_config['threshold']
        score_impact = rule_config['score_impact']
        confidence = rule_config['confidence_weight']

        evidence = []
        triggered = False
        total_impact = 0.0

        for amount_info in data.get('financial_amounts', []):
            value = amount_info.get('normalized_value', 0)
            if value >= threshold:
                triggered = True
                # Scale impact based on amount
                multiplier = min(3.0, value / threshold)
                impact = score_impact * multiplier
                total_impact += impact
                evidence.append(f"High value transaction: ${value:,.2f}")

        reasoning = f"Detected {len(evidence)} high-value transactions above ${threshold:,}" if evidence else "No high-value transactions detected"

        return RuleResult(
            rule_name='high_value_transactions',
            triggered=triggered,
            score_contribution=min(score_impact * 2, total_impact),  # Cap at 2x base impact
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _evaluate_very_high_value_transactions(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate very high value transactions (>$10M)"""
        threshold = rule_config['threshold']
        score_impact = rule_config['score_impact']
        confidence = rule_config['confidence_weight']

        evidence = []
        triggered = False

        for amount_info in data.get('financial_amounts', []):
            value = amount_info.get('normalized_value', 0)
            if value >= threshold:
                triggered = True
                evidence.append(f"Very high value transaction: ${value:,.2f}")

        reasoning = f"Detected {len(evidence)} very high-value transactions above ${threshold:,}" if evidence else ""

        return RuleResult(
            rule_name='very_high_value_transactions',
            triggered=triggered,
            score_contribution=score_impact if triggered else 0.0,
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _evaluate_structuring_patterns(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate structuring patterns"""
        patterns = rule_config['patterns']
        score_impact = rule_config['score_impact']
        confidence = rule_config['confidence_weight']

        evidence = []
        triggered = False

        for amount_info in data.get('financial_amounts', []):
            value = amount_info.get('normalized_value', 0)
            if any(abs(value - pattern) < 100 for pattern in patterns):
                triggered = True
                evidence.append(f"Potential structuring amount: ${value:,.2f}")

        reasoning = f"Detected {len(evidence)} potential structuring amounts" if evidence else ""

        return RuleResult(
            rule_name='structuring_patterns',
            triggered=triggered,
            score_contribution=score_impact if triggered else 0.0,
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _evaluate_sanctioned_entities(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate sanctioned entities"""
        score_impact = rule_config['score_impact']
        confidence = rule_config['confidence_weight']

        evidence = []
        triggered = False

        for entity in data.get('enriched_entities', data.get('aws_entities', [])):
            risk_indicators = entity.get('risk_indicators', [])
            if 'SANCTIONED' in risk_indicators:
                triggered = True
                evidence.append(f"Sanctioned entity: {entity.get('text', 'Unknown')}")

        reasoning = f"Detected {len(evidence)} sanctioned entities" if evidence else ""

        return RuleResult(
            rule_name='sanctioned_entities',
            triggered=triggered,
            score_contribution=score_impact if triggered else 0.0,
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _evaluate_pep_involvement(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate PEP involvement"""
        score_impact = rule_config['score_impact']
        confidence = rule_config['confidence_weight']

        evidence = []
        triggered = False

        for entity in data.get('enriched_entities', data.get('aws_entities', [])):
            risk_indicators = entity.get('risk_indicators', [])
            if 'LEGAL_OFFICIAL' in risk_indicators or entity.get('aml_category') == 'PEP':
                triggered = True
                evidence.append(f"PEP involvement: {entity.get('text', 'Unknown')}")

        reasoning = f"Detected {len(evidence)} PEP involvements" if evidence else ""

        return RuleResult(
            rule_name='pep_involvement',
            triggered=triggered,
            score_contribution=score_impact if triggered else 0.0,
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _evaluate_criminal_organizations(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate criminal organization involvement"""
        patterns = rule_config['patterns']
        confidence = rule_config['confidence_weight']

        evidence = []
        total_score = 0.0
        triggered = False

        # Check trong criminal_organizations
        for org in data.get('criminal_organizations', []):
            org_text = org.get('text', '').lower()
            for pattern, score in patterns.items():
                if pattern in org_text:
                    triggered = True
                    total_score += score
                    evidence.append(f"Criminal organization: {org.get('text', 'Unknown')} ({pattern})")

        # Also check in regular entities
        for entity in data.get('enriched_entities', data.get('aws_entities', [])):
            if 'CRIMINAL_ORGANIZATION' in entity.get('risk_indicators', []):
                triggered = True
                total_score += 50  # Default score
                evidence.append(f"Criminal entity: {entity.get('text', 'Unknown')}")

        reasoning = f"Detected {len(evidence)} criminal organizations" if evidence else ""

        return RuleResult(
            rule_name='criminal_organizations',
            triggered=triggered,
            score_contribution=min(80.0, total_score),  # Cap at 80
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _evaluate_multiple_criminal_entities(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate multiple criminal entities suggesting network"""
        threshold = rule_config['threshold']
        score_impact = rule_config['score_impact']
        confidence = rule_config['confidence_weight']

        criminal_count = len(data.get('criminal_organizations', []))

        # Also count entities with criminal indicators
        for entity in data.get('enriched_entities', data.get('aws_entities', [])):
            if 'CRIMINAL_ORGANIZATION' in entity.get('risk_indicators', []):
                criminal_count += 1

        triggered = criminal_count >= threshold
        evidence = [f"Multiple criminal entities detected: {criminal_count}"] if triggered else []
        reasoning = f"Found {criminal_count} criminal entities" if triggered else ""

        return RuleResult(
            rule_name='multiple_criminal_entities',
            triggered=triggered,
            score_contribution=score_impact if triggered else 0.0,
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _evaluate_keyword_rule(self, rule_config: Dict[str, Any], data: Dict[str, Any], data_key: str) -> RuleResult:
        """Generic keyword evaluation"""
        keywords = rule_config.get('keywords', [])
        score_impact = rule_config['score_impact']
        confidence = rule_config['confidence_weight']

        evidence = []
        triggered = False

        # Check trong custom entities
        for entity in data.get(data_key, []):
            entity_text = entity.get('text', '').lower()
            if any(keyword in entity_text for keyword in keywords):
                triggered = True
                evidence.append(f"Keyword match: {entity.get('text', 'Unknown')}")

        reasoning = f"Detected {len(evidence)} keyword matches" if evidence else ""

        return RuleResult(
            rule_name=rule_config.get('category', 'keyword_rule'),
            triggered=triggered,
            score_contribution=score_impact if triggered else 0.0,
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _evaluate_fraud_indicators(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate fraud indicators"""
        return self._evaluate_keyword_rule(rule_config, data, 'custom_entities')

    def _evaluate_racketeering_indicators(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate racketeering indicators"""
        return self._evaluate_keyword_rule(rule_config, data, 'custom_entities')

    def _evaluate_violence_threats(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate violence and threats"""
        keywords = rule_config['keywords']
        score_impact = rule_config['score_impact']
        confidence = rule_config['confidence_weight']

        evidence = []
        triggered = False

        # Check trong tất cả text contexts
        all_texts = []

        # Collect contexts from các entities
        for entity in data.get('aws_entities', []):
            if 'context' in entity:
                all_texts.append(entity['context'].lower())

        for org in data.get('criminal_organizations', []):
            if 'context' in org:
                all_texts.append(org['context'].lower())

        # Check for violence keywords
        for text in all_texts:
            for keyword in keywords:
                if keyword in text:
                    triggered = True
                    evidence.append(f"Violence indicator: '{keyword}' found in context")
                    break

        reasoning = f"Detected {len(evidence)} violence/threat indicators" if evidence else ""

        return RuleResult(
            rule_name='violence_threats',
            triggered=triggered,
            score_contribution=score_impact if triggered else 0.0,
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _evaluate_recent_activity(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate recent activity temporal risk"""
        days_threshold = rule_config['days_threshold']
        score_multiplier = rule_config['score_multiplier']
        confidence = rule_config['confidence_weight']

        evidence = []
        triggered = False

        # Check time references for recency
        for time_ref in data.get('time_references', []):
            recency_score = time_ref.get('recency_score', 0)
            if recency_score > 0.8:  # High recency
                triggered = True
                evidence.append(f"Recent activity: {time_ref.get('text', 'Unknown')}")

        reasoning = f"Detected {len(evidence)} recent activity indicators" if evidence else ""

        # This rule modifies other scores rather than adding its own
        return RuleResult(
            rule_name='recent_activity',
            triggered=triggered,
            score_contribution=0.0,  # Multiplier effect, not additive
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _evaluate_long_term_operation(self, rule_config: Dict[str, Any], data: Dict[str, Any]) -> RuleResult:
        """Evaluate long-term operation indicators"""
        years_threshold = rule_config['years_threshold']
        score_impact = rule_config['score_impact']
        confidence = rule_config['confidence_weight']

        evidence = []
        triggered = False

        # Check for long-term indicators in time references
        for time_ref in data.get('time_references', []):
            text = time_ref.get('text', '').lower()
            # Look for patterns like "25 years", "over 20 years", etc.
            import re
            year_pattern = r'(\d+)\s*years?'
            matches = re.findall(year_pattern, text)

            for match in matches:
                years = int(match)
                if years >= years_threshold:
                    triggered = True
                    evidence.append(f"Long-term operation: {years} years mentioned")

        reasoning = f"Detected {len(evidence)} long-term operation indicators" if evidence else ""

        return RuleResult(
            rule_name='long_term_operation',
            triggered=triggered,
            score_contribution=score_impact if triggered else 0.0,
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _evaluate_geographic_risk(self, rule_config: Dict[str, Any], data: Dict[str, Any],
                                  risk_type: str) -> RuleResult:
        """Evaluate geographic risk (high-risk countries or offshore jurisdictions)"""
        if risk_type == 'high_risk':
            jurisdictions = rule_config['countries']
            rule_name = 'high_risk_jurisdictions'
        else:
            jurisdictions = rule_config['jurisdictions']
            rule_name = 'offshore_jurisdictions'

        score_impact = rule_config['score_impact']
        confidence = rule_config['confidence_weight']

        evidence = []
        triggered = False

        # Check location entities
        for entity in data.get('aws_entities', []):
            if entity.get('type') == 'LOCATION':
                location_text = entity.get('text', '').lower()
                for jurisdiction in jurisdictions:
                    if jurisdiction in location_text:
                        triggered = True
                        evidence.append(f"Geographic risk: {entity.get('text', 'Unknown')}")
                        break

        reasoning = f"Detected {len(evidence)} geographic risk indicators" if evidence else ""

        return RuleResult(
            rule_name=rule_name,
            triggered=triggered,
            score_contribution=score_impact if triggered else 0.0,
            confidence=confidence if triggered else 1.0,
            evidence=evidence,
            reasoning=reasoning
        )

    def _apply_source_adjustment(self, base_score: float, data: Dict[str, Any]) -> float:
        """Apply source credibility adjustments"""
        source_info = data.get('s3_metadata', {})
        source_credibility = data.get('source_credibility', 0.8)  # Default credibility

        # Adjust based on source credibility
        if source_credibility > 0.9:
            # High credibility source - boost score slightly
            adjusted_score = base_score * 1.1
        elif source_credibility < 0.5:
            # Low credibility source - reduce score
            adjusted_score = base_score * 0.7
        else:
            # Medium credibility - no adjustment
            adjusted_score = base_score

        return adjusted_score

    def _calculate_overall_confidence(self, rule_results: List[RuleResult], data: Dict[str, Any]) -> float:
        """Calculate overall confidence in the rule-based assessment"""
        if not rule_results:
            return 0.5

        triggered_results = [r for r in rule_results if r.triggered]

        if not triggered_results:
            return 0.8  # High confidence in "no risk" assessment if no rules triggered

        # Calculate weighted average confidence
        total_weight = 0.0
        weighted_confidence = 0.0

        for result in triggered_results:
            weight = result.score_contribution
            total_weight += weight
            weighted_confidence += result.confidence * weight

        base_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.5

        # Adjust based on data quality
        data_quality = data.get('data_quality_score', 70) / 100.0
        quality_adjusted_confidence = base_confidence * (0.5 + 0.5 * data_quality)

        # Adjust based on number of triggered rules (more rules = higher confidence)
        rule_count_factor = min(1.0, len(triggered_results) / 5.0)  # Max factor at 5+ rules
        confidence_boost = 0.1 * rule_count_factor

        final_confidence = min(1.0, quality_adjusted_confidence + confidence_boost)

        return final_confidence

    def get_rule_summary(self, rule_result: RuleBasedScore) -> Dict[str, Any]:
        """Get a summary of rule evaluation results"""
        return {
            'total_score': rule_result.base_score,
            'total_rules_evaluated': rule_result.total_rules_evaluated,
            'rules_triggered': len(rule_result.triggered_rules),
            'high_confidence_rules': rule_result.high_confidence_rules,
            'overall_confidence': rule_result.confidence,
            'top_contributing_rules': sorted(
                rule_result.rule_breakdown.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5],
            'risk_categories': self._categorize_triggered_rules(rule_result.triggered_rules)
        }

    def _categorize_triggered_rules(self, triggered_rules: List[str]) -> Dict[str, int]:
        """Categorize triggered rules by risk type"""
        categories = {}

        for rule_name in triggered_rules:
            if rule_name in self.rules:
                category = self.rules[rule_name].get('category', 'other')
                categories[category] = categories.get(category, 0) + 1

        return categories

    def explain_score(self, rule_result: RuleBasedScore) -> str:
        """Generate human-readable explanation of the score"""
        if rule_result.base_score == 0:
            return "No significant risk indicators detected through rule-based analysis."

        explanation_parts = [
            f"Rule-based analysis resulted in a score of {rule_result.base_score:.1f}/100.",
            f"This assessment is based on {len(rule_result.triggered_rules)} triggered rules out of {rule_result.total_rules_evaluated} evaluated.",
            f"Confidence level: {rule_result.confidence:.2f}"
        ]

        if rule_result.rule_breakdown:
            top_rules = sorted(rule_result.rule_breakdown.items(), key=lambda x: x[1], reverse=True)[:3]
            explanation_parts.append("Top contributing factors:")
            for rule_name, score in top_rules:
                rule_desc = self.rules.get(rule_name, {}).get('description', rule_name)
                explanation_parts.append(f"- {rule_desc}: +{score:.1f} points")

        return " ".join(explanation_parts)

    def validate_rules(self) -> Dict[str, Any]:
        """Validate rule configuration for consistency"""
        validation_results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'rule_count': len(self.rules)
        }

        for rule_name, rule_config in self.rules.items():
            # Check required fields
            if 'score_impact' not in rule_config:
                validation_results['errors'].append(f"Rule {rule_name} missing score_impact")
                validation_results['valid'] = False

            if 'confidence_weight' not in rule_config:
                validation_results['warnings'].append(f"Rule {rule_name} missing confidence_weight")

            # Check score impact range
            score_impact = rule_config.get('score_impact', 0)
            if score_impact < 0 or score_impact > 100:
                validation_results['warnings'].append(f"Rule {rule_name} has unusual score_impact: {score_impact}")

        return validation_results