"""
Score Reconciler Module
Kết hợp rule-based và Bedrock scores để tạo final assessment
"""

import math
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from modules.exceptions import ReconciliationError


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class FinalRiskAssessment:
    """Final risk assessment sau khi reconcile"""
    final_score: float
    risk_level: RiskLevel
    confidence_level: ConfidenceLevel
    rule_based_component: Dict[str, Any]
    ai_enhanced_component: Dict[str, Any]
    reconciliation_explanation: str
    recommended_actions: List[str]
    requires_manual_review: bool
    score_discord: float
    weighting_strategy: str
    case_metadata: Dict[str, Any]


class ScoreReconciler:
    """Reconcile rule-based và Bedrock scores"""

    def __init__(self, config):
        self.config = config

        # Default weights
        self.rule_weight = config.get('rule_based_weight', 0.6)
        self.ai_weight = config.get('ai_enhanced_weight', 0.4)

        # Thresholds
        self.discord_threshold = config.get('score_discord_threshold', 15.0)
        self.confidence_threshold = config.get('high_confidence_threshold', 0.8)

        # Risk level thresholds
        self.critical_threshold = config.get('critical_risk_threshold', 80.0)
        self.high_threshold = config.get('high_risk_threshold', 60.0)
        self.medium_threshold = config.get('medium_risk_threshold', 30.0)

    def reconcile_scores(self, rule_result, bedrock_result, ner_data: Dict[str, Any]) -> FinalRiskAssessment:
        """Main reconciliation function"""
        try:
            # 1. Determine case characteristics
            case_characteristics = self._analyze_case_characteristics(ner_data)

            # 2. Adjust weights based on case type và confidence
            adjusted_weights = self._calculate_dynamic_weights(
                rule_result, bedrock_result, case_characteristics
            )

            # 3. Calculate weighted score
            final_score = self._calculate_weighted_score(
                rule_result, bedrock_result, adjusted_weights
            )

            # 4. Calculate score discord
            score_discord = abs(rule_result.base_score - bedrock_result.contextual_score)

            # 5. Determine risk và confidence levels
            risk_level = self._determine_risk_level(final_score, case_characteristics)
            confidence_level = self._determine_confidence_level(
                rule_result, bedrock_result, score_discord, case_characteristics
            )

            # 6. Determine if manual review needed
            requires_manual_review = self._requires_manual_review(
                final_score, score_discord, confidence_level, case_characteristics
            )

            # 7. Generate reconciliation explanation
            explanation = self._generate_reconciliation_explanation(
                rule_result, bedrock_result, final_score, score_discord, adjusted_weights
            )

            # 8. Combine recommended actions
            combined_actions = self._combine_recommended_actions(
                rule_result, bedrock_result, risk_level, requires_manual_review
            )

            # 9. Create case metadata
            case_metadata = self._create_case_metadata(
                ner_data, case_characteristics, adjusted_weights
            )

            return FinalRiskAssessment(
                final_score=round(final_score, 2),
                risk_level=risk_level,
                confidence_level=confidence_level,
                rule_based_component=self._serialize_rule_component(rule_result),
                ai_enhanced_component=self._serialize_ai_component(bedrock_result),
                reconciliation_explanation=explanation,
                recommended_actions=combined_actions,
                requires_manual_review=requires_manual_review,
                score_discord=round(score_discord, 2),
                weighting_strategy=adjusted_weights['strategy'],
                case_metadata=case_metadata
            )

        except Exception as e:
            raise ReconciliationError(f"Failed to reconcile scores: {str(e)}")

    def _analyze_case_characteristics(self, ner_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze case characteristics để adjust scoring approach"""
        characteristics = {
            'complexity': 'MEDIUM',
            'data_quality': ner_data.get('data_quality_score', 70) / 100.0,
            'entity_count': len(ner_data.get('enriched_entities', [])),
            'financial_amounts_count': len(ner_data.get('financial_amounts', [])),
            'criminal_orgs_count': len(ner_data.get('criminal_organizations', [])),
            'case_type': 'GENERAL'
        }

        # Determine complexity
        complexity_score = 0
        complexity_score += min(10, characteristics['entity_count'])
        complexity_score += min(10, characteristics['financial_amounts_count'] * 2)
        complexity_score += min(10, characteristics['criminal_orgs_count'] * 3)

        if complexity_score >= 20:
            characteristics['complexity'] = 'HIGH'
        elif complexity_score <= 10:
            characteristics['complexity'] = 'LOW'

        # Determine case type
        case_type = self._determine_case_type(ner_data)
        characteristics['case_type'] = case_type

        # Assess urgency
        characteristics['urgency'] = self._assess_case_urgency(ner_data)

        return characteristics

    def _determine_case_type(self, ner_data: Dict[str, Any]) -> str:
        """Determine the primary case type"""
        # Check custom entities for crime types
        custom_entities = ner_data.get('custom_entities', [])

        crime_categories = {}
        for entity in custom_entities:
            category = entity.get('category', 'general')
            crime_categories[category] = crime_categories.get(category, 0) + 1

        # Check for sanctions
        sanctioned_entities = [e for e in ner_data.get('enriched_entities', [])
                               if 'SANCTIONED' in e.get('risk_indicators', [])]
        if sanctioned_entities:
            return 'SANCTIONS'

        # Check for criminal organizations
        if ner_data.get('criminal_organizations'):
            return 'ORGANIZED_CRIME'

        # Check dominant crime category
        if crime_categories:
            dominant_category = max(crime_categories.items(), key=lambda x: x[1])[0]
            category_mapping = {
                'general_ml': 'MONEY_LAUNDERING',
                'racketeering': 'RACKETEERING',
                'other_crimes': 'FRAUD'
            }
            return category_mapping.get(dominant_category, 'GENERAL')

        return 'GENERAL'

    def _assess_case_urgency(self, ner_data: Dict[str, Any]) -> str:
        """Assess case urgency based on temporal factors"""
        time_refs = ner_data.get('time_references', [])

        for time_ref in time_refs:
            recency_score = time_ref.get('recency_score', 0)
            if recency_score > 0.8:
                return 'HIGH'

        # Check for violence indicators
        for entity in ner_data.get('enriched_entities', []):
            if any('violence' in indicator.lower() for indicator in entity.get('risk_indicators', [])):
                return 'HIGH'

        return 'MEDIUM'

    def _calculate_dynamic_weights(self, rule_result, bedrock_result, characteristics: Dict[str, Any]) -> Dict[
        str, Any]:
        """Calculate dynamic weights based on case characteristics"""
        base_rule_weight = self.rule_weight
        base_ai_weight = self.ai_weight

        # Adjust based on case type
        case_type = characteristics['case_type']
        type_adjustments = {
            'SANCTIONS': {'rule_boost': 0.2, 'reason': 'Sanctions require strict rule compliance'},
            'ORGANIZED_CRIME': {'ai_boost': 0.1, 'reason': 'Complex relationships need AI analysis'},
            'MONEY_LAUNDERING': {'balanced': True, 'reason': 'Balanced approach for ML detection'},
            'FRAUD': {'ai_boost': 0.15, 'reason': 'Fraud patterns benefit from AI analysis'}
        }

        adjustment = type_adjustments.get(case_type, {})
        strategy = 'BALANCED'

        if 'rule_boost' in adjustment:
            base_rule_weight = min(0.8, base_rule_weight + adjustment['rule_boost'])
            base_ai_weight = 1.0 - base_rule_weight
            strategy = 'RULE_FOCUSED'
        elif 'ai_boost' in adjustment:
            base_ai_weight = min(0.6, base_ai_weight + adjustment['ai_boost'])
            base_rule_weight = 1.0 - base_ai_weight
            strategy = 'AI_ENHANCED'

        # Adjust based on confidence levels
        rule_confidence = rule_result.confidence
        ai_confidence = 1.0 + bedrock_result.confidence_adjustment

        confidence_factor = 0.1
        if rule_confidence > ai_confidence + 0.2:
            base_rule_weight += confidence_factor
            base_ai_weight -= confidence_factor
            strategy += '_RULE_CONFIDENT'
        elif ai_confidence > rule_confidence + 0.2:
            base_ai_weight += confidence_factor
            base_rule_weight -= confidence_factor
            strategy += '_AI_CONFIDENT'

        # Adjust based on data quality
        data_quality = characteristics['data_quality']
        if data_quality < 0.6:
            # Low data quality - rely more on rules
            base_rule_weight += 0.1
            base_ai_weight -= 0.1
            strategy += '_LOW_QUALITY'

        # Normalize weights
        total_weight = base_rule_weight + base_ai_weight
        final_rule_weight = base_rule_weight / total_weight
        final_ai_weight = base_ai_weight / total_weight

        return {
            'rule_weight': final_rule_weight,
            'ai_weight': final_ai_weight,
            'strategy': strategy,
            'adjustments': adjustment,
            'case_type': case_type,
            'confidence_based_adjustment': abs(rule_confidence - ai_confidence) > 0.2
        }

    def _calculate_weighted_score(self, rule_result, bedrock_result, weights: Dict[str, Any]) -> float:
        """Calculate weighted final score"""
        rule_score = rule_result.base_score
        ai_score = bedrock_result.contextual_score

        rule_weight = weights['rule_weight']
        ai_weight = weights['ai_weight']

        # Basic weighted average
        weighted_score = (rule_score * rule_weight) + (ai_score * ai_weight)

        # Apply confidence adjustments
        confidence_adjustment = bedrock_result.confidence_adjustment
        adjusted_score = weighted_score * (1.0 + confidence_adjustment)

        # Ensure score is within bounds
        final_score = max(0.0, min(100.0, adjusted_score))

        return final_score

    def _determine_risk_level(self, score: float, characteristics: Dict[str, Any]) -> RiskLevel:
        """Determine risk level with context-aware thresholds"""
        # Base thresholds
        critical_threshold = self.critical_threshold
        high_threshold = self.high_threshold
        medium_threshold = self.medium_threshold

        # Adjust thresholds based on case characteristics
        case_type = characteristics['case_type']
        urgency = characteristics['urgency']

        # Lower thresholds for high-urgency cases
        if urgency == 'HIGH':
            critical_threshold -= 5
            high_threshold -= 5
            medium_threshold -= 5

        # Adjust for specific case types
        if case_type == 'SANCTIONS':
            # Sanctions are always serious
            if score >= 50:
                return RiskLevel.CRITICAL
        elif case_type == 'ORGANIZED_CRIME':
            # Organized crime gets elevated risk
            critical_threshold -= 10
            high_threshold -= 10

        # Apply thresholds
        if score >= critical_threshold:
            return RiskLevel.CRITICAL
        elif score >= high_threshold:
            return RiskLevel.HIGH
        elif score >= medium_threshold:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _determine_confidence_level(self, rule_result, bedrock_result, discord: float,
                                    characteristics: Dict[str, Any]) -> ConfidenceLevel:
        """Determine overall confidence level"""
        rule_confidence = rule_result.confidence
        ai_confidence = 1.0 + bedrock_result.confidence_adjustment
        data_quality = characteristics['data_quality']

        # Calculate base confidence
        base_confidence = (rule_confidence + ai_confidence) / 2.0

        # Adjust for score discord
        if discord > 20:
            base_confidence *= 0.7
        elif discord > 10:
            base_confidence *= 0.85

        # Adjust for data quality
        quality_adjusted = base_confidence * (0.5 + 0.5 * data_quality)

        # Determine level
        if quality_adjusted >= 0.8:
            return ConfidenceLevel.HIGH
        elif quality_adjusted >= 0.6:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW

    def _requires_manual_review(self, final_score: float, discord: float,
                                confidence: ConfidenceLevel, characteristics: Dict[str, Any]) -> bool:
        """Determine if manual review is required"""

        # Always review if high discord
        if discord > self.discord_threshold:
            return True

        # Review high-risk cases with low confidence
        if final_score >= self.high_threshold and confidence == ConfidenceLevel.LOW:
            return True

        # Review critical cases with medium confidence
        if final_score >= self.critical_threshold and confidence == ConfidenceLevel.MEDIUM:
            return True

        # Review based on case characteristics
        case_type = characteristics['case_type']
        urgency = characteristics['urgency']

        if case_type == 'SANCTIONS' and final_score >= 30:
            return True

        if urgency == 'HIGH' and final_score >= 50:
            return True

        # Review if data quality is very low
        if characteristics['data_quality'] < 0.5 and final_score >= 40:
            return True

        return False

    def _generate_reconciliation_explanation(self, rule_result, bedrock_result,
                                             final_score: float, discord: float,
                                             weights: Dict[str, Any]) -> str:
        """Generate detailed reconciliation explanation"""

        explanation_parts = [
            f"HYBRID RISK ASSESSMENT SUMMARY",
            f"Final Score: {final_score:.1f}/100",
            f"Weighting Strategy: {weights['strategy']}",
            f"",
            f"COMPONENT SCORES:",
            f"• Rule-based Assessment: {rule_result.base_score:.1f}/100 (Weight: {weights['rule_weight']:.1%})",
            f"  - Triggered Rules: {len(rule_result.triggered_rules)}",
            f"  - Confidence: {rule_result.confidence:.2f}",
            f"• AI-Enhanced Assessment: {bedrock_result.contextual_score:.1f}/100 (Weight: {weights['ai_weight']:.1%})",
            f"  - Confidence Adjustment: {bedrock_result.confidence_adjustment:+.2f}",
            f"  - Risk Indicators: {len(bedrock_result.risk_indicators)}",
            f"",
            f"RECONCILIATION ANALYSIS:",
            f"• Score Discord: {discord:.1f} points ({'ALIGNED' if discord < 10 else 'DIVERGENT' if discord < 20 else 'SIGNIFICANT DIVERGENCE'})",
            f"• Case Type: {weights['case_type']}",
        ]

        # Add rule details
        if rule_result.triggered_rules:
            explanation_parts.extend([
                f"",
                f"TOP RULE CONTRIBUTIONS:",
            ])
            top_rules = sorted(rule_result.rule_breakdown.items(), key=lambda x: x[1], reverse=True)[:3]
            for rule_name, score in top_rules:
                explanation_parts.append(f"• {rule_name}: +{score:.1f} points")

        # Add AI insights
        if bedrock_result.narrative_explanation:
            explanation_parts.extend([
                f"",
                f"AI CONTEXTUAL ANALYSIS:",
                bedrock_result.narrative_explanation[:200] + "..." if len(
                    bedrock_result.narrative_explanation) > 200 else bedrock_result.narrative_explanation
            ])

        return "\n".join(explanation_parts)

    def _combine_recommended_actions(self, rule_result, bedrock_result,
                                     risk_level: RiskLevel, requires_manual_review: bool) -> List[str]:
        """Combine and prioritize recommended actions"""
        actions = []

        # Start with AI recommendations
        actions.extend(bedrock_result.recommended_actions)

        # Add rule-based reasoning as actions
        for reasoning in rule_result.reasoning:
            actions.append(f"Investigate: {reasoning}")

        # Add risk-level specific actions
        if risk_level == RiskLevel.CRITICAL:
            actions.insert(0, "IMMEDIATE: Escalate to senior compliance officer")
            actions.insert(1, "URGENT: Freeze relevant accounts pending investigation")
        elif risk_level == RiskLevel.HIGH:
            actions.insert(0, "HIGH PRIORITY: Schedule enhanced due diligence within 24 hours")

        # Add manual review requirement
        if requires_manual_review:
            actions.insert(0, "MANUAL REVIEW REQUIRED: Analyst must validate automated assessment")

        # Remove duplicates while preserving order
        seen = set()
        unique_actions = []
        for action in actions:
            if action not in seen:
                unique_actions.append(action)
                seen.add(action)

        return unique_actions[:10]  # Limit to top 10 actions

    def _serialize_rule_component(self, rule_result) -> Dict[str, Any]:
        """Serialize rule component for storage"""
        return {
            'base_score': rule_result.base_score,
            'confidence': rule_result.confidence,
            'triggered_rules': rule_result.triggered_rules,
            'rule_breakdown': rule_result.rule_breakdown,
            'reasoning': rule_result.reasoning,
            'total_rules_evaluated': rule_result.total_rules_evaluated,
            'high_confidence_rules': rule_result.high_confidence_rules
        }

    def _serialize_ai_component(self, bedrock_result) -> Dict[str, Any]:
        """Serialize AI component for storage"""
        return {
            'contextual_score': bedrock_result.contextual_score,
            'confidence_adjustment': bedrock_result.confidence_adjustment,
            'risk_indicators': bedrock_result.risk_indicators,
            'narrative_explanation': bedrock_result.narrative_explanation,
            'recommended_actions': bedrock_result.recommended_actions,
            'contextual_factors': bedrock_result.contextual_factors,
            'rule_validation': bedrock_result.rule_validation,
            'processing_time_ms': bedrock_result.processing_time_ms
        }

    def _create_case_metadata(self, ner_data: Dict[str, Any], characteristics: Dict[str, Any],
                              weights: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive case metadata"""
        return {
            'case_id': ner_data.get('case_id', 'unknown'),
            'processing_timestamp': ner_data.get('processing_timestamp'),
            'data_quality_score': ner_data.get('data_quality_score'),
            'complexity': characteristics['complexity'],
            'case_type': characteristics['case_type'],
            'urgency': characteristics['urgency'],
            'entity_count': characteristics['entity_count'],
            'financial_amounts_count': characteristics['financial_amounts_count'],
            'criminal_orgs_count': characteristics['criminal_orgs_count'],
            'weighting_strategy': weights['strategy'],
            'source_bucket': ner_data.get('s3_metadata', {}).get('bucket'),
            'source_key': ner_data.get('s3_metadata', {}).get('object_key')
        }

    def get_reconciliation_summary(self, assessment: FinalRiskAssessment) -> Dict[str, Any]:
        """Get summary of reconciliation results"""
        return {
            'final_score': assessment.final_score,
            'risk_level': assessment.risk_level.value,
            'confidence_level': assessment.confidence_level.value,
            'score_discord': assessment.score_discord,
            'requires_manual_review': assessment.requires_manual_review,
            'weighting_strategy': assessment.weighting_strategy,
            'case_type': assessment.case_metadata['case_type'],
            'recommended_actions_count': len(assessment.recommended_actions),
            'rule_score': assessment.rule_based_component['base_score'],
            'ai_score': assessment.ai_enhanced_component['contextual_score']
        }