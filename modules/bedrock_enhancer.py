"""
Bedrock Enhancement Module
Sử dụng Amazon Bedrock để enhance rule-based assessment
"""

import json
import boto3
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from modules.exceptions import BedrockError


@dataclass
class BedrockEnhancedResult:
    """Kết quả enhancement từ Bedrock"""
    contextual_score: float
    risk_indicators: List[Dict[str, Any]]
    narrative_explanation: str
    confidence_adjustment: float
    recommended_actions: List[str]
    contextual_factors: List[str]
    rule_validation: Dict[str, Any]
    processing_time_ms: float


class BedrockEnhancer:
    """Bedrock enhancer cho AML risk assessment"""

    def __init__(self, config):
        self.config = config
        self.bedrock_client = boto3.client('bedrock-runtime')
        self.model_id = config.get('bedrock_model_id', 'anthropic.claude-3-sonnet-20240229-v1:0')
        self.max_tokens = config.get('bedrock_max_tokens', 2048)
        self.temperature = config.get('bedrock_temperature', 0.1)
        self.timeout = config.get('bedrock_timeout_seconds', 30)

    def enhance_assessment(self, ner_data: Dict[str, Any], rule_result) -> BedrockEnhancedResult:
        """Main enhancement function"""
        import time
        start_time = time.time()

        try:
            # Create comprehensive prompt
            prompt = self._create_enhancement_prompt(ner_data, rule_result)

            # Call Bedrock
            response = self._call_bedrock(prompt)

            # Parse response
            parsed_result = self._parse_bedrock_response(response, rule_result)

            processing_time = (time.time() - start_time) * 1000
            parsed_result.processing_time_ms = processing_time

            return parsed_result

        except Exception as e:
            raise BedrockError(f"Bedrock enhancement failed: {str(e)}")

    def _create_enhancement_prompt(self, ner_data: Dict[str, Any], rule_result) -> str:
        """Create comprehensive prompt cho Bedrock"""

        # Extract key information
        entities_summary = self._summarize_entities(ner_data)
        financial_summary = self._summarize_financial_data(ner_data)
        rule_summary = self._summarize_rule_results(rule_result)

        prompt = f"""
You are an expert AML (Anti-Money Laundering) risk assessment AI. Your task is to enhance and validate a rule-based risk assessment by providing contextual analysis and additional insights.

CASE INFORMATION:
Case ID: {ner_data.get('case_id', 'Unknown')}
Source: {ner_data.get('s3_metadata', {}).get('bucket', 'Unknown')}
Content Length: {ner_data.get('processing_metadata', {}).get('content_length', 0)} characters
Data Quality Score: {ner_data.get('data_quality_score', 0):.1f}/100

ENTITIES DETECTED:
{entities_summary}

FINANCIAL DATA:
{financial_summary}

RULE-BASED ASSESSMENT:
Score: {rule_result.base_score}/100
Confidence: {rule_result.confidence:.2f}
Triggered Rules: {', '.join(rule_result.triggered_rules)}
Key Reasoning: {'; '.join(rule_result.reasoning[:3])}

DETAILED RULE BREAKDOWN:
{rule_summary}

YOUR TASK:
Provide a comprehensive enhancement of this assessment. Consider:

1. CONTEXTUAL ANALYSIS
   - Relationships between entities that rules might miss
   - Narrative flow and logical connections
   - Temporal patterns and significance
   - Geographic and jurisdictional factors

2. RISK INDICATOR VALIDATION
   - Validate rule-based findings
   - Identify additional risk factors not captured by rules
   - Assess the severity and credibility of each indicator
   - Consider false positive possibilities

3. SCORING ENHANCEMENT
   - Suggest a contextual score (0-100) based on your analysis
   - Provide confidence adjustment (-0.3 to +0.3)
   - Explain any significant deviations from rule-based score

4. NARRATIVE EXPLANATION
   - Create a clear, professional explanation suitable for AML officers
   - Explain the risk scenario in natural language
   - Highlight key concerns and evidence

5. RECOMMENDATIONS
   - Suggest specific investigation steps
   - Identify priority areas for further analysis
   - Recommend appropriate regulatory actions if needed

REQUIRED OUTPUT FORMAT (JSON):
{{
    "contextual_score": <float 0-100>,
    "confidence_adjustment": <float -0.3 to +0.3>,
    "risk_indicators": [
        {{
            "indicator": "<brief description>",
            "severity": "<HIGH/MEDIUM/LOW>",
            "category": "<category>",
            "evidence": "<supporting evidence>",
            "confidence": <float 0-1>
        }}
    ],
    "narrative_explanation": "<comprehensive professional explanation>",
    "contextual_factors": [
        "<factor1>",
        "<factor2>"
    ],
    "recommended_actions": [
        "<action1>",
        "<action2>"
    ],
    "rule_validation": {{
        "agrees_with_rules": <true/false>,
        "disagreement_reasons": ["<reason1>", "<reason2>"],
        "suggested_rule_improvements": ["<improvement1>"],
        "overall_rule_accuracy": <float 0-1>
    }},
    "additional_insights": {{
        "entity_relationships": "<analysis of relationships>",
        "temporal_significance": "<temporal analysis>", 
        "risk_scenario": "<likely risk scenario>",
        "investigation_priority": "<HIGH/MEDIUM/LOW>"
    }}
}}

IMPORTANT GUIDELINES:
- Be thorough but concise
- Focus on actionable insights
- Consider both false positives and missed risks
- Maintain professional tone suitable for compliance documentation
- Provide specific evidence for your assessments
- If you disagree with rule-based assessment, explain clearly why

Begin your analysis:
"""

        return prompt

    def _summarize_entities(self, ner_data: Dict[str, Any]) -> str:
        """Summarize entities for prompt"""
        summary_parts = []

        # High-risk entities
        high_risk = [e for e in ner_data.get('enriched_entities', [])
                     if e.get('aml_risk_score', 0) > 50]
        if high_risk:
            summary_parts.append(f"High-risk entities ({len(high_risk)}):")
            for entity in high_risk[:5]:  # Limit to top 5
                risk_score = entity.get('aml_risk_score', 0)
                risk_indicators = entity.get('risk_indicators', [])
                summary_parts.append(
                    f"  - {entity.get('text', 'Unknown')} ({entity.get('type', 'Unknown')}) - Risk: {risk_score:.1f}, Indicators: {risk_indicators}")

        # Criminal organizations
        criminal_orgs = ner_data.get('criminal_organizations', [])
        if criminal_orgs:
            summary_parts.append(f"\nCriminal Organizations ({len(criminal_orgs)}):")
            for org in criminal_orgs[:3]:
                summary_parts.append(f"  - {org.get('text', 'Unknown')} ({org.get('subtype', 'Unknown')})")

        # Financial crime entities
        financial_crimes = ner_data.get('custom_entities', [])
        if financial_crimes:
            summary_parts.append(f"\nFinancial Crime References ({len(financial_crimes)}):")
            for crime in financial_crimes[:3]:
                summary_parts.append(f"  - {crime.get('text', 'Unknown')} ({crime.get('category', 'Unknown')})")

        return "\n".join(summary_parts) if summary_parts else "No significant entities detected."

    def _summarize_financial_data(self, ner_data: Dict[str, Any]) -> str:
        """Summarize financial data for prompt"""
        financial_amounts = ner_data.get('financial_amounts', [])

        if not financial_amounts:
            return "No financial amounts detected."

        summary_parts = [f"Financial Amounts ({len(financial_amounts)}):"]

        # Sort by value
        sorted_amounts = sorted(financial_amounts,
                                key=lambda x: x.get('normalized_value', 0),
                                reverse=True)

        for amount in sorted_amounts[:5]:  # Top 5 amounts
            value = amount.get('normalized_value', 0)
            risk_level = amount.get('risk_level', 'Unknown')
            context = amount.get('context', '')[:100] + '...' if len(amount.get('context', '')) > 100 else amount.get(
                'context', '')
            summary_parts.append(f"  - ${value:,.2f} (Risk: {risk_level}) - Context: {context}")

        # Add total
        total_amount = sum(amt.get('normalized_value', 0) for amt in financial_amounts)
        summary_parts.append(f"\nTotal Amount: ${total_amount:,.2f}")

        return "\n".join(summary_parts)

    def _summarize_rule_results(self, rule_result) -> str:
        """Summarize rule results for prompt"""
        if not rule_result.rule_breakdown:
            return "No rules triggered."

        summary_parts = ["Rule Details:"]

        # Sort by score contribution
        sorted_rules = sorted(rule_result.rule_breakdown.items(),
                              key=lambda x: x[1], reverse=True)

        for rule_name, score in sorted_rules:
            # Find the corresponding rule result for details
            rule_details = next((r for r in rule_result.rule_results
                                 if r.rule_name == rule_name and r.triggered), None)

            if rule_details:
                evidence_count = len(rule_details.evidence)
                summary_parts.append(f"  - {rule_name}: +{score:.1f} points ({evidence_count} evidence items)")
                if rule_details.evidence:
                    summary_parts.append(f"    Evidence: {rule_details.evidence[0]}")  # First evidence

        return "\n".join(summary_parts)

    def _call_bedrock(self, prompt: str) -> str:
        """Call Bedrock API với error handling"""
        try:
            payload = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }

            response = self.bedrock_client.invoke_model(
                body=json.dumps(payload),
                modelId=self.model_id,
                accept="application/json",
                contentType="application/json"
            )

            response_body = json.loads(response.get('body').read())
            return response_body['content'][0]['text']

        except self.bedrock_client.exceptions.ValidationException as e:
            raise BedrockError(f"Invalid request to Bedrock: {str(e)}")
        except self.bedrock_client.exceptions.ModelTimeoutException as e:
            raise BedrockError(f"Bedrock model timeout: {str(e)}")
        except self.bedrock_client.exceptions.ThrottlingException as e:
            raise BedrockError(f"Bedrock throttling: {str(e)}")
        except Exception as e:
            raise BedrockError(f"Unexpected Bedrock error: {str(e)}")

    def _parse_bedrock_response(self, response: str, rule_result) -> BedrockEnhancedResult:
        """Parse Bedrock response và tạo structured result"""
        try:
            # Try to parse JSON response
            parsed_json = json.loads(response)

            return BedrockEnhancedResult(
                contextual_score=float(parsed_json.get('contextual_score', rule_result.base_score)),
                risk_indicators=parsed_json.get('risk_indicators', []),
                narrative_explanation=parsed_json.get('narrative_explanation', ''),
                confidence_adjustment=float(parsed_json.get('confidence_adjustment', 0.0)),
                recommended_actions=parsed_json.get('recommended_actions', []),
                contextual_factors=parsed_json.get('contextual_factors', []),
                rule_validation=parsed_json.get('rule_validation', {}),
                processing_time_ms=0.0  # Will be set by caller
            )

        except json.JSONDecodeError:
            # Fallback: try to extract information from text response
            return self._parse_text_response(response, rule_result)

    def _parse_text_response(self, response: str, rule_result) -> BedrockEnhancedResult:
        """Fallback parsing for non-JSON responses"""
        # This is a simplified fallback - extract what we can
        lines = response.split('\n')

        narrative_explanation = response[:500] + "..." if len(response) > 500 else response

        # Try to extract a score if mentioned
        contextual_score = rule_result.base_score
        for line in lines:
            if 'score' in line.lower() and any(char.isdigit() for char in line):
                import re
                numbers = re.findall(r'\d+\.?\d*', line)
                if numbers:
                    try:
                        potential_score = float(numbers[0])
                        if 0 <= potential_score <= 100:
                            contextual_score = potential_score
                            break
                    except ValueError:
                        continue

        return BedrockEnhancedResult(
            contextual_score=contextual_score,
            risk_indicators=[],
            narrative_explanation=narrative_explanation,
            confidence_adjustment=0.0,
            recommended_actions=["Manual review recommended due to AI parsing issues"],
            contextual_factors=["AI response parsing incomplete"],
            rule_validation={"agrees_with_rules": True, "overall_rule_accuracy": 0.8},
            processing_time_ms=0.0
        )

    def create_fallback_result(self, rule_result, error_message: str) -> BedrockEnhancedResult:
        """Create fallback result when Bedrock fails"""
        return BedrockEnhancedResult(
            contextual_score=rule_result.base_score,
            risk_indicators=[],
            narrative_explanation=f"AI enhancement unavailable: {error_message}. Assessment based on rule-based analysis only.",
            confidence_adjustment=-0.2,  # Reduce confidence due to lack of AI enhancement
            recommended_actions=[
                "Manual review recommended due to AI unavailability",
                "Consider re-processing when AI services are available"
            ],
            contextual_factors=["AI enhancement failed"],
            rule_validation={
                "agrees_with_rules": True,
                "disagreement_reasons": [],
                "suggested_rule_improvements": [],
                "overall_rule_accuracy": 0.7
            },
            processing_time_ms=0.0
        )

    def validate_bedrock_config(self) -> Dict[str, Any]:
        """Validate Bedrock configuration"""
        validation_results = {
            'valid': True,
            'errors': [],
            'warnings': []
        }

        # Check model ID
        if not self.model_id:
            validation_results['errors'].append("Missing Bedrock model ID")
            validation_results['valid'] = False

        # Check token limits
        if self.max_tokens < 512:
            validation_results['warnings'].append("Very low max_tokens setting may truncate responses")
        elif self.max_tokens > 4096:
            validation_results['warnings'].append("Very high max_tokens may increase costs")

        # Check temperature
        if self.temperature < 0 or self.temperature > 1:
            validation_results['errors'].append("Temperature must be between 0 and 1")
            validation_results['valid'] = False

        # Test connectivity (optional)
        try:
            test_payload = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "Test"}]
            }

            self.bedrock_client.invoke_model(
                body=json.dumps(test_payload),
                modelId=self.model_id,
                accept="application/json",
                contentType="application/json"
            )

            validation_results['connectivity'] = True

        except Exception as e:
            validation_results['warnings'].append(f"Bedrock connectivity issue: {str(e)}")
            validation_results['connectivity'] = False

        return validation_results

    def get_enhancement_summary(self, result: BedrockEnhancedResult) -> Dict[str, Any]:
        """Get summary of enhancement results"""
        return {
            'contextual_score': result.contextual_score,
            'confidence_adjustment': result.confidence_adjustment,
            'risk_indicators_count': len(result.risk_indicators),
            'recommended_actions_count': len(result.recommended_actions),
            'agrees_with_rules': result.rule_validation.get('agrees_with_rules', True),
            'processing_time_ms': result.processing_time_ms,
            'has_narrative': len(result.narrative_explanation) > 0
        }