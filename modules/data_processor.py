"""
Data Processor Module
Xử lý và validate dữ liệu NER từ S3
"""

import json
import boto3
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from modules.exceptions import DataProcessingError


@dataclass
class ProcessedNERData:
    """Structured NER data sau khi xử lý"""
    aws_entities: List[Dict[str, Any]]
    custom_entities: List[Dict[str, Any]]
    financial_amounts: List[Dict[str, Any]]
    time_references: List[Dict[str, Any]]
    criminal_organizations: List[Dict[str, Any]]
    processing_metadata: Dict[str, Any]
    s3_metadata: Dict[str, Any]

    # Derived fields
    total_entities: int
    high_risk_entities: List[Dict[str, Any]]
    validated_entities: List[Dict[str, Any]]
    needs_review_entities: List[Dict[str, Any]]


class NERDataProcessor:
    """Processor cho NER data từ S3"""

    def __init__(self, s3_client):
        self.s3_client = s3_client

    def load_and_validate_ner_data(self, bucket: str, key: str) -> Dict[str, Any]:
        """Load và validate NER data từ S3"""
        try:
            # 1. Load raw data từ S3
            raw_data = self._load_from_s3(bucket, key)

            # 2. Validate structure
            validated_data = self._validate_ner_structure(raw_data)

            # 3. Process và enrich data
            processed_data = self._process_and_enrich(validated_data)

            # 4. Perform quality checks
            self._perform_quality_checks(processed_data)

            return processed_data

        except Exception as e:
            raise DataProcessingError(f"Failed to load/validate NER data from s3://{bucket}/{key}: {str(e)}")

    def _load_from_s3(self, bucket: str, key: str) -> Dict[str, Any]:
        """Load JSON data từ S3"""
        try:
            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            content = response['Body'].read().decode('utf-8')
            return json.loads(content)

        except self.s3_client.exceptions.NoSuchKey:
            raise DataProcessingError(f"File not found: s3://{bucket}/{key}")
        except self.s3_client.exceptions.NoSuchBucket:
            raise DataProcessingError(f"Bucket not found: {bucket}")
        except json.JSONDecodeError as e:
            raise DataProcessingError(f"Invalid JSON format: {str(e)}")
        except Exception as e:
            raise DataProcessingError(f"Failed to load from S3: {str(e)}")

    def _validate_ner_structure(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate cấu trúc NER data"""
        required_fields = [
            'aws_entities',
            'custom_entities',
            'financial_amounts',
            'time_references',
            'criminal_organizations',
            'processing_metadata'
        ]

        for field in required_fields:
            if field not in data:
                raise DataProcessingError(f"Missing required field: {field}")

            if not isinstance(data[field], list) and field != 'processing_metadata':
                raise DataProcessingError(f"Field {field} must be a list")

        # Validate processing_metadata
        if not isinstance(data['processing_metadata'], dict):
            raise DataProcessingError("processing_metadata must be a dictionary")

        # Check for minimum data quality
        if len(data['aws_entities']) == 0 and len(data['custom_entities']) == 0:
            raise DataProcessingError("No entities found in the data")

        return data

    def _process_and_enrich(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process và enrich NER data"""

        # 1. Categorize entities
        categorized_entities = self._categorize_entities(data['aws_entities'])

        # 2. Enrich với AML-specific fields
        enriched_entities = self._enrich_entities_for_aml(data['aws_entities'])

        # 3. Process financial amounts
        processed_amounts = self._process_financial_amounts(data['financial_amounts'])

        # 4. Analyze time references
        analyzed_time_refs = self._analyze_time_references(data['time_references'])

        # 5. Process criminal organizations
        processed_criminal_orgs = self._process_criminal_organizations(data['criminal_organizations'])

        # 6. Create summary statistics
        summary_stats = self._create_summary_statistics(data)

        # Return enriched data
        return {
            **data,  # Original data
            'enriched_entities': enriched_entities,
            'categorized_entities': categorized_entities,
            'processed_financial_amounts': processed_amounts,
            'analyzed_time_references': analyzed_time_refs,
            'processed_criminal_organizations': processed_criminal_orgs,
            'summary_statistics': summary_stats,
            'data_quality_score': self._calculate_data_quality_score(data),
            'processing_timestamp': data['processing_metadata'].get('processed_at'),
            'case_id': data['processing_metadata'].get('article_id', 'unknown')
        }

    def _categorize_entities(self, entities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Phân loại entities theo type và risk level"""
        categories = {
            'persons': [],
            'organizations': [],
            'locations': [],
            'financial': [],
            'temporal': [],
            'high_risk': [],
            'validated': [],
            'needs_review': []
        }

        for entity in entities:
            entity_type = entity.get('type', '').upper()
            validation_status = entity.get('validation_status', 'UNKNOWN')
            risk_indicators = entity.get('risk_indicators', [])

            # Categorize by type
            if entity_type == 'PERSON':
                categories['persons'].append(entity)
            elif entity_type == 'ORGANIZATION':
                categories['organizations'].append(entity)
            elif entity_type in ['LOCATION', 'GPE']:
                categories['locations'].append(entity)
            elif entity_type in ['MONEY', 'QUANTITY']:
                categories['financial'].append(entity)
            elif entity_type == 'DATE':
                categories['temporal'].append(entity)

            # Categorize by validation status
            if validation_status == 'VALIDATED':
                categories['validated'].append(entity)
            elif validation_status == 'NEEDS_REVIEW':
                categories['needs_review'].append(entity)

            # Categorize by risk
            if risk_indicators or entity.get('aml_relevance', 0) > 0.8:
                categories['high_risk'].append(entity)

        return categories

    def _enrich_entities_for_aml(self, entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich entities với AML-specific information"""
        enriched = []

        for entity in entities:
            enriched_entity = entity.copy()

            # Add AML risk score
            aml_risk_score = self._calculate_entity_aml_risk(entity)
            enriched_entity['aml_risk_score'] = aml_risk_score

            # Add AML category
            aml_category = self._determine_aml_category(entity)
            enriched_entity['aml_category'] = aml_category

            # Add priority level
            priority = self._determine_priority_level(entity, aml_risk_score)
            enriched_entity['priority_level'] = priority

            # Add relationship indicators
            relationships = self._identify_potential_relationships(entity, entities)
            enriched_entity['potential_relationships'] = relationships

            enriched.append(enriched_entity)

        return enriched

    def _calculate_entity_aml_risk(self, entity: Dict[str, Any]) -> float:
        """Tính AML risk score cho entity"""
        base_score = 0.0

        # Factor 1: AML relevance
        aml_relevance = entity.get('aml_relevance', 0)
        base_score += aml_relevance * 30

        # Factor 2: Risk indicators
        risk_indicators = entity.get('risk_indicators', [])
        if 'LEGAL_OFFICIAL' in risk_indicators:
            base_score += 20
        if 'CRIMINAL_ORGANIZATION' in risk_indicators:
            base_score += 40
        if 'SANCTIONED' in risk_indicators:
            base_score += 50

        # Factor 3: Confidence
        confidence = entity.get('confidence', 0)
        base_score = base_score * confidence

        # Factor 4: Validation status
        validation_status = entity.get('validation_status', 'UNKNOWN')
        if validation_status == 'NEEDS_REVIEW':
            base_score *= 0.8
        elif validation_status == 'VALIDATED':
            base_score *= 1.1

        return min(100.0, base_score)

    def _determine_aml_category(self, entity: Dict[str, Any]) -> str:
        """Xác định AML category cho entity"""
        risk_indicators = entity.get('risk_indicators', [])
        entity_type = entity.get('type', '')

        if 'CRIMINAL_ORGANIZATION' in risk_indicators:
            return 'CRIMINAL_ASSOCIATION'
        elif 'LEGAL_OFFICIAL' in risk_indicators:
            return 'PEP'  # Politically Exposed Person
        elif 'SANCTIONED' in risk_indicators:
            return 'SANCTIONS'
        elif entity_type == 'ORGANIZATION':
            return 'BUSINESS_ENTITY'
        elif entity_type == 'PERSON':
            return 'INDIVIDUAL'
        elif entity_type in ['MONEY', 'QUANTITY']:
            return 'FINANCIAL'
        else:
            return 'OTHER'

    def _determine_priority_level(self, entity: Dict[str, Any], aml_risk_score: float) -> str:
        """Xác định priority level"""
        if aml_risk_score >= 70:
            return 'CRITICAL'
        elif aml_risk_score >= 40:
            return 'HIGH'
        elif aml_risk_score >= 20:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _identify_potential_relationships(self, entity: Dict[str, Any], all_entities: List[Dict[str, Any]]) -> List[
        str]:
        """Identify potential relationships với other entities"""
        relationships = []
        entity_text = entity.get('text', '').lower()

        # Look for entities that appear near this entity (within 100 characters)
        entity_start = entity.get('start_offset', 0)
        entity_end = entity.get('end_offset', 0)

        for other_entity in all_entities:
            if other_entity == entity:
                continue

            other_start = other_entity.get('start_offset', 0)
            other_end = other_entity.get('end_offset', 0)

            # Check proximity
            distance = min(abs(entity_start - other_end), abs(other_start - entity_end))

            if distance < 100:  # Within 100 characters
                relationships.append({
                    'related_entity': other_entity.get('text', ''),
                    'relationship_type': 'PROXIMITY',
                    'distance': distance,
                    'context': 'NEARBY_MENTION'
                })

        return relationships

    def _process_financial_amounts(self, amounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process financial amounts với enhanced analysis"""
        processed = []

        for amount in amounts:
            processed_amount = amount.copy()

            # Add AML significance
            value = amount.get('normalized_value', 0)
            processed_amount['aml_significance'] = self._assess_amount_significance(value)

            # Add structuring indicators
            processed_amount['structuring_indicators'] = self._check_structuring_patterns(value)

            # Add reporting threshold flags
            processed_amount['reporting_thresholds'] = self._check_reporting_thresholds(value)

            processed.append(processed_amount)

        return processed

    def _assess_amount_significance(self, value: float) -> str:
        """Assess AML significance of amount"""
        if value >= 10000000:  # $10M+
            return 'VERY_HIGH'
        elif value >= 1000000:  # $1M+
            return 'HIGH'
        elif value >= 100000:  # $100K+
            return 'MEDIUM'
        elif value >= 10000:  # $10K+
            return 'LOW'
        else:
            return 'MINIMAL'

    def _check_structuring_patterns(self, value: float) -> List[str]:
        """Check for structuring patterns"""
        indicators = []

        # Just under $10K (CTR threshold)
        if 9000 <= value < 10000:
            indicators.append('UNDER_CTR_THRESHOLD')

        # Round amounts
        if value % 1000 == 0:
            indicators.append('ROUND_AMOUNT')

        # Common structuring amounts
        if value in [9999, 9500, 9000, 8000]:
            indicators.append('COMMON_STRUCTURING_AMOUNT')

        return indicators

    def _check_reporting_thresholds(self, value: float) -> Dict[str, bool]:
        """Check against various reporting thresholds"""
        return {
            'ctr_threshold': value >= 10000,  # Currency Transaction Report
            'sar_threshold': value >= 5000,  # Suspicious Activity Report consideration
            'fatf_threshold': value >= 15000,  # FATF recommendation
            'wire_threshold': value >= 3000  # Wire transfer reporting
        }

    def _analyze_time_references(self, time_refs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze time references for AML patterns"""
        analyzed = []

        for time_ref in time_refs:
            analyzed_ref = time_ref.copy()

            # Add temporal risk indicators
            analyzed_ref['temporal_risk_indicators'] = self._assess_temporal_risk(time_ref)

            # Add recency score
            analyzed_ref['recency_score'] = self._calculate_recency_score(time_ref)

            analyzed.append(analyzed_ref)

        return analyzed

    def _assess_temporal_risk(self, time_ref: Dict[str, Any]) -> List[str]:
        """Assess temporal risk indicators"""
        indicators = []

        text = time_ref.get('text', '').lower()

        # Look for suspicious temporal patterns
        if 'years' in text and any(word in text for word in ['25', '20', '15']):
            indicators.append('LONG_TERM_OPERATION')

        if any(word in text for word in ['immediately', 'urgent', 'asap']):
            indicators.append('URGENCY_INDICATOR')

        if 'night' in text or 'weekend' in text:
            indicators.append('UNUSUAL_TIMING')

        return indicators

    def _calculate_recency_score(self, time_ref: Dict[str, Any]) -> float:
        """Calculate recency score (0-1, where 1 is most recent)"""
        # This is a simplified implementation
        # In real implementation, you'd parse dates and calculate actual recency
        relevance_score = time_ref.get('relevance_score', 0.5)
        return relevance_score

    def _process_criminal_organizations(self, criminal_orgs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process criminal organizations với enhanced analysis"""
        processed = []

        for org in criminal_orgs:
            processed_org = org.copy()

            # Add threat level
            processed_org['threat_level'] = self._assess_organization_threat_level(org)

            # Add geographical risk
            processed_org['geographical_risk'] = self._assess_geographical_risk(org)

            # Add activity indicators
            processed_org['activity_indicators'] = self._identify_activity_indicators(org)

            processed.append(processed_org)

        return processed

    def _assess_organization_threat_level(self, org: Dict[str, Any]) -> str:
        """Assess threat level of criminal organization"""
        subtype = org.get('subtype', '').upper()
        risk_level = org.get('risk_level', '').upper()

        if subtype in ['MAFIA', 'CRIME_FAMILY', 'CARTEL']:
            return 'VERY_HIGH'
        elif risk_level == 'HIGH':
            return 'HIGH'
        else:
            return 'MEDIUM'

    def _assess_geographical_risk(self, org: Dict[str, Any]) -> str:
        """Assess geographical risk"""
        # This would be enhanced with actual geographical analysis
        return 'MEDIUM'  # Placeholder

    def _identify_activity_indicators(self, org: Dict[str, Any]) -> List[str]:
        """Identify activity indicators for criminal organization"""
        indicators = []

        context = org.get('context', '').lower()
        org_text = org.get('text', '').lower()

        # Financial crime indicators
        if any(word in context for word in ['money', 'laundering', 'financial']):
            indicators.append('FINANCIAL_CRIMES')

        # Violence indicators
        if any(word in context for word in ['threat', 'violence', 'hurt', 'kill']):
            indicators.append('VIOLENCE_THREATS')

        # Organizational structure indicators
        if any(word in context for word in ['captain', 'soldier', 'family', 'member']):
            indicators.append('STRUCTURED_ORGANIZATION')

        # Business infiltration
        if any(word in context for word in ['business', 'company', 'operation']):
            indicators.append('BUSINESS_INFILTRATION')

        return indicators

    def _create_summary_statistics(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary statistics for the NER data"""
        stats = {
            'total_entities': len(data.get('aws_entities', [])),
            'total_custom_entities': len(data.get('custom_entities', [])),
            'total_financial_amounts': len(data.get('financial_amounts', [])),
            'total_time_references': len(data.get('time_references', [])),
            'total_criminal_organizations': len(data.get('criminal_organizations', [])),
        }

        # Entity type breakdown
        entity_types = {}
        for entity in data.get('aws_entities', []):
            entity_type = entity.get('type', 'UNKNOWN')
            entity_types[entity_type] = entity_types.get(entity_type, 0) + 1
        stats['entity_type_breakdown'] = entity_types

        # Risk indicator statistics
        high_risk_count = 0
        validated_count = 0
        needs_review_count = 0

        for entity in data.get('aws_entities', []):
            if entity.get('risk_indicators'):
                high_risk_count += 1
            if entity.get('validation_status') == 'VALIDATED':
                validated_count += 1
            elif entity.get('validation_status') == 'NEEDS_REVIEW':
                needs_review_count += 1

        stats.update({
            'high_risk_entities': high_risk_count,
            'validated_entities': validated_count,
            'needs_review_entities': needs_review_count,
            'validation_rate': validated_count / max(1, stats['total_entities'])
        })

        # Financial statistics
        if data.get('financial_amounts'):
            amounts = [amt.get('normalized_value', 0) for amt in data['financial_amounts']]
            stats['financial_statistics'] = {
                'total_amount': sum(amounts),
                'max_amount': max(amounts) if amounts else 0,
                'min_amount': min(amounts) if amounts else 0,
                'avg_amount': sum(amounts) / len(amounts) if amounts else 0
            }

        return stats

    def _calculate_data_quality_score(self, data: Dict[str, Any]) -> float:
        """Calculate overall data quality score"""
        score = 0.0
        max_score = 100.0

        # Factor 1: Entity validation rate (30 points)
        total_entities = len(data.get('aws_entities', []))
        if total_entities > 0:
            validated = sum(1 for e in data['aws_entities'] if e.get('validation_status') == 'VALIDATED')
            validation_rate = validated / total_entities
            score += validation_rate * 30

        # Factor 2: Confidence scores (25 points)
        confidences = [e.get('confidence', 0) for e in data.get('aws_entities', [])]
        if confidences:
            avg_confidence = sum(confidences) / len(confidences)
            score += avg_confidence * 25

        # Factor 3: Data completeness (20 points)
        completeness_factors = [
            len(data.get('aws_entities', [])) > 0,
            len(data.get('financial_amounts', [])) > 0,
            data.get('processing_metadata', {}).get('content_length', 0) > 100,
            'article_id' in data.get('processing_metadata', {}),
        ]
        completeness_score = sum(completeness_factors) / len(completeness_factors)
        score += completeness_score * 20

        # Factor 4: AML relevance (15 points)
        aml_relevances = [e.get('aml_relevance', 0) for e in data.get('aws_entities', [])]
        if aml_relevances:
            avg_aml_relevance = sum(aml_relevances) / len(aml_relevances)
            score += avg_aml_relevance * 15

        # Factor 5: Processing metadata quality (10 points)
        metadata = data.get('processing_metadata', {})
        metadata_quality = all([
            'processed_at' in metadata,
            'content_length' in metadata,
            'total_entities_found' in metadata
        ])
        if metadata_quality:
            score += 10

        return min(max_score, score)

    def _perform_quality_checks(self, data: Dict[str, Any]):
        """Perform quality checks and raise warnings if needed"""
        quality_score = data.get('data_quality_score', 0)

        if quality_score < 50:
            print(f"WARNING: Low data quality score: {quality_score}")

        # Check for minimum entities
        if data['summary_statistics']['total_entities'] < 3:
            print("WARNING: Very few entities detected")

        # Check for validation issues
        needs_review_count = data['summary_statistics']['needs_review_entities']
        if needs_review_count > data['summary_statistics']['total_entities'] * 0.3:
            print(f"WARNING: High number of entities need review: {needs_review_count}")

        # Check for missing critical data
        if not data.get('financial_amounts') and not data.get('criminal_organizations'):
            print("WARNING: No financial amounts or criminal organizations detected")

    def extract_original_text(self, bucket: str, key: str) -> Optional[str]:
        """Extract original text if available in metadata"""
        try:
            data = self._load_from_s3(bucket, key)
            # Try to reconstruct text from entities or get from metadata
            # This is a simplified implementation
            return data.get('original_text', '')
        except Exception:
            return None

    def get_processing_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Get processing summary for logging/monitoring"""
        return {
            'case_id': data.get('case_id', 'unknown'),
            'processing_timestamp': data.get('processing_timestamp'),
            'data_quality_score': data.get('data_quality_score', 0),
            'total_entities': data['summary_statistics']['total_entities'],
            'high_risk_entities': data['summary_statistics']['high_risk_entities'],
            'validation_rate': data['summary_statistics']['validation_rate'],
            'content_length': data.get('processing_metadata', {}).get('content_length', 0)
        }