import json
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import os
from decimal import Decimal
import urllib.parse
import traceback

# Configure logging with detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AMLRiskScorer:
    def __init__(self):
        try:
            # Initialize AWS clients with error handling
            self.s3_client = boto3.client('s3')
            self.dynamodb = boto3.resource('dynamodb')
            self.sns = boto3.client('sns')

            # Initialize Bedrock client with region check
            region = os.environ.get('AWS_REGION', 'us-east-1')
            self.bedrock_client = boto3.client('bedrock-runtime', region_name=region)

            # Environment variables with defaults
            self.risk_scores_table = os.environ.get('RISK_SCORES_TABLE', 'aml-risk-scores')
            self.sns_topic_arn = os.environ.get('SNS_TOPIC_ARN', '')
            # Disable Bedrock by default to avoid access issues
            self.bedrock_model_id = os.environ.get('BEDROCK_MODEL_ID', '')  # Empty = disabled
            self.output_bucket = os.environ.get('OUTPUT_BUCKET', '')

            # Validate required environment variables
            if not self.risk_scores_table:
                raise ValueError("RISK_SCORES_TABLE environment variable is required")

            logger.info(f"Initialized AMLRiskScorer with table: {self.risk_scores_table}")

        except Exception as e:
            logger.error(f"Error initializing AMLRiskScorer: {str(e)}")
            raise

        # Risk scoring weights
        self.weights = {
            'financial_crime_weight': 0.35,
            'entity_risk_weight': 0.25,
            'financial_amount_weight': 0.20,
            'criminal_org_weight': 0.15,
            'source_credibility_weight': 0.05
        }

        # Risk thresholds
        self.risk_thresholds = {
            'high': 70,
            'medium': 40,
            'low': 0
        }

    def lambda_handler(self, event, context):
        """Main Lambda handler function with comprehensive error handling"""
        try:
            logger.info(f"Received event: {json.dumps(event, default=str)}")

            # Validate event structure
            if 'Records' not in event:
                raise ValueError("Event must contain 'Records' key")

            # Process each S3 record in the event
            processed_count = 0
            error_count = 0

            for record in event['Records']:
                try:
                    # Extract S3 information safely
                    if 's3' not in record or 'bucket' not in record['s3'] or 'object' not in record['s3']:
                        logger.error(f"Invalid S3 record structure: {record}")
                        error_count += 1
                        continue

                    bucket = record['s3']['bucket']['name']
                    key = record['s3']['object']['key']

                    # URL decode the key (S3 encodes special characters)
                    key = urllib.parse.unquote_plus(key)

                    logger.info(f"Processing file: s3://{bucket}/{key}")

                    # Check if this is a valid NER output file
                    if not self.is_valid_ner_file(key):
                        logger.info(f"Skipping non-NER file: {key}")
                        continue

                    # Download and parse NER output
                    ner_data = self.download_and_parse_s3_file(bucket, key)
                    if not ner_data:
                        logger.warning(f"No data found in file: {key}")
                        error_count += 1
                        continue

                    # Validate NER data structure
                    if not self.validate_ner_data(ner_data):
                        logger.warning(f"Invalid NER data structure in file: {key}")
                        error_count += 1
                        continue

                    # Calculate risk score
                    risk_result = self.calculate_comprehensive_risk_score(ner_data)

                    # Generate AI explanation using Bedrock (with fallback)
                    ai_explanation = self.generate_ai_explanation(ner_data, risk_result)
                    risk_result['ai_explanation'] = ai_explanation

                    # Save results
                    self.save_risk_results(risk_result)

                    # Send alerts if high risk
                    if risk_result['risk_level'] == 'HIGH':
                        self.send_high_risk_alert(risk_result)

                    processed_count += 1
                    logger.info(
                        f"Risk scoring completed for {key} - Score: {risk_result['total_risk_score']}, Level: {risk_result['risk_level']}")

                except Exception as record_error:
                    error_count += 1
                    logger.error(f"Error processing record {record}: {str(record_error)}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    continue

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Risk scoring completed',
                    'processed_records': processed_count,
                    'error_records': error_count,
                    'total_records': len(event['Records'])
                })
            }

        except Exception as e:
            logger.error(f"Error in lambda_handler: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'error': str(e),
                    'message': 'Risk scoring failed'
                })
            }

    def is_valid_ner_file(self, key: str) -> bool:
        """Check if the S3 object is a valid NER output file"""
        try:
            # Check file extension
            if not key.lower().endswith('.json'):
                return False

            # Check if it's in NER output directory or has NER naming pattern
            ner_patterns = [
                'ner',
                'named-entity',
                'entity-recognition',
                'comprehend'
            ]

            key_lower = key.lower()
            return any(pattern in key_lower for pattern in ner_patterns)

        except Exception as e:
            logger.error(f"Error checking file validity: {str(e)}")
            return True  # Default to processing if unsure

    def validate_ner_data(self, ner_data: Dict) -> bool:
        """Validate NER data structure"""
        try:
            # Check required fields
            if not isinstance(ner_data, dict):
                logger.error("NER data is not a dictionary")
                return False

            # Check for processing_metadata
            if 'processing_metadata' not in ner_data:
                logger.warning("Missing processing_metadata in NER data")
                return False

            # Check for article_id
            metadata = ner_data.get('processing_metadata', {})
            if not metadata.get('article_id'):
                logger.warning("Missing article_id in processing_metadata")
                return False

            logger.info(f"Validated NER data for article: {metadata.get('article_id')}")
            return True

        except Exception as e:
            logger.error(f"Error validating NER data: {str(e)}")
            return False

    def download_and_parse_s3_file(self, bucket: str, key: str) -> Optional[Dict]:
        """Download and parse NER output JSON from S3 with error handling"""
        try:
            logger.info(f"Downloading file from S3: s3://{bucket}/{key}")

            # Check if object exists first
            try:
                self.s3_client.head_object(Bucket=bucket, Key=key)
            except self.s3_client.exceptions.NoSuchKey:
                logger.error(f"File not found in S3: s3://{bucket}/{key}")
                return None
            except Exception as head_error:
                logger.error(f"Error checking file existence: {str(head_error)}")
                return None

            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            content = response['Body'].read().decode('utf-8')

            if not content.strip():
                logger.warning(f"Empty file content for: {key}")
                return None

            data = json.loads(content)
            logger.info(f"Successfully parsed JSON file: {key}, size: {len(content)} bytes")
            return data

        except self.s3_client.exceptions.NoSuchKey:
            logger.error(f"File not found in S3: s3://{bucket}/{key}")
            return None
        except self.s3_client.exceptions.NoSuchBucket:
            logger.error(f"Bucket not found: {bucket}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in file {key}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error downloading file from S3: {str(e)}")
            return None

    def calculate_comprehensive_risk_score(self, ner_data: Dict) -> Dict:
        """Calculate comprehensive risk score with error handling"""
        try:
            # Initialize scores with safe defaults
            financial_crime_score = self.calculate_financial_crime_score(ner_data.get('custom_entities', []))
            entity_risk_score = self.calculate_entity_risk_score(ner_data.get('aws_entities', []))
            financial_amount_score = self.calculate_financial_amount_score(ner_data.get('financial_amounts', []))
            criminal_org_score = self.calculate_criminal_organization_score(ner_data.get('criminal_organizations', []))
            source_credibility_score = self.calculate_source_credibility_score(ner_data)

            # Calculate weighted total score
            total_score = (
                    financial_crime_score * self.weights['financial_crime_weight'] +
                    entity_risk_score * self.weights['entity_risk_weight'] +
                    financial_amount_score * self.weights['financial_amount_weight'] +
                    criminal_org_score * self.weights['criminal_org_weight'] +
                    source_credibility_score * self.weights['source_credibility_weight']
            )

            # Determine risk level
            risk_level = self.determine_risk_level(total_score)

            # Get article_id safely
            article_id = ner_data.get('processing_metadata', {}).get('article_id', 'unknown')

            # Create result
            risk_result = {
                'article_id': article_id,
                'total_risk_score': round(float(total_score), 2),
                'risk_level': risk_level,
                'component_scores': {
                    'financial_crime_score': round(float(financial_crime_score), 2),
                    'entity_risk_score': round(float(entity_risk_score), 2),
                    'financial_amount_score': round(float(financial_amount_score), 2),
                    'criminal_org_score': round(float(criminal_org_score), 2),
                    'source_credibility_score': round(float(source_credibility_score), 2)
                },
                'risk_indicators': self.extract_risk_indicators(ner_data),
                'processed_at': datetime.utcnow().isoformat(),
                'source_metadata': ner_data.get('processing_metadata', {}),
                's3_metadata': ner_data.get('s3_metadata', {})
            }

            logger.info(f"Calculated risk score: {total_score} ({risk_level}) for article: {article_id}")
            return risk_result

        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            # Return default risk result
            return {
                'article_id': ner_data.get('processing_metadata', {}).get('article_id', 'unknown'),
                'total_risk_score': 0.0,
                'risk_level': 'LOW',
                'component_scores': {
                    'financial_crime_score': 0.0,
                    'entity_risk_score': 0.0,
                    'financial_amount_score': 0.0,
                    'criminal_org_score': 0.0,
                    'source_credibility_score': 0.0
                },
                'risk_indicators': [],
                'processed_at': datetime.utcnow().isoformat(),
                'source_metadata': ner_data.get('processing_metadata', {}),
                's3_metadata': ner_data.get('s3_metadata', {}),
                'error': f"Risk calculation failed: {str(e)}"
            }

    def calculate_financial_crime_score(self, custom_entities: List[Dict]) -> float:
        """Calculate score based on financial crime entities with safe handling"""
        try:
            if not custom_entities or not isinstance(custom_entities, list):
                return 0.0

            crime_weights = {
                'money laundering': 90,
                'general_ml': 90,
                'racketeering': 85,
                'illegal gambling': 70,
                'fraud': 80,
                'other_crimes': 60
            }

            max_score = 0
            crime_count = 0

            for entity in custom_entities:
                if not isinstance(entity, dict):
                    continue

                if entity.get('type') == 'FINANCIAL_CRIME':
                    category = str(entity.get('category', '')).lower()
                    confidence = float(entity.get('confidence', 0))

                    # Get base score for crime type
                    base_score = crime_weights.get(category, 50)

                    # Adjust by confidence
                    adjusted_score = base_score * confidence
                    max_score = max(max_score, adjusted_score)
                    crime_count += 1

            # Apply frequency multiplier
            frequency_multiplier = min(1 + (crime_count - 1) * 0.1, 1.5)
            final_score = min(max_score * frequency_multiplier, 100)

            logger.debug(f"Financial crime score: {final_score} (crimes: {crime_count})")
            return final_score

        except Exception as e:
            logger.error(f"Error calculating financial crime score: {str(e)}")
            return 0.0

    def calculate_entity_risk_score(self, aws_entities: List[Dict]) -> float:
        """Calculate score based on AWS entities and their risk indicators"""
        try:
            if not aws_entities or not isinstance(aws_entities, list):
                return 0.0

            risk_scores = []

            for entity in aws_entities:
                if not isinstance(entity, dict):
                    continue

                entity_score = 0
                aml_relevance = float(entity.get('aml_relevance', 0))
                confidence = float(entity.get('confidence', 0))
                risk_indicators = entity.get('risk_indicators', [])

                # Base score from AML relevance and confidence
                base_score = aml_relevance * confidence * 50

                # Add risk indicator bonuses
                for indicator in risk_indicators:
                    if indicator == 'LEGAL_OFFICIAL':
                        base_score += 20
                    elif indicator == 'CRIMINAL_ORGANIZATION':
                        base_score += 40

                risk_scores.append(min(base_score, 100))

            # Return average of top 3 scores
            risk_scores.sort(reverse=True)
            top_scores = risk_scores[:3]
            final_score = sum(top_scores) / len(top_scores) if top_scores else 0

            logger.debug(f"Entity risk score: {final_score} (entities: {len(aws_entities)})")
            return final_score

        except Exception as e:
            logger.error(f"Error calculating entity risk score: {str(e)}")
            return 0.0

    def calculate_financial_amount_score(self, financial_amounts: List[Dict]) -> float:
        """Calculate score based on financial amounts mentioned"""
        try:
            if not financial_amounts or not isinstance(financial_amounts, list):
                return 0.0

            max_score = 0

            for amount_info in financial_amounts:
                if not isinstance(amount_info, dict):
                    continue

                normalized_value = float(amount_info.get('normalized_value', 0))
                risk_level = amount_info.get('risk_level', 'LOW')

                # Score based on amount thresholds
                if normalized_value >= 10000000:  # $10M+
                    amount_score = 90
                elif normalized_value >= 1000000:  # $1M+
                    amount_score = 70
                elif normalized_value >= 100000:  # $100K+
                    amount_score = 50
                else:
                    amount_score = 20

                # Adjust by risk level
                risk_multipliers = {'HIGH': 1.2, 'MEDIUM': 1.0, 'LOW': 0.8}
                adjusted_score = amount_score * risk_multipliers.get(risk_level, 1.0)

                max_score = max(max_score, adjusted_score)

            final_score = min(max_score, 100)
            logger.debug(f"Financial amount score: {final_score} (amounts: {len(financial_amounts)})")
            return final_score

        except Exception as e:
            logger.error(f"Error calculating financial amount score: {str(e)}")
            return 0.0

    def calculate_criminal_organization_score(self, criminal_orgs: List[Dict]) -> float:
        """Calculate score based on criminal organizations mentioned"""
        try:
            if not criminal_orgs or not isinstance(criminal_orgs, list):
                return 0.0

            org_weights = {
                'MAFIA': 95,
                'CRIME_FAMILY': 90,
                'ITALIAN_MAFIA': 95,
                'CRIMINAL_ORGANIZATION': 80
            }

            max_score = 0
            org_count = len(criminal_orgs)

            for org in criminal_orgs:
                if not isinstance(org, dict):
                    continue

                subtype = org.get('subtype', 'CRIMINAL_ORGANIZATION')
                risk_level = org.get('risk_level', 'MEDIUM')

                base_score = org_weights.get(subtype, 70)

                # Adjust by risk level
                if risk_level == 'HIGH':
                    base_score *= 1.1

                max_score = max(max_score, base_score)

            # Apply frequency multiplier for multiple organizations
            frequency_multiplier = min(1 + (org_count - 1) * 0.05, 1.3)
            final_score = min(max_score * frequency_multiplier, 100)

            logger.debug(f"Criminal org score: {final_score} (orgs: {org_count})")
            return final_score

        except Exception as e:
            logger.error(f"Error calculating criminal organization score: {str(e)}")
            return 0.0

    def calculate_source_credibility_score(self, ner_data: Dict) -> float:
        """Calculate score based on source credibility"""
        try:
            metadata = ner_data.get('processing_metadata', {})
            source = str(metadata.get('source', 'unknown')).lower()

            # Source credibility mapping
            credibility_scores = {
                'newspaper': 80,
                'government': 95,
                'regulatory': 90,
                'court_document': 95,
                'law_enforcement': 90,
                'social_media': 40,
                'blog': 30,
                'forum': 25,
                'unknown': 50
            }

            base_credibility = credibility_scores.get(source, 50)

            # Check for validation status
            aws_entities = ner_data.get('aws_entities', [])
            if aws_entities:
                validated_entities = sum(1 for entity in aws_entities
                                         if entity.get('validation_status') == 'VALIDATED')
                total_entities = len(aws_entities)

                validation_ratio = validated_entities / total_entities
                credibility_adjustment = validation_ratio * 20  # Up to 20 point bonus
            else:
                credibility_adjustment = 0

            final_score = min(base_credibility + credibility_adjustment, 100)
            logger.debug(f"Source credibility score: {final_score} (source: {source})")
            return final_score

        except Exception as e:
            logger.error(f"Error calculating source credibility score: {str(e)}")
            return 50.0

    def determine_risk_level(self, score: float) -> str:
        """Determine risk level based on score"""
        try:
            if score >= self.risk_thresholds['high']:
                return 'HIGH'
            elif score >= self.risk_thresholds['medium']:
                return 'MEDIUM'
            else:
                return 'LOW'
        except Exception as e:
            logger.error(f"Error determining risk level: {str(e)}")
            return 'LOW'

    def extract_risk_indicators(self, ner_data: Dict) -> List[str]:
        """Extract key risk indicators from the data"""
        try:
            indicators = []

            # Financial crime indicators
            for entity in ner_data.get('custom_entities', []):
                if entity.get('type') == 'FINANCIAL_CRIME':
                    indicators.append(f"Financial Crime: {entity.get('text', 'Unknown')}")

            # Criminal organization indicators
            for org in ner_data.get('criminal_organizations', []):
                indicators.append(f"Criminal Organization: {org.get('text', 'Unknown')}")

            # High-value financial amounts
            for amount in ner_data.get('financial_amounts', []):
                if amount.get('normalized_value', 0) >= 1000000:
                    indicators.append(f"Large Financial Amount: {amount.get('amount', 'Unknown')}")

            # Legal officials mentioned
            legal_officials = [entity.get('text') for entity in ner_data.get('aws_entities', [])
                               if 'LEGAL_OFFICIAL' in entity.get('risk_indicators', [])]
            if legal_officials:
                indicators.append(f"Legal Officials Mentioned: {', '.join(legal_officials[:3])}")

            return indicators[:10]  # Limit to top 10 indicators

        except Exception as e:
            logger.error(f"Error extracting risk indicators: {str(e)}")
            return []

    def generate_ai_explanation(self, ner_data: Dict, risk_result: Dict) -> str:
        """Generate AI explanation using AWS Bedrock with fallback"""
        try:
            # Check if Bedrock is enabled
            if not self.bedrock_model_id:
                logger.info("Bedrock disabled, using fallback explanation")
                return self.generate_fallback_explanation(risk_result)

            # Try available models for ap-southeast-1 region
            model_options = [
                'amazon.titan-text-lite-v1',
                'amazon.titan-text-express-v1',
                'ai21.j2-mid-v1',
                'ai21.j2-ultra-v1'
            ]

            for model_id in model_options:
                try:
                    logger.info(f"Trying Bedrock model: {model_id}")

                    prompt = self.create_bedrock_prompt(ner_data, risk_result)

                    # Use Titan format (most likely to be available)
                    request_body = {
                        "inputText": prompt,
                        "textGenerationConfig": {
                            "maxTokenCount": 1000,
                            "temperature": 0.3,
                            "topP": 0.9
                        }
                    }

                    response = self.bedrock_client.invoke_model(
                        modelId=model_id,
                        body=json.dumps(request_body)
                    )

                    response_body = json.loads(response['body'].read())
                    explanation = response_body['results'][0]['outputText']

                    logger.info(f"Successfully generated AI explanation using {model_id}")
                    return explanation

                except Exception as model_error:
                    logger.warning(f"Model {model_id} failed: {str(model_error)}")
                    continue

            # If all models fail, use fallback
            logger.info("All Bedrock models failed, using fallback explanation")
            return self.generate_fallback_explanation(risk_result)

        except Exception as e:
            logger.warning(f"Error generating AI explanation, using fallback: {str(e)}")
            return self.generate_fallback_explanation(risk_result)

    def create_bedrock_prompt(self, ner_data: Dict, risk_result: Dict) -> str:
        """Create prompt for Bedrock AI explanation"""
        try:
            # Extract key information
            financial_crimes = [entity.get('text') for entity in ner_data.get('custom_entities', [])
                                if entity.get('type') == 'FINANCIAL_CRIME']
            criminal_orgs = [org.get('text') for org in ner_data.get('criminal_organizations', [])]
            financial_amounts = [amount.get('amount') for amount in ner_data.get('financial_amounts', [])]
            risk_indicators = risk_result.get('risk_indicators', [])

            prompt = f"""
As an AML (Anti-Money Laundering) expert, analyze the following case and provide a clear explanation of the risk assessment.

CASE DETAILS:
- Article ID: {ner_data.get('processing_metadata', {}).get('article_id')}
- Risk Score: {risk_result['total_risk_score']}/100
- Risk Level: {risk_result['risk_level']}

DETECTED ENTITIES:
- Financial Crimes: {', '.join(financial_crimes) if financial_crimes else 'None detected'}
- Criminal Organizations: {', '.join(criminal_orgs) if criminal_orgs else 'None detected'}
- Financial Amounts: {', '.join(financial_amounts) if financial_amounts else 'None detected'}
- Key Risk Indicators: {'; '.join(risk_indicators) if risk_indicators else 'None'}

COMPONENT SCORES:
- Financial Crime Score: {risk_result['component_scores']['financial_crime_score']}/100
- Entity Risk Score: {risk_result['component_scores']['entity_risk_score']}/100
- Financial Amount Score: {risk_result['component_scores']['financial_amount_score']}/100
- Criminal Organization Score: {risk_result['component_scores']['criminal_org_score']}/100
- Source Credibility Score: {risk_result['component_scores']['source_credibility_score']}/100

Please provide:
1. A summary of why this case received this risk level
2. The main risk factors identified
3. Recommended actions for AML compliance team
4. Any additional considerations for investigation

Keep the explanation professional, concise (under 500 words), and actionable for AML analysts.
"""
            return prompt

        except Exception as e:
            logger.error(f"Error creating Bedrock prompt: {str(e)}")
            return f"Analyze AML risk for case {risk_result.get('article_id', 'unknown')} with score {risk_result.get('total_risk_score', 0)}"

    def generate_fallback_explanation(self, risk_result: Dict) -> str:
        """Generate fallback explanation when Bedrock is not available"""
        try:
            risk_level = risk_result.get('risk_level', 'UNKNOWN')
            total_score = risk_result.get('total_risk_score', 0)
            risk_indicators = risk_result.get('risk_indicators', [])

            explanation = f"""Risk Assessment Summary:
- Overall Risk Level: {risk_level}
- Risk Score: {total_score}/100

Key Risk Factors:
{chr(10).join(f"• {indicator}" for indicator in risk_indicators[:5]) if risk_indicators else "• No specific risk indicators detected"}

Recommendation:
"""

            if risk_level == 'HIGH':
                explanation += "Immediate investigation required. This case shows multiple high-risk indicators."
            elif risk_level == 'MEDIUM':
                explanation += "Enhanced due diligence recommended. Monitor for additional risk factors."
            else:
                explanation += "Standard monitoring sufficient. Low risk profile detected."

            return explanation

        except Exception as e:
            logger.error(f"Error generating fallback explanation: {str(e)}")
            return f"Risk assessment completed. Level: {risk_result.get('risk_level', 'UNKNOWN')}"

    def save_risk_results(self, risk_result: Dict):
        """Save risk scoring results with comprehensive error handling"""
        try:
            # Save to DynamoDB
            table = self.dynamodb.Table(self.risk_scores_table)

            article_id = risk_result.get('article_id', 'unknown')
            timestamp = risk_result.get('processed_at', datetime.utcnow().isoformat())

            # Create DynamoDB item - check if table uses pk/sk or different schema
            try:
                # First try with pk/sk structure
                dynamodb_item = {
                    'pk': f"ARTICLE#{article_id}",
                    'sk': f"RISK_SCORE#{timestamp}",
                    'article_id': article_id,
                    'processed_date': timestamp[:10],  # YYYY-MM-DD for GSI
                    'total_risk_score': risk_result['total_risk_score'],
                    'risk_level': risk_result['risk_level'],
                    'component_scores': risk_result['component_scores'],
                    'risk_indicators': risk_result['risk_indicators'],
                    'ai_explanation': risk_result.get('ai_explanation', ''),
                    'source_metadata': risk_result['source_metadata'],
                    's3_metadata': risk_result['s3_metadata'],
                    'ttl': int((datetime.utcnow() + timedelta(days=2555)).timestamp())  # 7 years retention
                }

                # Convert float values to Decimal for DynamoDB
                dynamodb_item = self.convert_floats_to_decimal(dynamodb_item)

                table.put_item(Item=dynamodb_item)
                logger.info(f"Successfully saved to DynamoDB with pk/sk: {article_id}")

            except Exception as pk_sk_error:
                # If pk/sk fails, try with timestamp as primary key
                logger.warning(f"pk/sk structure failed, trying timestamp structure: {str(pk_sk_error)}")

                dynamodb_item_alt = {
                    'timestamp': timestamp,
                    'article_id': article_id,
                    'processed_date': timestamp[:10],
                    'total_risk_score': risk_result['total_risk_score'],
                    'risk_level': risk_result['risk_level'],
                    'component_scores': risk_result['component_scores'],
                    'risk_indicators': risk_result['risk_indicators'],
                    'ai_explanation': risk_result.get('ai_explanation', ''),
                    'source_metadata': risk_result['source_metadata'],
                    's3_metadata': risk_result['s3_metadata'],
                    'ttl': int((datetime.utcnow() + timedelta(days=2555)).timestamp())
                }

                # Convert float values to Decimal for DynamoDB
                dynamodb_item_alt = self.convert_floats_to_decimal(dynamodb_item_alt)

                table.put_item(Item=dynamodb_item_alt)
                logger.info(f"Successfully saved to DynamoDB with timestamp: {article_id}")

            # Save detailed results to S3 (if bucket configured)
            if self.output_bucket:
                try:
                    output_key = f"risk-scores/date={datetime.utcnow().strftime('%Y-%m-%d')}/{article_id}_risk_score.json"

                    self.s3_client.put_object(
                        Bucket=self.output_bucket,
                        Key=output_key,
                        Body=json.dumps(risk_result, indent=2, default=str),
                        ContentType='application/json'
                    )

                    logger.info(f"Risk results saved to S3: {output_key}")
                except Exception as s3_error:
                    logger.warning(f"Failed to save to S3: {str(s3_error)}")

        except Exception as e:
            logger.error(f"Error saving risk results: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            # Don't raise exception to continue processing other records
            logger.warning("Continuing without saving to DynamoDB")

    def convert_floats_to_decimal(self, obj):
        """Convert float values to Decimal for DynamoDB compatibility"""
        try:
            if isinstance(obj, dict):
                return {k: self.convert_floats_to_decimal(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [self.convert_floats_to_decimal(v) for v in obj]
            elif isinstance(obj, float):
                return Decimal(str(obj))
            elif isinstance(obj, int):
                return obj
            else:
                return obj
        except Exception as e:
            logger.error(f"Error converting to Decimal: {str(e)}")
            return obj

    def send_high_risk_alert(self, risk_result: Dict):
        """Send SNS alert for high-risk cases"""
        if not self.sns_topic_arn:
            logger.info("SNS topic not configured, skipping alert")
            return

        try:
            message = {
                "alert_type": "HIGH_RISK_AML_CASE",
                "article_id": risk_result['article_id'],
                "risk_score": risk_result['total_risk_score'],
                "risk_level": risk_result['risk_level'],
                "risk_indicators": risk_result['risk_indicators'],
                "timestamp": risk_result['processed_at'],
                "component_scores": risk_result['component_scores']
            }

            self.sns.publish(
                TopicArn=self.sns_topic_arn,
                Message=json.dumps(message, indent=2, default=str),
                Subject=f"🚨 HIGH RISK AML Alert - Case {risk_result['article_id']}"
            )

            logger.info(f"High risk alert sent for case {risk_result['article_id']}")

        except Exception as e:
            logger.error(f"Error sending SNS alert: {str(e)}")


# Initialize the scorer with error handling
try:
    risk_scorer = AMLRiskScorer()
    logger.info("AMLRiskScorer initialized successfully")
except Exception as init_error:
    logger.error(f"Failed to initialize AMLRiskScorer: {str(init_error)}")
    risk_scorer = None


def lambda_handler(event, context):
    """Lambda entry point with error handling"""
    try:
        if risk_scorer is None:
            logger.error("AMLRiskScorer not initialized")
            return {
                'statusCode': 500,
                'body': json.dumps('AMLRiskScorer initialization failed')
            }

        return risk_scorer.lambda_handler(event, context)

    except Exception as e:
        logger.error(f"Lambda handler error: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Lambda execution failed: {str(e)}')
        }