"""
Result Handler Module
Xử lý kết quả final assessment - store, alert, report
"""

import json
import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from modules.score_reconciler import FinalRiskAssessment, RiskLevel
from modules.exceptions import AMLProcessingError


class ResultHandler:
    """Handler cho processing final assessment results"""

    def __init__(self, config, dynamodb_resource, sns_client):
        self.config = config
        self.dynamodb = dynamodb_resource
        self.sns_client = sns_client

        # Get table names
        self.table_names = {
            'critical_cases': config.get('critical_cases_table', 'aml-critical-cases'),
            'high_risk_cases': config.get('high_risk_cases_table', 'aml-high-risk-cases'),
            'medium_risk_cases': config.get('medium_risk_cases_table', 'aml-medium-risk-cases'),
            'all_cases': config.get('all_cases_table', 'aml-all-cases'),
            'processing_errors': config.get('processing_errors_table', 'aml-processing-errors')
        }

        # Get SNS topic ARNs
        self.sns_topics = {
            'critical_alerts': config.get('critical_alerts_topic'),
            'high_risk_alerts': config.get('high_risk_alerts_topic'),
            'medium_risk_alerts': config.get('medium_risk_alerts_topic')
        }

    def process_final_assessment(self, assessment: FinalRiskAssessment,
                                 processing_context: Dict[str, Any]) -> Dict[str, Any]:
        """Main function để process final assessment"""
        try:
            results = {
                'case_id': assessment.case_metadata['case_id'],
                'final_score': assessment.final_score,
                'risk_level': assessment.risk_level.value,
                'processing_timestamp': datetime.utcnow().isoformat(),
                'actions_taken': []
            }

            # 1. Store trong appropriate table
            storage_result = self._store_assessment(assessment, processing_context)
            results['storage'] = storage_result
            results['actions_taken'].append('assessment_stored')

            # 2. Send alerts based on risk level
            alert_result = self._send_risk_alerts(assessment, processing_context)
            results['alerts'] = alert_result
            if alert_result['alerts_sent'] > 0:
                results['actions_taken'].append('alerts_sent')

            # 3. Handle manual review requirements
            if assessment.requires_manual_review:
                review_result = self._schedule_manual_review(assessment, processing_context)
                results['manual_review'] = review_result
                results['actions_taken'].append('manual_review_scheduled')

            # 4. Update metrics and monitoring
            self._update_processing_metrics(assessment, processing_context)
            results['actions_taken'].append('metrics_updated')

            # 5. Generate compliance artifacts if needed
            if assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                compliance_result = self._generate_compliance_artifacts(assessment, processing_context)
                results['compliance'] = compliance_result
                results['actions_taken'].append('compliance_artifacts_generated')

            return results

        except Exception as e:
            raise AMLProcessingError(f"Failed to process final assessment: {str(e)}")

    def _store_assessment(self, assessment: FinalRiskAssessment,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        """Store assessment trong appropriate DynamoDB table"""
        try:
            # Determine primary table based on risk level
            if assessment.risk_level == RiskLevel.CRITICAL:
                primary_table_name = self.table_names['critical_cases']
                status = 'CRITICAL_REVIEW_PENDING'
            elif assessment.risk_level == RiskLevel.HIGH:
                primary_table_name = self.table_names['high_risk_cases']
                status = 'HIGH_RISK_REVIEW_PENDING'
            elif assessment.risk_level == RiskLevel.MEDIUM:
                primary_table_name = self.table_names['medium_risk_cases']
                status = 'MEDIUM_RISK_QUEUE'
            else:
                primary_table_name = self.table_names['all_cases']
                status = 'CLEARED'

            # Prepare item for storage
            item = self._prepare_storage_item(assessment, context, status)

            # Store in primary table
            primary_table = self.dynamodb.Table(primary_table_name)
            primary_table.put_item(Item=item)

            # Also store in all_cases table for comprehensive tracking
            if primary_table_name != self.table_names['all_cases']:
                all_cases_table = self.dynamodb.Table(self.table_names['all_cases'])
                all_cases_item = item.copy()
                all_cases_item['primary_table'] = primary_table_name
                all_cases_table.put_item(Item=all_cases_item)

            return {
                'success': True,
                'primary_table': primary_table_name,
                'case_id': assessment.case_metadata['case_id'],
                'status': status
            }

        except Exception as e:
            print(f"Error storing assessment: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _prepare_storage_item(self, assessment: FinalRiskAssessment,
                              context: Dict[str, Any], status: str) -> Dict[str, Any]:
        """Prepare item for DynamoDB storage"""

        # Calculate TTL (30 days for low risk, 1 year for high risk)
        if assessment.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            ttl_days = 365
        elif assessment.risk_level == RiskLevel.MEDIUM:
            ttl_days = 180
        else:
            ttl_days = 30

        ttl_timestamp = int((datetime.utcnow() + timedelta(days=ttl_days)).timestamp())

        item = {
            'case_id': assessment.case_metadata['case_id'],
            'timestamp': datetime.utcnow().isoformat(),
            'final_score': assessment.final_score,
            'risk_level': assessment.risk_level.value,
            'confidence_level': assessment.confidence_level.value,
            'status': status,
            'requires_manual_review': assessment.requires_manual_review,
            'score_discord': assessment.score_discord,
            'weighting_strategy': assessment.weighting_strategy,

            # Rule-based component
            'rule_based_score': assessment.rule_based_component['base_score'],
            'rule_confidence': assessment.rule_based_component['confidence'],
            'triggered_rules': assessment.rule_based_component['triggered_rules'],
            'triggered_rules_count': len(assessment.rule_based_component['triggered_rules']),

            # AI component
            'ai_enhanced_score': assessment.ai_enhanced_component['contextual_score'],
            'ai_confidence_adjustment': assessment.ai_enhanced_component['confidence_adjustment'],
            'ai_risk_indicators_count': len(assessment.ai_enhanced_component['risk_indicators']),
            'ai_processing_time_ms': assessment.ai_enhanced_component['processing_time_ms'],

            # Metadata
            'case_type': assessment.case_metadata['case_type'],
            'complexity': assessment.case_metadata['complexity'],
            'urgency': assessment.case_metadata['urgency'],
            'data_quality_score': assessment.case_metadata.get('data_quality_score', 0),
            'source_bucket': assessment.case_metadata.get('source_bucket'),
            'source_key': assessment.case_metadata.get('source_key'),

            # Processing context
            'request_id': context.get('request_id'),
            'function_name': context.get('function_name'),
            'processing_time_seconds': (datetime.utcnow() - context['start_time']).total_seconds(),

            # Detailed data (stored as JSON strings for complex objects)
            'rule_breakdown': json.dumps(assessment.rule_based_component['rule_breakdown']),
            'ai_risk_indicators': json.dumps(assessment.ai_enhanced_component['risk_indicators']),
            'recommended_actions': assessment.recommended_actions,
            'reconciliation_explanation': assessment.reconciliation_explanation,

            # TTL
            'ttl': ttl_timestamp
        }

        # Add narrative explanation if not too long
        narrative = assessment.ai_enhanced_component['narrative_explanation']
        if len(narrative) <= 4000:  # DynamoDB item size limit consideration
            item['ai_narrative_explanation'] = narrative
        else:
            item['ai_narrative_explanation'] = narrative[:4000] + "... [TRUNCATED]"

        return item

    def _send_risk_alerts(self, assessment: FinalRiskAssessment,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        """Send alerts based on risk level"""
        alerts_sent = 0
        alert_results = []

        try:
            # Determine alert configuration
            alert_config = self._get_alert_config(assessment.risk_level)

            if not alert_config['send_alert']:
                return {
                    'alerts_sent': 0,
                    'message': 'No alerts required for this risk level'
                }

            # Prepare alert message
            alert_message = self._prepare_alert_message(assessment, context)

            # Send to appropriate SNS topic
            topic_arn = alert_config['topic_arn']
            if topic_arn:
                try:
                    response = self.sns_client.publish(
                        TopicArn=topic_arn,
                        Message=alert_message['body'],
                        Subject=alert_message['subject'],
                        MessageAttributes={
                            'RiskLevel': {
                                'DataType': 'String',
                                'StringValue': assessment.risk_level.value
                            },
                            'FinalScore': {
                                'DataType': 'Number',
                                'StringValue': str(assessment.final_score)
                            },
                            'CaseId': {
                                'DataType': 'String',
                                'StringValue': assessment.case_metadata['case_id']
                            },
                            'RequiresManualReview': {
                                'DataType': 'String',
                                'StringValue': str(assessment.requires_manual_review)
                            }
                        }
                    )

                    alerts_sent += 1
                    alert_results.append({
                        'topic': topic_arn,
                        'message_id': response['MessageId'],
                        'success': True
                    })

                except Exception as e:
                    alert_results.append({
                        'topic': topic_arn,
                        'error': str(e),
                        'success': False
                    })

            # For critical cases, send to multiple channels
            if assessment.risk_level == RiskLevel.CRITICAL:
                # Send to high risk topic as well for redundancy
                high_risk_topic = self.sns_topics.get('high_risk_alerts')
                if high_risk_topic and high_risk_topic != topic_arn:
                    try:
                        redundant_message = alert_message.copy()
                        redundant_message['subject'] = f"[REDUNDANT] {redundant_message['subject']}"

                        self.sns_client.publish(
                            TopicArn=high_risk_topic,
                            Message=redundant_message['body'],
                            Subject=redundant_message['subject']
                        )
                        alerts_sent += 1

                    except Exception as e:
                        print(f"Failed to send redundant alert: {e}")

            return {
                'alerts_sent': alerts_sent,
                'alert_results': alert_results,
                'primary_topic': topic_arn
            }

        except Exception as e:
            return {
                'alerts_sent': 0,
                'error': str(e),
                'alert_results': []
            }

    def _get_alert_config(self, risk_level: RiskLevel) -> Dict[str, Any]:
        """Get alert configuration for risk level"""
        if risk_level == RiskLevel.CRITICAL:
            return {
                'send_alert': True,
                'topic_arn': self.sns_topics.get('critical_alerts'),
                'urgency': 'IMMEDIATE',
                'escalation_time_minutes': 15
            }
        elif risk_level == RiskLevel.HIGH:
            return {
                'send_alert': True,
                'topic_arn': self.sns_topics.get('high_risk_alerts'),
                'urgency': 'HIGH',
                'escalation_time_minutes': 60
            }
        elif risk_level == RiskLevel.MEDIUM:
            return {
                'send_alert': self.config.get('alert_on_medium_risk', False),
                'topic_arn': self.sns_topics.get('medium_risk_alerts'),
                'urgency': 'MEDIUM',
                'escalation_time_minutes': 240
            }
        else:
            return {
                'send_alert': False,
                'topic_arn': None,
                'urgency': 'LOW',
                'escalation_time_minutes': 1440
            }

    def _prepare_alert_message(self, assessment: FinalRiskAssessment,
                               context: Dict[str, Any]) -> Dict[str, str]:
        """Prepare alert message content"""
        case_id = assessment.case_metadata['case_id']
        risk_level = assessment.risk_level.value
        final_score = assessment.final_score

        # Subject line
        subject = f"{risk_level} Risk AML Case Detected: {case_id} (Score: {final_score:.1f})"

        if assessment.requires_manual_review:
            subject += " [MANUAL REVIEW REQUIRED]"

        # Message body
        body_parts = [
            f"AML RISK ALERT - {risk_level} PRIORITY",
            f"",
            f"Case ID: {case_id}",
            f"Final Risk Score: {final_score:.1f}/100",
            f"Risk Level: {risk_level}",
            f"Confidence Level: {assessment.confidence_level.value}",
            f"Manual Review Required: {'YES' if assessment.requires_manual_review else 'NO'}",
            f"",
            f"CASE DETAILS:",
            f"Case Type: {assessment.case_metadata['case_type']}",
            f"Complexity: {assessment.case_metadata['complexity']}",
            f"Urgency: {assessment.case_metadata['urgency']}",
            f"Score Discord: {assessment.score_discord:.1f} points",
            f"Weighting Strategy: {assessment.weighting_strategy}",
            f"",
            f"COMPONENT SCORES:",
            f"Rule-based: {assessment.rule_based_component['base_score']:.1f}/100",
            f"AI-enhanced: {assessment.ai_enhanced_component['contextual_score']:.1f}/100",
            f"",
            f"TOP TRIGGERED RULES:",
        ]

        # Add top triggered rules
        rule_breakdown = assessment.rule_based_component['rule_breakdown']
        if rule_breakdown:
            top_rules = sorted(rule_breakdown.items(), key=lambda x: x[1], reverse=True)[:5]
            for rule_name, score in top_rules:
                body_parts.append(f"• {rule_name}: +{score:.1f} points")
        else:
            body_parts.append("• No rules triggered")

        body_parts.extend([
            f"",
            f"AI RISK INDICATORS: {len(assessment.ai_enhanced_component['risk_indicators'])}",
            f"",
            f"RECOMMENDED ACTIONS:",
        ])

        # Add top recommended actions
        for i, action in enumerate(assessment.recommended_actions[:5], 1):
            body_parts.append(f"{i}. {action}")

        body_parts.extend([
            f"",
            f"PROCESSING INFO:",
            f"Request ID: {context.get('request_id', 'Unknown')}",
            f"Processed At: {datetime.utcnow().isoformat()}",
            f"Source: {assessment.case_metadata.get('source_bucket', 'Unknown')}",
            f"",
            f"This alert was automatically generated by the AML Hybrid Risk Scoring System."
        ])

        return {
            'subject': subject,
            'body': '\n'.join(body_parts)
        }

    def _schedule_manual_review(self, assessment: FinalRiskAssessment,
                                context: Dict[str, Any]) -> Dict[str, Any]:
        """Schedule manual review for cases that require it"""
        try:
            # Store manual review request
            review_table = self.dynamodb.Table('aml-manual-review-queue')

            review_item = {
                'review_id': f"{assessment.case_metadata['case_id']}_{int(datetime.utcnow().timestamp())}",
                'case_id': assessment.case_metadata['case_id'],
                'timestamp': datetime.utcnow().isoformat(),
                'priority': self._determine_review_priority(assessment),
                'status': 'PENDING',
                'assigned_to': None,
                'review_reason': self._determine_review_reason(assessment),
                'final_score': assessment.final_score,
                'risk_level': assessment.risk_level.value,
                'score_discord': assessment.score_discord,
                'rule_based_score': assessment.rule_based_component['base_score'],
                'ai_enhanced_score': assessment.ai_enhanced_component['contextual_score'],
                'case_summary': assessment.ai_enhanced_component['narrative_explanation'][:500],
                'recommended_actions': assessment.recommended_actions[:5],
                'due_date': (datetime.utcnow() + timedelta(hours=self._get_review_sla_hours(assessment))).isoformat(),
                'source_data': {
                    'bucket': assessment.case_metadata.get('source_bucket'),
                    'key': assessment.case_metadata.get('source_key')
                }
            }

            review_table.put_item(Item=review_item)

            return {
                'success': True,
                'review_id': review_item['review_id'],
                'priority': review_item['priority'],
                'due_date': review_item['due_date']
            }

        except Exception as e:
            print(f"Error scheduling manual review: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _determine_review_priority(self, assessment: FinalRiskAssessment) -> str:
        """Determine priority for manual review"""
        if assessment.risk_level == RiskLevel.CRITICAL:
            return 'URGENT'
        elif assessment.risk_level == RiskLevel.HIGH:
            return 'HIGH'
        elif assessment.score_discord > 25:
            return 'HIGH'  # High discord cases need urgent review
        elif assessment.confidence_level.value == 'LOW':
            return 'MEDIUM'
        else:
            return 'NORMAL'

    def _determine_review_reason(self, assessment: FinalRiskAssessment) -> str:
        """Determine reason for manual review"""
        reasons = []

        if assessment.score_discord > self.config.get('score_discord_threshold', 15):
            reasons.append(f"High score discord ({assessment.score_discord:.1f} points)")

        if assessment.confidence_level.value == 'LOW':
            reasons.append("Low confidence assessment")

        if assessment.risk_level == RiskLevel.CRITICAL:
            reasons.append("Critical risk level")

        if assessment.case_metadata['case_type'] == 'SANCTIONS':
            reasons.append("Sanctions case requiring verification")

        if not reasons:
            reasons.append("System-flagged for review")

        return "; ".join(reasons)

    def _get_review_sla_hours(self, assessment: FinalRiskAssessment) -> int:
        """Get SLA hours for manual review"""
        if assessment.risk_level == RiskLevel.CRITICAL:
            return 4  # 4 hours
        elif assessment.risk_level == RiskLevel.HIGH:
            return 24  # 24 hours
        elif assessment.score_discord > 25:
            return 12  # High discord needs faster review
        else:
            return 72  # 3 days

    def _update_processing_metrics(self, assessment: FinalRiskAssessment,
                                   context: Dict[str, Any]):
        """Update CloudWatch metrics"""
        try:
            cloudwatch = boto3.client('cloudwatch')

            processing_time = (datetime.utcnow() - context['start_time']).total_seconds()

            metrics = [
                {
                    'MetricName': 'ProcessingTimeSeconds',
                    'Value': processing_time,
                    'Unit': 'Seconds',
                    'Dimensions': [
                        {'Name': 'RiskLevel', 'Value': assessment.risk_level.value},
                        {'Name': 'CaseType', 'Value': assessment.case_metadata['case_type']}
                    ]
                },
                {
                    'MetricName': 'FinalRiskScore',
                    'Value': assessment.final_score,
                    'Unit': 'None',
                    'Dimensions': [
                        {'Name': 'RiskLevel', 'Value': assessment.risk_level.value}
                    ]
                },
                {
                    'MetricName': 'ScoreDiscord',
                    'Value': assessment.score_discord,
                    'Unit': 'None',
                    'Dimensions': [
                        {'Name': 'WeightingStrategy', 'Value': assessment.weighting_strategy}
                    ]
                },
                {
                    'MetricName': 'CasesProcessed',
                    'Value': 1,
                    'Unit': 'Count',
                    'Dimensions': [
                        {'Name': 'RiskLevel', 'Value': assessment.risk_level.value},
                        {'Name': 'ManualReviewRequired', 'Value': str(assessment.requires_manual_review)}
                    ]
                }
            ]

            # Add confidence level metric
            confidence_values = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
            metrics.append({
                'MetricName': 'ConfidenceLevel',
                'Value': confidence_values[assessment.confidence_level.value],
                'Unit': 'None',
                'Dimensions': [
                    {'Name': 'RiskLevel', 'Value': assessment.risk_level.value}
                ]
            })

            # AI processing time metric
            if assessment.ai_enhanced_component['processing_time_ms'] > 0:
                metrics.append({
                    'MetricName': 'AIProcessingTimeMs',
                    'Value': assessment.ai_enhanced_component['processing_time_ms'],
                    'Unit': 'Milliseconds'
                })

            cloudwatch.put_metric_data(
                Namespace='AML/HybridScoring',
                MetricData=metrics
            )

        except Exception as e:
            print(f"Failed to update CloudWatch metrics: {e}")

    def _generate_compliance_artifacts(self, assessment: FinalRiskAssessment,
                                       context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance artifacts for high-risk cases"""
        try:
            # Create compliance report
            compliance_report = self._create_compliance_report(assessment, context)

            # Store in S3 for audit trail
            s3_client = boto3.client('s3')
            compliance_bucket = self.config.get('compliance_bucket', 'aml-compliance-reports')

            # Generate S3 key
            case_id = assessment.case_metadata['case_id']
            timestamp = datetime.utcnow().strftime('%Y/%m/%d')
            risk_level = assessment.risk_level.value.lower()

            s3_key = f"compliance-reports/{timestamp}/{risk_level}/{case_id}_compliance_report.json"

            # Upload to S3
            s3_client.put_object(
                Bucket=compliance_bucket,
                Key=s3_key,
                Body=json.dumps(compliance_report, indent=2),
                ContentType='application/json',
                Metadata={
                    'case-id': case_id,
                    'risk-level': assessment.risk_level.value,
                    'final-score': str(assessment.final_score),
                    'generated-by': 'aml-hybrid-scoring-system'
                }
            )

            return {
                'success': True,
                'compliance_report_s3_uri': f"s3://{compliance_bucket}/{s3_key}",
                'report_size_bytes': len(json.dumps(compliance_report))
            }

        except Exception as e:
            print(f"Error generating compliance artifacts: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _create_compliance_report(self, assessment: FinalRiskAssessment,
                                  context: Dict[str, Any]) -> Dict[str, Any]:
        """Create detailed compliance report"""
        return {
            'report_metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'report_version': '1.0',
                'system_version': 'hybrid-scoring-v1.0',
                'request_id': context.get('request_id'),
                'compliance_standard': 'BSA/AML'
            },

            'case_information': {
                'case_id': assessment.case_metadata['case_id'],
                'case_type': assessment.case_metadata['case_type'],
                'complexity': assessment.case_metadata['complexity'],
                'urgency': assessment.case_metadata['urgency'],
                'source_data': {
                    'bucket': assessment.case_metadata.get('source_bucket'),
                    'key': assessment.case_metadata.get('source_key'),
                    'data_quality_score': assessment.case_metadata.get('data_quality_score')
                }
            },

            'risk_assessment': {
                'final_score': assessment.final_score,
                'risk_level': assessment.risk_level.value,
                'confidence_level': assessment.confidence_level.value,
                'requires_manual_review': assessment.requires_manual_review,
                'assessment_methodology': 'Hybrid Rule-based and AI-enhanced scoring'
            },

            'scoring_details': {
                'rule_based_component': {
                    'score': assessment.rule_based_component['base_score'],
                    'confidence': assessment.rule_based_component['confidence'],
                    'triggered_rules': assessment.rule_based_component['triggered_rules'],
                    'rule_breakdown': assessment.rule_based_component['rule_breakdown']
                },
                'ai_enhanced_component': {
                    'score': assessment.ai_enhanced_component['contextual_score'],
                    'confidence_adjustment': assessment.ai_enhanced_component['confidence_adjustment'],
                    'risk_indicators_count': len(assessment.ai_enhanced_component['risk_indicators']),
                    'processing_time_ms': assessment.ai_enhanced_component['processing_time_ms']
                },
                'reconciliation': {
                    'score_discord': assessment.score_discord,
                    'weighting_strategy': assessment.weighting_strategy,
                    'explanation': assessment.reconciliation_explanation
                }
            },

            'recommendations': {
                'immediate_actions': assessment.recommended_actions,
                'regulatory_considerations': self._get_regulatory_considerations(assessment),
                'escalation_requirements': self._get_escalation_requirements(assessment)
            },

            'audit_trail': {
                'processing_timestamp': context.get('start_time', datetime.utcnow()).isoformat(),
                'processing_duration_seconds': (
                            datetime.utcnow() - context.get('start_time', datetime.utcnow())).total_seconds(),
                'function_name': context.get('function_name'),
                'aws_request_id': context.get('request_id')
            }
        }

    def _get_regulatory_considerations(self, assessment: FinalRiskAssessment) -> List[str]:
        """Get regulatory considerations based on assessment"""
        considerations = []

        if assessment.risk_level == RiskLevel.CRITICAL:
            considerations.extend([
                "Consider filing Suspicious Activity Report (SAR)",
                "Immediate senior management notification required",
                "Document all investigative steps for regulatory examination"
            ])

        if assessment.risk_level == RiskLevel.HIGH:
            considerations.extend([
                "Enhanced due diligence recommended",
                "Consider customer risk rating update",
                "Monitor for ongoing suspicious activity"
            ])

        if assessment.case_metadata['case_type'] == 'SANCTIONS':
            considerations.extend([
                "OFAC compliance verification required",
                "Consider account blocking pending investigation",
                "Report to appropriate regulatory authorities"
            ])

        if assessment.requires_manual_review:
            considerations.append("Manual analyst review required before final determination")

        return considerations

    def _get_escalation_requirements(self, assessment: FinalRiskAssessment) -> Dict[str, Any]:
        """Get escalation requirements"""
        if assessment.risk_level == RiskLevel.CRITICAL:
            return {
                'immediate_escalation': True,
                'escalation_level': 'Senior Compliance Officer',
                'time_limit_hours': 2,
                'notification_required': True
            }
        elif assessment.risk_level == RiskLevel.HIGH:
            return {
                'immediate_escalation': False,
                'escalation_level': 'AML Manager',
                'time_limit_hours': 24,
                'notification_required': True
            }
        else:
            return {
                'immediate_escalation': False,
                'escalation_level': 'AML Analyst',
                'time_limit_hours': 72,
                'notification_required': False
            }

    def get_processing_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Get summary of processing results"""
        return {
            'case_id': results['case_id'],
            'final_score': results['final_score'],
            'risk_level': results['risk_level'],
            'actions_taken': results['actions_taken'],
            'alerts_sent': results.get('alerts', {}).get('alerts_sent', 0),
            'manual_review_scheduled': 'manual_review_scheduled' in results['actions_taken'],
            'compliance_artifacts_generated': 'compliance_artifacts_generated' in results['actions_taken'],
            'storage_successful': results.get('storage', {}).get('success', False),
            'processing_timestamp': results['processing_timestamp']
        }