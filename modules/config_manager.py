"""
Configuration Manager Module
Quản lý cấu hình cho Hybrid Risk Scoring System
"""

import os
import json
import boto3
from typing import Dict, Any, Optional
from modules.exceptions import ConfigurationError


class ConfigManager:
    """Configuration manager cho AML Hybrid Scoring"""

    def __init__(self):
        self.environment = os.environ.get('ENVIRONMENT', 'dev')
        self.ssm_client = boto3.client('ssm')
        self.parameter_prefix = f"/aml/hybrid-scoring/{self.environment}"

        # Cache cho configuration
        self._config_cache = None
        self._default_config = self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values"""
        return {
            # Scoring weights
            'rule_based_weight': 0.6,
            'ai_enhanced_weight': 0.4,

            # Confidence thresholds
            'high_confidence_threshold': 0.8,
            'medium_confidence_threshold': 0.6,

            # Risk thresholds
            'critical_risk_threshold': 80.0,
            'high_risk_threshold': 60.0,
            'medium_risk_threshold': 30.0,

            # Discord threshold
            'score_discord_threshold': 15.0,

            # Bedrock configuration
            'bedrock_model_id': 'anthropic.claude-3-sonnet-20240229-v1:0',
            'bedrock_max_tokens': 2048,
            'bedrock_temperature': 0.1,
            'bedrock_timeout_seconds': 30,

            # Fallback settings
            'bedrock_fallback_enabled': True,
            'fallback_confidence_penalty': 0.2,

            # Processing settings
            'enable_performance_monitoring': True,
            'enable_detailed_logging': True,
            'alert_on_high_discord': True,

            # Table names
            'critical_cases_table': 'aml-critical-cases',
            'high_risk_cases_table': 'aml-high-risk-cases',
            'medium_risk_cases_table': 'aml-medium-risk-cases',
            'all_cases_table': 'aml-all-cases',
            'processing_errors_table': 'aml-processing-errors',

            # SNS topics
            'critical_alerts_topic': 'arn:aws:sns:region:account:aml-critical-alerts',
            'high_risk_alerts_topic': 'arn:aws:sns:region:account:aml-high-risk-alerts',
            'medium_risk_alerts_topic': 'arn:aws:sns:region:account:aml-medium-risk-alerts'
        }

    def get_config_for_case(self, case_type: str = None) -> Dict[str, Any]:
        """Get configuration for a specific case type"""
        try:
            # Load base config
            base_config = self._load_configuration()

            # Apply case-specific adjustments if provided
            if case_type:
                case_adjustments = self._get_case_type_adjustments(case_type)
                base_config.update(case_adjustments)

            return base_config

        except Exception as e:
            print(f"Failed to load configuration, using defaults: {e}")
            return self._default_config

    def _load_configuration(self) -> Dict[str, Any]:
        """Load configuration từ Parameter Store hoặc cache"""
        if self._config_cache is not None:
            return self._config_cache

        try:
            # Load từ AWS Parameter Store
            config = self._load_from_parameter_store()

            # Validate configuration
            validated_config = self._validate_and_merge_config(config)

            # Cache configuration
            self._config_cache = validated_config

            return validated_config

        except Exception as e:
            print(f"Error loading configuration from Parameter Store: {e}")
            return self._default_config

    def _load_from_parameter_store(self) -> Dict[str, Any]:
        """Load configuration từ AWS Systems Manager Parameter Store"""
        config = {}

        try:
            # Get all parameters with pagination
            paginator = self.ssm_client.get_paginator('get_parameters_by_path')

            for page in paginator.paginate(
                    Path=self.parameter_prefix,
                    Recursive=True,
                    WithDecryption=True
            ):
                for param in page['Parameters']:
                    # Remove prefix to get parameter name
                    param_name = param['Name'].replace(f"{self.parameter_prefix}/", "")
                    param_value = param['Value']

                    # Convert to appropriate type
                    config[param_name] = self._convert_parameter_value(param_name, param_value)

            return config

        except self.ssm_client.exceptions.ParameterNotFound:
            print(f"No parameters found at path: {self.parameter_prefix}")
            return {}
        except Exception as e:
            raise ConfigurationError(f"Failed to load from Parameter Store: {str(e)}")

    def _convert_parameter_value(self, param_name: str, param_value: str) -> Any:
        """Convert parameter value to appropriate type"""

        # Float parameters
        float_params = [
            'rule_based_weight', 'ai_enhanced_weight',
            'high_confidence_threshold', 'medium_confidence_threshold',
            'critical_risk_threshold', 'high_risk_threshold', 'medium_risk_threshold',
            'score_discord_threshold', 'bedrock_temperature', 'fallback_confidence_penalty'
        ]

        # Integer parameters
        int_params = [
            'bedrock_max_tokens', 'bedrock_timeout_seconds'
        ]

        # Boolean parameters
        bool_params = [
            'bedrock_fallback_enabled', 'enable_performance_monitoring',
            'enable_detailed_logging', 'alert_on_high_discord'
        ]

        try:
            if param_name in float_params:
                return float(param_value)
            elif param_name in int_params:
                return int(param_value)
            elif param_name in bool_params:
                return param_value.lower() in ['true', '1', 'yes', 'on']
            else:
                # Try to parse as JSON first, fallback to string
                try:
                    return json.loads(param_value)
                except json.JSONDecodeError:
                    return param_value

        except ValueError as e:
            print(f"Error converting parameter {param_name}: {e}")
            return param_value

    def _validate_and_merge_config(self, loaded_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate và merge với default configuration"""
        # Start with defaults
        final_config = self._default_config.copy()

        # Override with loaded configuration
        final_config.update(loaded_config)

        # Validate critical values
        validation_errors = []

        # Validate weights sum to 1.0
        rule_weight = final_config['rule_based_weight']
        ai_weight = final_config['ai_enhanced_weight']
        if abs((rule_weight + ai_weight) - 1.0) > 0.01:
            print(f"Warning: Weights don't sum to 1.0, normalizing. Rule: {rule_weight}, AI: {ai_weight}")
            total = rule_weight + ai_weight
            final_config['rule_based_weight'] = rule_weight / total
            final_config['ai_enhanced_weight'] = ai_weight / total

        # Validate thresholds
        if final_config['critical_risk_threshold'] <= final_config['high_risk_threshold']:
            validation_errors.append("Critical threshold must be higher than high threshold")

        if final_config['high_risk_threshold'] <= final_config['medium_risk_threshold']:
            validation_errors.append("High threshold must be higher than medium threshold")

        # Validate confidence thresholds
        if final_config['high_confidence_threshold'] <= final_config['medium_confidence_threshold']:
            validation_errors.append("High confidence threshold must be higher than medium")

        # Validate Bedrock settings
        if final_config['bedrock_temperature'] < 0 or final_config['bedrock_temperature'] > 1:
            validation_errors.append("Bedrock temperature must be between 0 and 1")

        if final_config['bedrock_max_tokens'] < 256:
            validation_errors.append("Bedrock max_tokens should be at least 256")

        if validation_errors:
            error_message = "; ".join(validation_errors)
            raise ConfigurationError(f"Configuration validation failed: {error_message}")

        return final_config

    def _get_case_type_adjustments(self, case_type: str) -> Dict[str, Any]:
        """Get case-type specific configuration adjustments"""
        adjustments = {}

        case_type = case_type.upper()

        if case_type == 'SANCTIONS':
            # Sanctions cases prioritize rules heavily
            adjustments.update({
                'rule_based_weight': 0.8,
                'ai_enhanced_weight': 0.2,
                'critical_risk_threshold': 70.0,  # Lower threshold
                'bedrock_temperature': 0.05  # More conservative AI
            })

        elif case_type == 'ORGANIZED_CRIME':
            # Complex cases benefit from AI analysis
            adjustments.update({
                'rule_based_weight': 0.5,
                'ai_enhanced_weight': 0.5,
                'bedrock_max_tokens': 3072,  # More tokens for complex analysis
                'score_discord_threshold': 20.0  # Allow more discord
            })

        elif case_type == 'MONEY_LAUNDERING':
            # Balanced approach for ML
            adjustments.update({
                'rule_based_weight': 0.55,
                'ai_enhanced_weight': 0.45
            })

        elif case_type == 'FRAUD':
            # Fraud benefits from AI pattern recognition
            adjustments.update({
                'rule_based_weight': 0.4,
                'ai_enhanced_weight': 0.6,
                'bedrock_temperature': 0.15  # Slightly more creative AI
            })

        elif case_type == 'RACKETEERING':
            # Complex organized crime
            adjustments.update({
                'rule_based_weight': 0.5,
                'ai_enhanced_weight': 0.5,
                'high_risk_threshold': 50.0  # Lower threshold for racketeering
            })

        return adjustments

    def update_configuration(self, updates: Dict[str, Any]) -> bool:
        """Update configuration in Parameter Store"""
        try:
            for param_name, param_value in updates.items():
                parameter_path = f"{self.parameter_prefix}/{param_name}"

                # Convert value to string
                if isinstance(param_value, (dict, list)):
                    string_value = json.dumps(param_value)
                else:
                    string_value = str(param_value)

                # Update in Parameter Store
                self.ssm_client.put_parameter(
                    Name=parameter_path,
                    Value=string_value,
                    Type='String',
                    Overwrite=True,
                    Description=f"AML Hybrid Scoring configuration - {param_name}"
                )

            # Clear cache to force reload
            self._config_cache = None

            print(f"Successfully updated {len(updates)} configuration parameters")
            return True

        except Exception as e:
            print(f"Failed to update configuration: {e}")
            return False

    def get_table_names(self) -> Dict[str, str]:
        """Get DynamoDB table names"""
        config = self.get_config_for_case()
        return {
            'critical_cases': config['critical_cases_table'],
            'high_risk_cases': config['high_risk_cases_table'],
            'medium_risk_cases': config['medium_risk_cases_table'],
            'all_cases': config['all_cases_table'],
            'processing_errors': config['processing_errors_table']
        }

    def get_sns_topics(self) -> Dict[str, str]:
        """Get SNS topic ARNs"""
        config = self.get_config_for_case()
        return {
            'critical_alerts': config['critical_alerts_topic'],
            'high_risk_alerts': config['high_risk_alerts_topic'],
            'medium_risk_alerts': config['medium_risk_alerts_topic']
        }

    def get_bedrock_config(self, case_complexity: str = 'medium') -> Dict[str, Any]:
        """Get Bedrock-specific configuration"""
        config = self.get_config_for_case()

        bedrock_config = {
            'model_id': config['bedrock_model_id'],
            'max_tokens': config['bedrock_max_tokens'],
            'temperature': config['bedrock_temperature'],
            'timeout_seconds': config['bedrock_timeout_seconds'],
            'fallback_enabled': config['bedrock_fallback_enabled']
        }

        # Adjust based on complexity
        if case_complexity == 'high':
            bedrock_config['max_tokens'] = min(4096, bedrock_config['max_tokens'] * 1.5)
            bedrock_config['temperature'] = max(0.05, bedrock_config['temperature'] - 0.05)
        elif case_complexity == 'low':
            bedrock_config['max_tokens'] = max(1024, bedrock_config['max_tokens'] // 2)

        return bedrock_config

    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring and alerting configuration"""
        config = self.get_config_for_case()
        return {
            'performance_monitoring_enabled': config['enable_performance_monitoring'],
            'detailed_logging_enabled': config['enable_detailed_logging'],
            'alert_on_high_discord': config['alert_on_high_discord'],
            'discord_threshold': config['score_discord_threshold']
        }

    def validate_environment_setup(self) -> Dict[str, Any]:
        """Validate entire environment setup"""
        validation_results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'environment': self.environment
        }

        try:
            # Test Parameter Store access
            try:
                config = self._load_configuration()
                validation_results['parameter_store'] = 'OK'
            except Exception as e:
                validation_results['errors'].append(f"Parameter Store access failed: {e}")
                validation_results['valid'] = False
                validation_results['parameter_store'] = 'FAILED'

            # Test DynamoDB table access
            dynamodb = boto3.resource('dynamodb')
            table_names = self.get_table_names()

            for table_purpose, table_name in table_names.items():
                try:
                    table = dynamodb.Table(table_name)
                    table.load()
                    validation_results[f'table_{table_purpose}'] = 'OK'
                except Exception as e:
                    validation_results['warnings'].append(f"Table {table_name} not accessible: {e}")
                    validation_results[f'table_{table_purpose}'] = 'WARNING'

            # Test SNS topics
            sns = boto3.client('sns')
            sns_topics = self.get_sns_topics()

            for topic_purpose, topic_arn in sns_topics.items():
                try:
                    sns.get_topic_attributes(TopicArn=topic_arn)
                    validation_results[f'sns_{topic_purpose}'] = 'OK'
                except Exception as e:
                    validation_results['warnings'].append(f"SNS topic {topic_arn} not accessible: {e}")
                    validation_results[f'sns_{topic_purpose}'] = 'WARNING'

            # Test Bedrock access
            try:
                bedrock = boto3.client('bedrock-runtime')
                bedrock_config = self.get_bedrock_config()

                # Try a simple test call
                test_payload = {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Test"}]
                }

                bedrock.invoke_model(
                    body=json.dumps(test_payload),
                    modelId=bedrock_config['model_id'],
                    accept="application/json",
                    contentType="application/json"
                )

                validation_results['bedrock'] = 'OK'

            except Exception as e:
                validation_results['warnings'].append(f"Bedrock access issue: {e}")
                validation_results['bedrock'] = 'WARNING'

            # Check configuration consistency
            config_validation = self._validate_configuration_consistency()
            validation_results.update(config_validation)

        except Exception as e:
            validation_results['errors'].append(f"Environment validation failed: {e}")
            validation_results['valid'] = False

        return validation_results

    def _validate_configuration_consistency(self) -> Dict[str, Any]:
        """Validate configuration for internal consistency"""
        results = {
            'config_consistency': 'OK',
            'config_warnings': []
        }

        config = self.get_config_for_case()

        # Check weight consistency
        total_weight = config['rule_based_weight'] + config['ai_enhanced_weight']
        if abs(total_weight - 1.0) > 0.01:
            results['config_warnings'].append(f"Weights don't sum to 1.0: {total_weight}")

        # Check threshold ordering
        if config['critical_risk_threshold'] <= config['high_risk_threshold']:
            results['config_warnings'].append("Risk thresholds not properly ordered")

        # Check reasonable values
        if config['score_discord_threshold'] > 50:
            results['config_warnings'].append("Very high discord threshold may miss important disagreements")

        if config['bedrock_max_tokens'] > 4096:
            results['config_warnings'].append("Very high max_tokens may increase costs significantly")

        if results['config_warnings']:
            results['config_consistency'] = 'WARNING'

        return results

    def export_configuration(self) -> Dict[str, Any]:
        """Export current configuration for backup/review"""
        config = self.get_config_for_case()

        return {
            'environment': self.environment,
            'export_timestamp': boto3.Session().region_name,  # Placeholder for timestamp
            'configuration': config,
            'parameter_prefix': self.parameter_prefix
        }

    def clear_cache(self):
        """Clear configuration cache"""
        self._config_cache = None

    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get a summary of current configuration"""
        config = self.get_config_for_case()

        return {
            'environment': self.environment,
            'scoring_weights': {
                'rule_based': config['rule_based_weight'],
                'ai_enhanced': config['ai_enhanced_weight']
            },
            'risk_thresholds': {
                'critical': config['critical_risk_threshold'],
                'high': config['high_risk_threshold'],
                'medium': config['medium_risk_threshold']
            },
            'bedrock_model': config['bedrock_model_id'],
            'discord_threshold': config['score_discord_threshold'],
            'fallback_enabled': config['bedrock_fallback_enabled'],
            'monitoring_enabled': config['enable_performance_monitoring']
        }


# Environment variable based configuration fallback
def get_env_config() -> Dict[str, Any]:
    """Get configuration from environment variables as fallback"""
    return {
        'rule_based_weight': float(os.environ.get('RULE_WEIGHT', '0.6')),
        'ai_enhanced_weight': float(os.environ.get('AI_WEIGHT', '0.4')),
        'critical_risk_threshold': float(os.environ.get('CRITICAL_THRESHOLD', '80.0')),
        'high_risk_threshold': float(os.environ.get('HIGH_THRESHOLD', '60.0')),
        'medium_risk_threshold': float(os.environ.get('MEDIUM_THRESHOLD', '30.0')),
        'score_discord_threshold': float(os.environ.get('DISCORD_THRESHOLD', '15.0')),
        'bedrock_model_id': os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0'),
        'bedrock_max_tokens': int(os.environ.get('BEDROCK_MAX_TOKENS', '2048')),
        'bedrock_temperature': float(os.environ.get('BEDROCK_TEMPERATURE', '0.1'))
    }