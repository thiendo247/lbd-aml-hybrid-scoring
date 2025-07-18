# lbd-aml-hybrid-scoring

---
## Structure code

```
aml-hybrid-scoring/
├── lambda_function.py          # Main handler
├── modules/
│   ├── __init__.py
│   ├── data_processor.py       # NER data processing
│   ├── rule_engine.py          # Rule-based scoring
│   ├── bedrock_enhancer.py     # Bedrock AI enhancement
│   ├── score_reconciler.py     # Score reconciliation
│   ├── result_handler.py       # Result processing
│   ├── config_manager.py       # Configuration management
│   └── exceptions.py           # Custom exceptions
├── requirements.txt
├── serverless.yml
├── deploy.sh
├── Dockerfile
├── docker-compose.yml
└── Makefile
```