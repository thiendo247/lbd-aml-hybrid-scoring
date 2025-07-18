aws dynamodb create-table \
    --table-name aml-risk-scores \
    --attribute-definitions \
        AttributeName=pk,AttributeType=S \
        AttributeName=sk,AttributeType=S \
        AttributeName=risk_level,AttributeType=S \
        AttributeName=processed_date,AttributeType=S \
        AttributeName=total_risk_score,AttributeType=N \
    --key-schema \
        AttributeName=pk,KeyType=HASH \
        AttributeName=sk,KeyType=RANGE \
    --global-secondary-indexes \
        IndexName=RiskLevelIndex,KeySchema=[{AttributeName=risk_level,KeyType=HASH},{AttributeName=total_risk_score,KeyType=RANGE}],Projection={ProjectionType=ALL} \
        IndexName=DateIndex,KeySchema=[{AttributeName=processed_date,KeyType=HASH},{AttributeName=sk,KeyType=RANGE}],Projection={ProjectionType=ALL} \
    --billing-mode PAY_PER_REQUEST \
    --region ap-southeast-1