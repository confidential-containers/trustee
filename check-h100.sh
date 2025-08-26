#!/bin/bash
REGIONS=("us-east-1" "eu-west-1" "eu-central-1" "ap-northeast-1" "ap-southeast-2")

for region in "${REGIONS[@]}"; do
    echo "Checking $region..."
    
    # Get default VPC
    vpc=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --region $region --query 'Vpcs[0].VpcId' --output text 2>/dev/null)
    
    if [ "$vpc" != "None" ] && [ -n "$vpc" ]; then
        # Try to request p5 instance (dry-run)
        aws ec2 run-instances \
            --image-id ami-12345678 \
            --instance-type p5.48xlarge \
            --max-count 1 \
            --min-count 1 \
            --dry-run \
            --region $region 2>&1 | grep -E "(InsufficientInstanceCapacity|InvalidAMIID.NotFound)"
        
        if [[ $? -eq 0 ]]; then
            echo "✓ $region might have capacity (got past capacity check)"
        fi
    else
        echo "✗ $region - No default VPC"
    fi
    echo "---"
done
