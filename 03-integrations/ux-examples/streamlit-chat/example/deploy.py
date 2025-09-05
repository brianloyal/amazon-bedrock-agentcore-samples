import json
import os
import sys
import time

import boto3
from bedrock_agentcore_starter_toolkit import Runtime
from boto3.session import Session


def create_agentcore_role(agent_name):
    iam_client = boto3.client("iam")
    agentcore_role_name = f"agentcore-{agent_name}-role"
    boto_session = Session()
    region = boto_session.region_name
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BedrockPermissions",
                "Effect": "Allow",
                "Action": [
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                ],
                "Resource": "*",
            },
            {
                "Sid": "ECRImageAccess",
                "Effect": "Allow",
                "Action": [
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                ],
                "Resource": [f"arn:aws:ecr:{region}:{account_id}:repository/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:DescribeLogStreams", "logs:CreateLogGroup"],
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:log-group:/aws/bedrock-agentcore/runtimes/*"
                ],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:DescribeLogGroups"],
                "Resource": [f"arn:aws:logs:{region}:{account_id}:log-group:*"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*"
                ],
            },
            {
                "Sid": "ECRTokenAccess",
                "Effect": "Allow",
                "Action": ["ecr:GetAuthorizationToken"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "xray:PutTraceSegments",
                    "xray:PutTelemetryRecords",
                    "xray:GetSamplingRules",
                    "xray:GetSamplingTargets",
                ],
                "Resource": ["*"],
            },
            {
                "Effect": "Allow",
                "Resource": "*",
                "Action": "cloudwatch:PutMetricData",
                "Condition": {
                    "StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}
                },
            },
            {
                "Sid": "GetAgentAccessToken",
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:GetWorkloadAccessToken",
                    "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                    "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                ],
                "Resource": [
                    f"arn:aws:bedrock-agentcore:{region}:{account_id}:workload-identity-directory/default",
                    f"arn:aws:bedrock-agentcore:{region}:{account_id}:workload-identity-directory/default/workload-identity/{agent_name}-*",
                ],
            },
            {
                "Sid": "CreateCodeBuildProject",
                "Effect": "Allow",
                "Action": [
                    "codebuild:BatchGetBuilds",
                    "codebuild:CreateProject",
                    "codebuild:StartBuild",
                    "codebuild:UpdateProject",
                ],
                "Resource": [
                    f"arn:aws:codebuild:{region}:{account_id}:project/bedrock-agentcore-*",
                    f"arn:aws:codebuild:{region}:{account_id}:build/bedrock-agentcore-*",
                ],
            },
            {
                "Sid": "SecretsManagerAccess",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:CreateSecret",
                    "secretsmanager:UpdateSecret",
                    "secretsmanager:TagResource",
                ],
                "Resource": [
                    f"arn:aws:secretsmanager:{region}:{account_id}:secret:agentcore-chat/cognito-config-*"
                ],
            },
        ],
    }
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeRolePolicy",
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": f"{account_id}"},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:bedrock-agentcore:{region}:{account_id}:*"
                    },
                },
            }
        ],
    }

    assume_role_policy_document_json = json.dumps(assume_role_policy_document)
    role_policy_document = json.dumps(role_policy)
    # Create IAM Role for the Lambda function
    try:
        agentcore_iam_role = iam_client.create_role(
            RoleName=agentcore_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document_json,
        )

        # Pause to make sure role is created
        time.sleep(10)
    except iam_client.exceptions.EntityAlreadyExistsException:
        print("Role already exists -- deleting and creating it again")
        policies = iam_client.list_role_policies(
            RoleName=agentcore_role_name, MaxItems=100
        )
        print("policies:", policies)
        for policy_name in policies["PolicyNames"]:
            iam_client.delete_role_policy(
                RoleName=agentcore_role_name, PolicyName=policy_name
            )
        print(f"deleting {agentcore_role_name}")
        iam_client.delete_role(RoleName=agentcore_role_name)
        print(f"recreating {agentcore_role_name}")
        agentcore_iam_role = iam_client.create_role(
            RoleName=agentcore_role_name,
            AssumeRolePolicyDocument=assume_role_policy_document_json,
        )

    # Attach the AWSLambdaBasicExecutionRole policy
    print(f"attaching role policy {agentcore_role_name}")
    try:
        iam_client.put_role_policy(
            PolicyDocument=role_policy_document,
            PolicyName="AgentCorePolicy",
            RoleName=agentcore_role_name,
        )
    except Exception as e:
        print(e)

    return agentcore_iam_role


if __name__ == "__main__":

    agent_name = "example_strands_agent"
    agentcore_iam_role = create_agentcore_role(agent_name=agent_name)

    boto_session = Session()
    region = boto_session.region_name

    agentcore_runtime = Runtime()
    current_dir = os.path.dirname(os.path.abspath(__file__))

    print(current_dir)
    response = agentcore_runtime.configure(
        entrypoint=os.path.join(current_dir, "agent.py"),
        execution_role=agentcore_iam_role["Role"]["Arn"],
        auto_create_ecr=True,
        requirements_file=os.path.join(current_dir, "requirements.txt"),
        region=region,
        agent_name=agent_name,
    )

    launch_result = agentcore_runtime.launch(auto_update_on_conflict=True)

    status_response = agentcore_runtime.status()
    status = status_response.endpoint["status"]
    end_status = ["READY", "CREATE_FAILED", "DELETE_FAILED", "UPDATE_FAILED"]
    while status not in end_status:
        time.sleep(10)
        status_response = agentcore_runtime.status()
        status = status_response.endpoint["status"]
        print(status)

    # Test the deployed agent
    print("\n🧪 Testing deployed agent...")
    invoke_response = agentcore_runtime.invoke({"prompt": "How is the weather now?"})

    # Process the streaming response properly
    if "text/event-stream" in invoke_response.get("contentType", ""):
        print("📡 Processing streaming response:")
        for line in invoke_response["response"].iter_lines(chunk_size=10):
            if line:
                line = line.decode("utf-8")
                if line.startswith("data: "):
                    data = line[6:].replace('"', "")
                    if data.startswith("start_event_loop:"):
                        print(f"\n⏰ {data.split(': ', 1)[1]}")
                    elif data.startswith("🔧 Using tool:"):
                        print(f"\n{data}")
                    else:
                        print(data, end="")
        print("\n✅ Agent test completed successfully!")
    else:
        print("📄 Non-streaming response received")
        print(invoke_response)
