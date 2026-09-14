import { defineFunction } from "@aws-amplify/backend";
import { Duration, RemovalPolicy, Stack } from "aws-cdk-lib";
import {
  AttributeType,
  BillingMode,
  Table,
} from "aws-cdk-lib/aws-dynamodb";
import {
  Code,
  Function as LambdaFunction,
  Runtime,
} from "aws-cdk-lib/aws-lambda";
import { PolicyStatement } from "aws-cdk-lib/aws-iam";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const functionDirectory = dirname(fileURLToPath(import.meta.url));
const modelId = "us.amazon.nova-2-lite-v1:0";

export const chatAgent = defineFunction(
  (scope) => {
    const usageTable = new Table(scope, "ChatUsage", {
      partitionKey: {
        name: "userId",
        type: AttributeType.STRING,
      },
      sortKey: {
        name: "day",
        type: AttributeType.STRING,
      },
      billingMode: BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: "expiresAt",
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const chatFunction = new LambdaFunction(scope, "ChatAgent", {
      runtime: Runtime.PYTHON_3_13,
      handler: "handler.handler",
      code: Code.fromAsset(functionDirectory, {
        exclude: ["resource.ts"],
      }),
      timeout: Duration.seconds(28),
      memorySize: 512,
      reservedConcurrentExecutions: 10,
      description: "Answer authenticated LogSentinel chat questions with Nova 2 Lite",
      environment: {
        BEDROCK_MODEL_ID: modelId,
        CHAT_USAGE_TABLE: usageTable.tableName,
        MAX_DAILY_REQUESTS: "100",
      },
    });
    usageTable.grantReadWriteData(chatFunction);

    const stack = Stack.of(chatFunction);
    chatFunction.addToRolePolicy(
      new PolicyStatement({
        actions: ["bedrock:InvokeModel"],
        resources: [
          stack.formatArn({
            service: "bedrock",
            region: stack.region,
            account: stack.account,
            resource: "inference-profile",
            resourceName: modelId,
          }),
          stack.formatArn({
            service: "bedrock",
            region: "*",
            account: "",
            resource: "foundation-model",
            resourceName: "amazon.nova-2-lite-v1:0",
          }),
        ],
      }),
    );

    return chatFunction;
  },
  {
    resourceGroupName: "data",
  },
);
