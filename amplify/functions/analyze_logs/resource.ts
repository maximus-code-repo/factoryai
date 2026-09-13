import { defineFunction } from "@aws-amplify/backend";
import {
  AssetHashType,
  Duration,
} from "aws-cdk-lib";
import {
  Code,
  Function as LambdaFunction,
  Runtime,
} from "aws-cdk-lib/aws-lambda";
import { cpSync, copyFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const functionDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(functionDirectory, "../../..");

export const analyzeLogs = defineFunction(
  (scope) =>
    new LambdaFunction(scope, "AnalyzeLogs", {
      runtime: Runtime.PYTHON_3_13,
      handler: "handler.handler",
      timeout: Duration.minutes(15),
      memorySize: 2048,
      description: "Analyze uploaded security logs and save private JSON reports",
      code: Code.fromAsset(projectRoot, {
        assetHashType: AssetHashType.OUTPUT,
        bundling: {
          image: Runtime.PYTHON_3_13.bundlingImage,
          local: {
            tryBundle(outputDirectory: string) {
              mkdirSync(outputDirectory, { recursive: true });
              cpSync(
                join(projectRoot, "logsentinel"),
                join(outputDirectory, "logsentinel"),
                {
                  recursive: true,
                  filter: (source: string) =>
                    !source.includes("__pycache__") && !source.endsWith(".pyc"),
                },
              );
              copyFileSync(
                join(functionDirectory, "handler.py"),
                join(outputDirectory, "handler.py"),
              );
              return true;
            },
          },
          command: [
            "bash",
            "-c",
            [
              "cp -r /asset-input/logsentinel /asset-output/logsentinel",
              "find /asset-output/logsentinel -type d -name __pycache__ -prune -exec rm -rf {} +",
              "cp /asset-input/amplify/functions/analyze_logs/handler.py /asset-output/handler.py",
            ].join(" && "),
          ],
        },
      }),
    }),
  {
    resourceGroupName: "storage",
  },
);
