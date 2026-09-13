import { defineBackend } from "@aws-amplify/backend";
import { EventType } from "aws-cdk-lib/aws-s3";
import { LambdaDestination } from "aws-cdk-lib/aws-s3-notifications";

import { auth } from "./auth/resource";
import { analyzeLogs } from "./functions/analyze_logs/resource";
import { storage } from "./storage/resource";

const backend = defineBackend({
  auth,
  storage,
  analyzeLogs,
});

backend.storage.resources.bucket.addEventNotification(
  EventType.OBJECT_CREATED,
  new LambdaDestination(backend.analyzeLogs.resources.lambda),
  { prefix: "uploads/" },
);

backend.storage.resources.cfnResources.cfnBucket.lifecycleConfiguration = {
  rules: [
    {
      id: "AbortIncompleteMultipartUploads",
      status: "Enabled",
      abortIncompleteMultipartUpload: {
        daysAfterInitiation: 1,
      },
    },
  ],
};
