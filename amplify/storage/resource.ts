import { defineStorage } from "@aws-amplify/backend";
import { analyzeLogs } from "../functions/analyze_logs/resource";

export const storage = defineStorage({
  name: "logsentinelFiles",
  keepOnDelete: true,
  access: (allow) => ({
    "uploads/{entity_id}/*": [
      allow.entity("identity").to(["read", "write", "delete"]),
      allow.resource(analyzeLogs).to(["read", "delete"]),
    ],
    "analyses/{entity_id}/*": [
      allow.entity("identity").to(["read", "delete"]),
      allow.resource(analyzeLogs).to(["write"]),
    ],
  }),
});
