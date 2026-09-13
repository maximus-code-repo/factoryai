import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const outputPath = resolve("amplify_outputs.json");

if (!existsSync(outputPath)) {
  writeFileSync(outputPath, JSON.stringify({ version: "1" }, null, 2) + "\n");
  console.warn(
    "Created a local placeholder amplify_outputs.json. Run `npm run sandbox` " +
      "to connect the app to an AWS backend.",
  );
}
