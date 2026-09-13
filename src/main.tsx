import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { Amplify } from "aws-amplify";
import { Authenticator } from "@aws-amplify/ui-react";
import "@aws-amplify/ui-react/styles.css";

import outputs from "../amplify_outputs.json";
import App from "./App";
import "./styles.css";

Amplify.configure(outputs);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Authenticator>
      {({ signOut, user }) => (
        <App username={user?.signInDetails?.loginId} signOut={signOut} />
      )}
    </Authenticator>
  </StrictMode>,
);
