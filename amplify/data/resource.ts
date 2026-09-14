import { a, defineData, type ClientSchema } from "@aws-amplify/backend";

import { chatAgent } from "../functions/chat_agent/resource";

const schema = a.schema({
  ChatSession: a
    .model({
      title: a.string().required(),
      lastMessageAt: a.datetime().required(),
    })
    .authorization((allow) => [allow.owner()]),

  ChatExchange: a
    .model({
      sessionId: a.id().required(),
      userContent: a.string().required(),
      assistantContent: a.string().required(),
      sentAt: a.datetime().required(),
    })
    .authorization((allow) => [allow.owner()]),

  ChatResponse: a.customType({
    answer: a.string().required(),
    modelId: a.string().required(),
    inputTokens: a.integer(),
    outputTokens: a.integer(),
  }),

  chat: a
    .mutation()
    .arguments({
      message: a.string().required(),
      historyJson: a.string(),
      reportContextJson: a.string(),
    })
    .returns(a.ref("ChatResponse"))
    .authorization((allow) => [allow.authenticated()])
    .handler(a.handler.function(chatAgent)),
});

export type Schema = ClientSchema<typeof schema>;

export const data = defineData({
  schema,
  authorizationModes: {
    defaultAuthorizationMode: "userPool",
  },
});
