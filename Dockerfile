# One image for both the relay and the agent (pick with the command).
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/protocol/package.json packages/protocol/
COPY packages/relay/package.json packages/relay/
COPY packages/agent/package.json packages/agent/
COPY packages/client/package.json packages/client/
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app /app
USER node
# Node >= 22.18 runs the TypeScript sources directly (type stripping).
CMD ["node", "packages/relay/src/main.ts"]
