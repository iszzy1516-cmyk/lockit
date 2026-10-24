FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.server.json tsconfig.client.json tsconfig.cli.json vite.config.ts index.html ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN groupadd --system lockit && useradd --system --gid lockit --home-dir /app lockit
COPY --from=build --chown=lockit:lockit /app/node_modules ./node_modules
COPY --from=build --chown=lockit:lockit /app/dist ./dist
COPY --chown=lockit:lockit package.json ./
RUN mkdir -p /data && chown lockit:lockit /data
USER lockit
EXPOSE 3000
VOLUME ["/data"]
CMD ["node", "dist/server/server/index.js"]
