# ---- build the web client
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/crypto/package.json packages/crypto/
COPY server/package.json server/
COPY web/package.json web/
RUN npm ci
COPY packages packages
COPY web web
RUN npm run build --workspace web

# ---- runtime: Node runs the TypeScript server directly (type stripping)
FROM node:24-alpine
ENV NODE_ENV=production \
    PARLEY_PORT=8787 \
    PARLEY_DB=/data/parley.sqlite \
    PARLEY_STATIC_DIR=/app/web/dist
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/crypto/package.json packages/crypto/
COPY server/package.json server/
COPY web/package.json web/
RUN npm ci --omit=dev && npm cache clean --force
COPY packages/crypto/src packages/crypto/src
COPY server/src server/src
COPY --from=build /app/web/dist web/dist
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME /data
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:8787/api/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "--disable-warning=ExperimentalWarning", "server/src/index.ts"]
