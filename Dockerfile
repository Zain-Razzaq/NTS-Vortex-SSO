FROM node:20-alpine

WORKDIR /app

COPY package.json ./
# python3/make/g++ are needed to compile better-sqlite3's native addon on
# musl (Alpine) — no prebuilt binary is published for it, unlike glibc
# hosts. Removed again after install; the compiled .node binary doesn't
# need them at runtime.
RUN apk add --no-cache --virtual .build-deps python3 make g++ \
  && npm install --omit=dev \
  && apk del .build-deps

COPY . .

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server.js"]
