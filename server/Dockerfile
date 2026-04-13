FROM node:20-bookworm-slim AS base
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install

FROM base AS build
COPY tsconfig.json ./
COPY prisma ./prisma
COPY src ./src
RUN npm run prisma:generate
RUN npm run build

FROM node:20-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/prisma ./prisma
COPY package.json ./
EXPOSE 3000
CMD ["node", "dist/server.js"]
