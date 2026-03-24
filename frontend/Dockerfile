FROM node:20-alpine

WORKDIR /app

COPY package.json tsconfig.json next-env.d.ts next.config.js ./
COPY app ./app

RUN npm install
RUN npm run build
# Standalone server resolves static assets relative to its working directory (not repo root).
RUN mkdir -p .next/standalone/.next && cp -r .next/static .next/standalone/.next/static
RUN if [ -d public ]; then cp -r public .next/standalone/public; fi

ENV NODE_ENV=production
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

WORKDIR /app/.next/standalone
EXPOSE 3000

CMD ["node", "server.js"]
