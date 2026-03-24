FROM node:20-alpine

WORKDIR /app

COPY package.json tsconfig.json next-env.d.ts next.config.js ./
COPY app ./app

RUN npm install
RUN npm run build
RUN mkdir -p .next/standalone/.next && cp -r .next/static .next/standalone/.next/static
RUN if [ -d public ]; then cp -r public .next/standalone/public; fi

EXPOSE 3000

CMD ["node", ".next/standalone/server.js"]
