# node:22-slim
FROM node@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee

WORKDIR /app

# Install pnpm: the repository's packageManager version, checked against its hash
RUN corepack enable && corepack prepare pnpm@10.28.0+sha512.05df71d1421f21399e053fde567cea34d446fa02c76571441bfc1c7956e98e363088982d940465fd34480d4d90a0668bc12362f8aa88000a64e83d0b0e47be48 --activate

# Copy package files
COPY package.json ./

# Install dependencies (no lockfile - standalone package)
RUN pnpm install --prod

# Copy built files
COPY dist/ ./dist/

# Default migrations directory
ENV MIGRATIONS_DIR=/migrations

# Run the migration script
CMD ["node", "dist/index.js"]
