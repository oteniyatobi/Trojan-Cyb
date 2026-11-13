FROM node:22-alpine AS build

WORKDIR /app/ui

COPY package.json package-lock.json ./
RUN npm ci

ARG VITE_SUPABASE_URL
ARG VITE_SUPABASE_PUBLISHABLE_KEY
ENV VITE_SUPABASE_URL=$VITE_SUPABASE_URL
ENV VITE_SUPABASE_PUBLISHABLE_KEY=$VITE_SUPABASE_PUBLISHABLE_KEY

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/ui/dist /usr/share/nginx/html
EXPOSE 80
