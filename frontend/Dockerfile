# ขั้นที่ 1: build React เป็นไฟล์ HTML/JS ธรรมดา
FROM node:24.21.0-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

# ขั้นที่ 2: เอาแค่ผลลัพธ์ไปเสิร์ฟด้วย nginx ไม่มี Node.js และ source code ติดไปใน image สุดท้าย
FROM nginxinc/nginx-unprivileged:1.28.2-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080