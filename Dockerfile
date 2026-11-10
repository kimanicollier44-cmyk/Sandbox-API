FROM python:3.12-slim
WORKDIR /app
COPY . .
EXPOSE 8771
CMD ["python", "main.py", "serve", "8771"]
