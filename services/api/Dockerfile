FROM python:3.11-slim

WORKDIR /app

# --- Step 1: Install lightweight deps first (no torch) ---
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Step 2: Install CPU-only torch (explicit index, no CUDA) ---
RUN pip install --no-cache-dir \
    --index-url https://download.pytorch.org/whl/cpu \
    torch==2.5.1+cpu

# --- Step 3: Copy app ---
COPY model.py .
COPY best_model.pth .
COPY app.py .

EXPOSE 5000

CMD ["python", "app.py"]
