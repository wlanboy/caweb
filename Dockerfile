FROM python:3.12-slim

WORKDIR /app

COPY main.py /app/
COPY templates/ /app/templates/
COPY static/ /app/static/

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 2000

#CMD ["python", "main.py"]
CMD ["uvicorn", "--listen=0.0.0.0:2000", "main:app"]