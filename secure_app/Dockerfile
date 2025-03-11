# Używamy obrazu Pythona jako bazy
FROM python:3.10-slim

# Ustawiamy katalog roboczy w kontenerze
WORKDIR /app

# Kopiujemy plik requirements.txt do kontenera
COPY requirements.txt .

# Instalujemy zależności Pythona
RUN pip install --no-cache-dir -r requirements.txt

# Kopiujemy resztę kodu projektu do kontenera
COPY . .

# Uruchamiamy serwer Django
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
