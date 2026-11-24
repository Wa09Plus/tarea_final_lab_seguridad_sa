# Imagen base oficial mínima
FROM python:3.12-slim

# Evita archivos .pyc y habilita logs inmediatos en stdout
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv/internaldesk

# Crear usuario y grupo sin privilegios de root
RUN groupadd --system appgroup && useradd --system --gid appgroup appuser

# Instalar únicamente dependencias congeladas de la aplicación
COPY requirements-lock.txt .
RUN pip install --no-cache-dir -r requirements-lock.txt

# Copiar código fuente de la aplicación y asignar permisos mínimos
COPY app_final_sa ./app_final_sa
RUN chown -R appuser:appgroup /srv/internaldesk

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app_final_sa.main:app", "--host", "0.0.0.0", "--port", "8000"]