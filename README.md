# InternalDesk API — Laboratorio de Seguridad de Aplicaciones

**Universidad Mariano Gálvez de Guatemala — Maestría en Ingeniería en Sistemas y Seguridad de Aplicaciones**  
**Autor:** Josué David Cacao Sánchez

API REST desarrollada en **Python (FastAPI + SQLite)** para la gestión interna de tickets de soporte, implementada como laboratorio controlado de ingeniería de seguridad de aplicaciones (**AppSec / DevSecOps**). Incluye una línea base vulnerable (`Commit A: 01d0bba`) y su versión remediada con controles automatizados en CI/CD (`Commit B: f4db39f`).

---

## Estructura del Repositorio

```text
tarea_final_lab_seguridad_sa/
├── .github/workflows/
│   └── security-pipeline.yml      # Pipeline CI/CD en GitHub Actions (Gates de bloqueo y escaneos)
├── app_final_sa/                  # Código fuente activo de la API (FastAPI, Auth JWT, SQLite)
├── app_vulnerable_ref/            # Copia aislada de referencia del estado vulnerable inicial
├── tests/
│   └── test_security.py           # Suite de pruebas automatizadas funcionales y de seguridad
├── seguridad/
│   ├── semgrep_rules.yml          # Regla SAST personalizada contra SQL Injection (CWE-89)
│   └── semgrep_rules.py           # Casos de prueba unitarios para validar la regla de Semgrep
├── politica/
│   ├── security.rego              # Política OPA/Rego de configuración de despliegue
│   ├── deploy_config.json         # Configuración activa evaluada por el pipeline
│   ├── input_allow.json           # Caso de prueba permitido
│   └── input_deny.json            # Caso de prueba denegado
├── infra/
│   ├── insegura/main.tf           # Terraform AWS Security Group sin endurecer
│   └── segura/main.tf             # Terraform AWS Security Group endurecido
├── evidencia/
│   ├── antes/                     # Reportes, logs y capturas del Commit A (bloqueado)
│   └── despues/                   # Reportes, diffs, logs y capturas del Commit B (aprobado)
├── Dockerfile                     # Imagen endurecida con usuario no-root (appuser)
├── .dockerignore                  # Exclusión de archivos locales y entorno virtual
├── requirements.txt               # Dependencias principales
├── requirements-lock.txt          # Dependencias exactas congeladas
└── pytest.ini                     # Configuración de pytest
```

---

## Instalación y Ejecución Local

### 1. Preparar entorno e instalar dependencias
```powershell

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-lock.txt

```

### 2. Ejecutar pruebas automatizadas
```powershell
pytest -v
```

### 3. Levantar la API en local
```powershell
uvicorn app_final_sa.main:app --host 127.0.0.1 --port 8000
```
* Documentación interactiva: `[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)`
* Healthcheck: `[http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)`

### 4. Comandos de verificación de seguridad (opcional en local)
```powershell
# SAST (Semgrep)
semgrep --test seguridad
semgrep scan --config seguridad/semgrep_rules.yml --metrics=off app_final_sa

# SCA y SBOM
pip-audit -r requirements-lock.txt
cyclonedx-py requirements requirements-lock.txt --of JSON -o sbom.json

# IaC (Checkov)
checkov -d infra/insegura --framework terraform
checkov -d infra/segura --framework terraform
```

---

## Alcance y Uso Ético

Este proyecto y sus escenarios vulnerables fueron construidos exclusivamente con fines académicos en un entorno de laboratorio local y controlado. No debe desplegarse en producción ni utilizarse contra sistemas de terceros sin autorización explícita.