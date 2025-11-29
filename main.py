import os
from pathlib import Path
from datetime import datetime, timedelta
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Static files (CSS)
app.mount("/static", StaticFiles(directory="static"), name="static")

CERT_DIR = Path(os.getenv("LOCAL_CA_PATH", "/local-ca"))
FILE_DIR = Path(os.getenv("LOCAL_CA_PATH", "/data"))
CA_CERT = CERT_DIR / "ca.pem"
CA_KEY = CERT_DIR / "ca.key"

@app.get("/", response_class=HTMLResponse)
async def form(request: Request):
    return templates.TemplateResponse("form.html", {"request": request})

@app.post("/", response_class=HTMLResponse)
async def create_cert(request: Request, hostname: str = Form(...), alt_names: str = Form("")):
    alt_names_list = [n.strip() for n in alt_names.split(",") if n.strip()]
    host_dir = CERT_DIR / hostname
    host_dir.mkdir(parents=True, exist_ok=True)

    # Schlüssel generieren
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    key_path = host_dir / f"{hostname}.key"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # CA laden
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # CSR bauen
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Germany"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "LAN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Homelab"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    alt_names_objs = [x509.DNSName(hostname)] + [x509.DNSName(n) for n in alt_names_list]

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).add_extension(
        x509.SubjectAlternativeName(alt_names_objs), critical=False
    ).sign(key, hashes.SHA256())

    # Zertifikat signieren
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(alt_names_objs), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    cert_path = FILE_DIR / f"{hostname}.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    cert_content = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_content = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    # Ergebnis direkt unter dem Formular anzeigen
    return templates.TemplateResponse("form.html", {
        "request": request,
        "hostname": hostname,
        "cert_content": cert_content,
        "key_content": key_content
    })

@app.get("/download/{hostname}/{filename}")
async def download_file(hostname: str, filename: str):
    full_path = FILE_DIR / hostname / filename
    return FileResponse(full_path, filename=filename)
