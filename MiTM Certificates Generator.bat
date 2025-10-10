@echo off
setlocal enabledelayedexpansion

if "%~1"=="" (
  set /p LEAF_HOST="Enter LEAF_HOST_OR_IP: "
) else (
  set "LEAF_HOST=%~1"
)

if "%LEAF_HOST%"=="" (
  echo No host provided. Exiting.
  exit /b 1
)

set "WORKDIR=C:\temp\mitmcerts"
if not exist "%WORKDIR%" mkdir "%WORKDIR%"
cd /d "%WORKDIR%"

REM ==== CA ext file (write safe, line-by-line) ====
>"ca_ext.cnf" (
  echo [ req ]
  echo distinguished_name = dn
  echo x509_extensions = v3_ca
  echo prompt = no
  echo [ dn ]
  echo CN = My Local MITM CA
  echo O = MyOrg
  echo C = US
  echo [ v3_ca ]
  echo basicConstraints = critical,CA:TRUE
  echo keyUsage = critical,keyCertSign,cRLSign
  echo subjectKeyIdentifier = hash
)

REM create CA key if missing
if not exist myCA.key (
  openssl genrsa -out myCA.key 4096
)

REM create CA CRT if missing
if not exist myCA.crt (
  openssl req -x509 -new -key myCA.key -nodes -days 3650 -out myCA.crt -config ca_ext.cnf -extensions v3_ca -subj "/C=US/O=MyOrg/CN=My Local MITM CA"
)

REM Export a PFX for the CA (proxy needs this) - change password to something safe (avoid ! & ^ < > |)
set "CAPFXPASS=ChangeMeStrong123"
openssl pkcs12 -export -out myCA.pfx -inkey myCA.key -in myCA.crt -passout pass:%CAPFXPASS%

REM ==== leaf key + csr ====
openssl genrsa -out leaf.key 2048
openssl req -new -key leaf.key -out leaf.csr -subj "/CN=%LEAF_HOST%"

REM ==== SAN determination ====
set "SAN_LINE="
echo %LEAF_HOST% | findstr /R "^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$" >nul
if %ERRORLEVEL%==0 (
  set "SAN_LINE=subjectAltName = IP:%LEAF_HOST%"
) else (
  set "SAN_LINE=subjectAltName = DNS:%LEAF_HOST%"
)

REM ==== leaf ext file (write safe) ====
>"leaf_ext.cnf" (
  echo [ v3_req ]
  echo authorityKeyIdentifier=keyid,issuer
  echo basicConstraints=CA:FALSE
  echo keyUsage = digitalSignature, keyEncipherment
  echo extendedKeyUsage = serverAuth
  echo %SAN_LINE%
)

REM ==== sign CSR with CA ====
openssl x509 -req -in leaf.csr -CA myCA.crt -CAkey myCA.key -CAcreateserial -out leaf.crt -days 730 -sha256 -extfile leaf_ext.cnf -extensions v3_req

REM ==== bundle leaf PFX ====
set "LEAFPFXPASS=myPfxPass123"
openssl pkcs12 -export -out leaf.pfx -inkey leaf.key -in leaf.crt -certfile myCA.crt -passout pass:%LEAFPFXPASS%

echo.
echo Done. Files in %WORKDIR%
echo myCA.key
echo myCA.crt
echo myCA.pfx (password: %CAPFXPASS%)
echo leaf.key
echo leaf.crt
echo leaf.pfx (password: %LEAFPFXPASS%)
echo.

pause
