# Bounded Authority Plane (BAP) - Enterprise Certificate Authority & TLS Provisioner
# Generates a dedicated BAP Internal Root CA and signs the Control Plane TLS certificate
# with Subject Alternative Names (SANs) including localhost and enterprise domains.
# Also embeds the Root CA into client binaries for zero-friction verified HTTPS.

param(
    [bool]$ForceRegen = $false,
    [bool]$InstallToStore = $false,
    [string]$AdditionalSAN = "a.b.com"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = (Get-Item (Join-Path $scriptDir "..")).FullName

$caCertPath = Join-Path $rootDir "bap-root-ca.crt"
$caKeyPath  = Join-Path $rootDir "bap-root-ca.key"
$serverCertPath = Join-Path $rootDir "controlplane-cert.pem"
$serverKeyPath  = Join-Path $rootDir "controlplane-key.pem"
$serverCsrPath  = Join-Path $rootDir "controlplane.csr"
$certConfPath   = Join-Path $rootDir "cert_openssl.cnf"

# 1. Locate OpenSSL
$opensslBin = $null
$possibleOpenssl = @(
    (Get-Command openssl -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
    "C:\Program Files\Git\usr\bin\openssl.exe",
    "C:\Program Files (x86)\Git\usr\bin\openssl.exe",
    "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
)
foreach ($p in $possibleOpenssl) {
    if ($p -and (Test-Path $p)) {
        $opensslBin = $p
        break
    }
}

if (!$opensslBin) {
    Write-Error "OpenSSL not found. Please install Git or OpenSSL."
    exit 1
}

Write-Host "[BAP Cert Provisioner] Using OpenSSL at: $opensslBin" -ForegroundColor Cyan

# 2. Check if certificates already exist and skip if not forced
$certsExist = (Test-Path $caCertPath) -and (Test-Path $caKeyPath) -and (Test-Path $serverCertPath) -and (Test-Path $serverKeyPath)

if ($certsExist -and !$ForceRegen) {
    Write-Host "[+] BAP Root CA and Control Plane certificates already exist. Reusing existing credentials." -ForegroundColor Green
    Write-Host "    (Use -ForceRegen to rotate Root CA and invalidate older clients)" -ForegroundColor DarkGray
} else {
    if ($ForceRegen) {
        Write-Host "[*] -ForceRegen specified: Rotating Root CA and revoking legacy client trust..." -ForegroundColor Yellow
    } else {
        Write-Host "[*] Initial provisioning of BAP Internal Root CA and TLS certificates..." -ForegroundColor Yellow
    }

    # Generate OpenSSL configuration with SANs
    $confContent = @"
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = US
O = Bounded Authority Plane
OU = Enterprise Security
CN = bapcontrolplane

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = a.b.com
DNS.3 = bapcontrolplane
DNS.4 = bap.corp.internal
IP.1 = 127.0.0.1
IP.2 = ::1
"@
    if ($AdditionalSAN -and $AdditionalSAN -ne "a.b.com") {
        $confContent += "`nDNS.5 = $AdditionalSAN"
    }

    [System.IO.File]::WriteAllText($certConfPath, $confContent, [System.Text.Encoding]::ASCII)

    # 2.1 Create BAP Root CA (4096-bit, 10-year validity)
    Write-Host "  [*] Generating BAP Internal Root CA (4096-bit RSA)..." -ForegroundColor Gray
    & $opensslBin req -x509 -new -nodes -newkey rsa:4096 -sha256 -days 3650 `
        -subj "/C=US/O=Bounded Authority Plane/OU=Enterprise Security/CN=BAP Root CA" `
        -keyout $caKeyPath -out $caCertPath
    if ($LASTEXITCODE -ne 0) { throw "Failed to generate Root CA" }

    # 2.2 Create Server Private Key and CSR
    Write-Host "  [*] Generating Control Plane TLS key and CSR..." -ForegroundColor Gray
    & $opensslBin req -new -nodes -newkey rsa:2048 `
        -keyout $serverKeyPath -out $serverCsrPath -config $certConfPath
    if ($LASTEXITCODE -ne 0) { throw "Failed to generate Server CSR" }

    # 2.3 Sign Server Certificate using BAP Root CA
    Write-Host "  [*] Signing Control Plane certificate with BAP Root CA..." -ForegroundColor Gray
    $v3ExtContent = @"
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = a.b.com
DNS.3 = bapcontrolplane
DNS.4 = bap.corp.internal
IP.1 = 127.0.0.1
IP.2 = ::1
"@
    if ($AdditionalSAN -and $AdditionalSAN -ne "a.b.com") {
        $v3ExtContent += "`nDNS.5 = $AdditionalSAN"
    }
    $v3ExtPath = Join-Path $rootDir "v3_ext.cnf"
    [System.IO.File]::WriteAllText($v3ExtPath, $v3ExtContent, [System.Text.Encoding]::ASCII)

    & $opensslBin x509 -req -in $serverCsrPath -CA $caCertPath -CAkey $caKeyPath `
        -CAcreateserial -out $serverCertPath -days 825 -sha256 -extfile $v3ExtPath
    if ($LASTEXITCODE -ne 0) { throw "Failed to sign server certificate" }

    # Cleanup temporary CSR and cnf files
    Remove-Item $serverCsrPath -Force -ErrorAction SilentlyContinue
    Remove-Item $certConfPath -Force -ErrorAction SilentlyContinue
    Remove-Item $v3ExtPath -Force -ErrorAction SilentlyContinue
    $srlPath = Join-Path $rootDir "bap-root-ca.srl"
    Remove-Item $srlPath -Force -ErrorAction SilentlyContinue

    Write-Host "[+] BAP Root CA and Control Plane TLS certificate successfully created!" -ForegroundColor Green
}

# 3. Synchronize Root CA into Go packages for binary embedding (optional local dev)
$embedTargets = @(
    (Join-Path $rootDir "bap-edge\internal\httptransport\certs\embedded_ca.crt"),
    (Join-Path $rootDir "bap-gateway\internal\httptransport\certs\embedded_ca.crt"),
    (Join-Path $rootDir "cchook\certs\embedded_ca.crt")
)

foreach ($target in $embedTargets) {
    $parentDir = Split-Path -Parent $target
    if (!(Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    Copy-Item -Path $caCertPath -Destination $target -Force
    $relPath = $target.Replace($rootDir, "").TrimStart("\/")
    Write-Host "  [+] Synchronized CA to embed path: $relPath" -ForegroundColor DarkCyan
}

# 4. Install Root CA into Windows Certificate Store (CurrentUser\Root)
if ($InstallToStore -and [System.Environment]::OSVersion.Platform -eq "Win32NT") {
    Write-Host "[*] Checking Windows Trusted Root Certification Authorities store..." -ForegroundColor Gray
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
    $store.Open("ReadOnly")
    $found = $false
    $caBytes = [System.IO.File]::ReadAllBytes($caCertPath)
    $caCertObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$caBytes)

    foreach ($cert in $store.Certificates) {
        if ($cert.Thumbprint -eq $caCertObj.Thumbprint) {
            $found = $true
            break
        }
    }
    $store.Close()

    if ($found) {
        Write-Host "[+] BAP Root CA is already trusted in CurrentUser\Root store." -ForegroundColor Green
    } else {
        Write-Host "  [*] Adding BAP Root CA to CurrentUser\Root store via certutil..." -ForegroundColor Yellow
        & certutil.exe -addstore -user Root $caCertPath | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] SUCCESS: BAP Root CA installed into Windows Trusted Root store. Chrome/Edge will trust https without warnings!" -ForegroundColor Green
        } else {
            Write-Warning "Could not add certificate automatically to cert store (exit code $LASTEXITCODE)."
        }
    }
}
