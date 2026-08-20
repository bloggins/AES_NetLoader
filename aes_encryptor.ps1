#requires -version 5.1
<#
.SYNOPSIS
    aes_encryptor.ps1 - AES-256-CBC + PBKDF2-HMAC-SHA256 payload encryptor
    for the NetLoader_AES reflective loader.

.DESCRIPTION
    Produces the exact blob format expected by NetLoader_AES.cs:
        b"AES1" | salt(16) | iv(16) | AES-256-CBC(PKCS7) ciphertext

    Parameters mirror the loader exactly:
        KDF        : PBKDF2-HMAC-SHA256 (requires .NET 4.7.2+ for the
                     HashAlgorithmName overload, present by default on
                     Windows 10 1803+ / Server 2019+)
        iterations : 120000
        key size   : 32 bytes (AES-256)
        password   : UTF-8 encoded
        padding    : PKCS7

.EXAMPLE
    .\aes_encryptor.ps1 -Key 's3cr3t' -InFile payload.exe -OutFile payload.exe.aes
.EXAMPLE
    .\aes_encryptor.ps1 -Key 's3cr3t' -InFile payload.exe.aes -Decrypt -OutFile restored.exe
.EXAMPLE
    $b64 = .\aes_encryptor.ps1 -Key 's3cr3t' -InFile payload.exe -Base64
#>

param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Key,
    [Parameter(Mandatory = $true, Position = 1)][string]$InFile,
    [string]$OutFile,
    [switch]$Base64,
    [switch]$Decrypt
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$Iterations = 120000
$Magic = [byte[]](65, 69, 83, 49)          # "AES1"

if ([Environment]::OSVersion.Version -lt [Version]'10.0.17134') {
    Write-Warning "PBKDF2-HMAC-SHA256 overload requires .NET 4.7.2+; expecting issues on this host."
}

function Get-DerivedKey {
    param([string]$Passphrase, [byte[]]$Salt)
    $pbkdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $Passphrase, $Salt, $Iterations,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    return $pbkdf.GetBytes(32)
}

function Invoke-AesCbc {
    param([byte[]]$InputBytes, [byte[]]$Key, [byte[]]$Iv, [bool]$Encrypt)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode   = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $Key
    $aes.IV  = $Iv

    $transform = if ($Encrypt) { $aes.CreateEncryptor() } else { $aes.CreateDecryptor() }
    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $transform,
        [System.Security.Cryptography.CryptoStreamMode]::Write)
    try {
        $cs.Write($InputBytes, 0, $InputBytes.Length)
        $cs.FlushFinalBlock()
        return $ms.ToArray()
    }
    finally {
        $cs.Dispose(); $ms.Dispose(); $transform.Dispose(); $aes.Dispose()
    }
}

$raw = [System.IO.File]::ReadAllBytes((Resolve-Path $InFile))

$output = $null
$label  = 'AES1 blob'

if ($Decrypt) {
    if ($raw.Length -lt 52 -or $raw[0] -ne 65 -or $raw[1] -ne 69 -or $raw[2] -ne 83 -or $raw[3] -ne 49) {
        throw 'Not an AES-256 NetLoader payload (bad magic)'
    }
    $salt = New-Object byte[] 16
    $iv   = New-Object byte[] 16
    [Array]::Copy($raw, 4, $salt, 0, 16)
    [Array]::Copy($raw, 20, $iv, 0, 16)
    $cipher = New-Object byte[] ($raw.Length - 36)
    [Array]::Copy($raw, 36, $cipher, 0, $cipher.Length)

    $key = Get-DerivedKey -Passphrase $Key -Salt $salt
    try { $output = Invoke-AesCbc -InputBytes $cipher -Key $key -Iv $iv -Encrypt $false }
    finally { $key = $null }

    $label = 'plaintext'
}
else {
    $salt = New-Object byte[] 16
    $iv   = New-Object byte[] 16
    $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($salt)
        $rng.GetBytes($iv)
    }
    finally { $rng.Dispose() }

    $key = Get-DerivedKey -Passphrase $Key -Salt $salt
    try { $cipher = Invoke-AesCbc -InputBytes $raw -Key $key -Iv $iv -Encrypt $true }
    finally { $key = $null }

    $output = New-Object byte[] ($cipher.Length + 36)
    [Array]::Copy($Magic, 0, $output, 0, 4)
    [Array]::Copy($salt, 0, $output, 4, 16)
    [Array]::Copy($iv, 0, $output, 20, 16)
    [Array]::Copy($cipher, 0, $output, 36, $cipher.Length)
}

if ($Base64) {
    return [Convert]::ToBase64String($output)
}

$outFile = $OutFile
if (-not $outFile) {
    $outFile = $InFile + $(if ($Decrypt) { '.dec' } else { '.aes' })
}
[System.IO.File]::WriteAllBytes($outFile, $output)
Write-Host "[+] $label : $($raw.Length) -> $($output.Length) bytes -> $outFile"
