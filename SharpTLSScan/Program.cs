// SharpTLSScan
// Joseph Ryan Ries, 2014
// ryanries09@gmail.com - myotherpcisacloud.com
//
// This application probes network hosts to see which versions of SSL/TLS and which ciphers they support.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Authentication;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Runtime.InteropServices;
using System.IO;

namespace SharpTLSScan
{
    class Program
    {
        private static string productName = Assembly.GetExecutingAssembly().GetName().Name;
        private static string productVersion = FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).FileVersion.Split('.')[0] +
            "." + FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).FileVersion.Split('.')[1];

        static void Main(string[] args)
        {
            byte[] clientRandom = new byte[28];
            bool bypassSchannel = false;

            #region Argument validation, DNS resolution, and TCP connectivity
            UInt16 portNum = 443;
            string hostName = string.Empty;
            IPAddress ipAddress;

            Regex hostnameRegex = new Regex(@"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$", RegexOptions.IgnoreCase);

            if ((args.Length != 1) & (args.Length != 2))            
                PrintHelpMessageAndExit();             

            hostName = args[0].Split(':')[0];

            if (!hostnameRegex.IsMatch(hostName))            
                PrintHelpMessageAndExit();

            if (args[0].Contains(':'))            
                if (!UInt16.TryParse(args[0].Split(':')[1], out portNum))                
                    PrintHelpMessageAndExit();

            if (!BitConverter.IsLittleEndian)
            {
                Console.WriteLine("Sorry! This program doesn't work on big endian systems!");
                return;
            }

            if (args.Length == 2)
                if (args[1].Equals("NoSchannel", StringComparison.OrdinalIgnoreCase))
                    bypassSchannel = true;
                else
                    PrintHelpMessageAndExit();
            


            IPHostEntry ipHostEntry = null;
            try
            {
                ipHostEntry = Dns.GetHostEntry(hostName);
            }
            catch (Exception ex)
            {
                // DNS didn't work, maybe it's an IP address?
                if (IPAddress.TryParse(hostName, out ipAddress) == false)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("ERROR: " + ex.Message);
                    Console.ResetColor();
                    return;
                }
                else
                {
                    hostName = ipAddress.ToString();
                }
            }

            Console.WriteLine("Scanning " + hostName + " on port " + portNum + "...");

            if (ipHostEntry != null)
            {
                Console.WriteLine(hostName + " resolved to " + ipHostEntry.AddressList.Length + " IP addresses:");
                foreach (var ip in ipHostEntry.AddressList)
                    Console.WriteLine(" " + ip);
            }


            try
            {
                using (TcpClient tcpClient = new TcpClient(hostName, portNum))                
                    Console.WriteLine(hostName + " responds to TCP on " + portNum + ".\n");                
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ERROR: " + hostName + " does not respond to TCP on " + portNum + ".\n" + ex.Message);
                Console.ResetColor();
                return;
            }
            #endregion

            // This is an easy way for me to leverage the high-level .NET classes to grab the server's certificate,
            // but it will fail if you've turned off support of all the protocols/ciphers that the server supports and therefore
            // the SChannel SSP cannot negotiate a connection.
            #region SChannel Negotiation
            if (!bypassSchannel)
            try
            {
                using (TcpClient tcpClient = new TcpClient(hostName, portNum))
                using (SslStream sslStream = new SslStream(tcpClient.GetStream(), true, CertificateValidationCallBack))
                {
                    sslStream.AuthenticateAsClient(hostName);
                    Console.WriteLine();
                    Console.WriteLine("SChannel negotiated the following:\n");
                    Console.WriteLine("Protocol Version      : " + sslStream.SslProtocol);
                    Console.WriteLine("Cipher Algorithm      : " + sslStream.CipherAlgorithm);
                    Console.WriteLine("Cipher Strength       : " + sslStream.CipherStrength + " bits");
                    Console.WriteLine("Hash Algorithm        : " + sslStream.HashAlgorithm);
                    Console.WriteLine("Hash Strength         : " + sslStream.HashStrength + " bits");
                    Console.Write("Key Exchange Algorithm: ");
                    if (sslStream.KeyExchangeAlgorithm.ToString() == "44550")
                        Console.WriteLine("ECDH Ephemeral");
                    else
                        Console.WriteLine(sslStream.KeyExchangeAlgorithm);

                    Console.WriteLine("Key Exchange Strength : " + sslStream.KeyExchangeStrength + " bits");
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("ERROR: Unable to negotiate SChannel secure connection with " + hostName + ".\n" + ex.Message);
                Console.ResetColor();
            }
            #endregion

            Console.WriteLine(hostName + ":" + portNum + " supports the following \nprotocol versions and cipher suites:\n");

            List<string> sslv20CipherSuitesSupported = new List<string>();
            List<string> sslv30CipherSuitesSupported = new List<string>();
            List<string> tlsv10CipherSuitesSupported = new List<string>();
            List<string> tlsv11CipherSuitesSupported = new List<string>();
            List<string> tlsv12CipherSuitesSupported = new List<string>();            
                                    
            // With SSLv2, only one request to the server is necessary, because the server
            // gives all supported cipher suites in the first ServerHello. SSLv2 is not secure, so all SSLv2 support is hilighted in RED.
            #region SSLv2
            using (TcpClient tcpClient = new TcpClient(hostName, portNum))
            {
                using (NetworkStream netStream = tcpClient.GetStream())
                {
                    byte[] sslv2ClientHello = { 0x80, 0x2E,              // Length [Record Layer]
                                                0x01,                    // Client Hello
                                                0x00, 0x02,              // Version (0x0002)
                                                0x00, 0x15,              // Cipher Specs Length
                                                0x00, 0x00,              // Session ID Length
                                                0x00, 0x10,              // Challenge Length
                                                0x01, 0x00, 0x80,        // SSL_CK_RC4_128_WITH_MD5
                                                0x02, 0x00, 0x80,        // SSL_CK_RC4_128_EXPORT40_WITH_MD5
                                                0x03, 0x00, 0x80,        // SSL_CK_RC2_128_CBC_WITH_MD5
                                                0x04, 0x00, 0x80,        // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
                                                0x05, 0x00, 0x80,        // SSL_CK_IDEA_128_CBC_WITH_MD5
                                                0x06, 0x00, 0x40,        // SSL_CK_DES_64_CBC_WITH_MD5
                                                0x07, 0x00, 0xC0,        // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
                                                0xDE, 0xAD, 0xBE, 0xEF,  // Challenge Data (16 bytes of dead beef)
                                                0xDE, 0xAD, 0xBE, 0xEF,
                                                0xDE, 0xAD, 0xBE, 0xEF,
                                                0xDE, 0xAD, 0xBE, 0xEF };

                    byte[] sslv2ReadBuffer = new byte[1];
                    List<byte> sslv2ServerHello = new List<byte>();
                    tcpClient.ReceiveTimeout = 3000;
                    tcpClient.SendTimeout = 3000;
                    netStream.ReadTimeout = 3000;
                    netStream.WriteTimeout = 3000;

                    netStream.Write(sslv2ClientHello, 0, sslv2ClientHello.Length);
                    try
                    {
                        do
                        {
                            netStream.Read(sslv2ReadBuffer, 0, sslv2ReadBuffer.Length);
                            foreach (byte b in sslv2ReadBuffer)
                                sslv2ServerHello.Add(b);
                        }
                        while (netStream.DataAvailable);
                        if (sslv2ServerHello.Count < 64)
                            throw new Exception("Did not receive enough data from the server.");

                        if (sslv2ServerHello[2] != 4)  // The third byte = 0x04 = ServerHello 
                            throw new Exception("Server did not send a ServerHello message.");

                        if (sslv2ServerHello[6] != (byte)ProtocolVersion.SSLv20) // Seventh byte = 0x02 = SSLv2
                            throw new Exception("SeverHello did not indicate SSLv2.");

                        byte[] certLenBytes = sslv2ServerHello.Skip(7).Take(2).ToArray();
                        Array.Reverse(certLenBytes);

                        int certificateLength = BitConverter.ToUInt16(certLenBytes, 0);

                        if (sslv2ServerHello.Count < 13 + certificateLength)
                            throw new Exception("Server did not send enough data.");

                        byte[] cipherSpecLenBytes = sslv2ServerHello.Skip(9).Take(2).ToArray();

                        Array.Reverse(cipherSpecLenBytes);

                        int cipherSpecLength = BitConverter.ToUInt16(cipherSpecLenBytes, 0);

                        byte[] cipherSpecs = sslv2ServerHello.Skip(13 + certificateLength).Take(cipherSpecLength).ToArray();

                        if (cipherSpecs.Length % 3 != 0)                        // Each cipher suite should be 24 bits long
                            throw new Exception("Invalid list of ciphers.");

                        for (int x = 0; x < cipherSpecs.Length; x += 3)
                        {
                            byte[] cSpec = new byte[4];
                            cSpec[0] = 0x00;
                            Array.Copy(cipherSpecs.Skip(x).Take(3).ToArray(), 0, cSpec, 1, 3);

                            Array.Reverse(cSpec);

                            string csName = Enum.GetName(typeof(SSLv2CipherSuite), BitConverter.ToInt32(cSpec, 0));
                            
                            if (csName.Length > 0)
                                sslv20CipherSuitesSupported.Add("SSLv20 Cipher: " + csName);
                            else
                                sslv20CipherSuitesSupported.Add("SSLv20 Cipher: UNKNOWN");                            
                        }
                    }
                    catch
                    {

                    }
                }
            }
            #endregion

            Console.ForegroundColor = ConsoleColor.Red;
            foreach (string line in sslv20CipherSuitesSupported)
                Console.WriteLine(line);

            Console.ResetColor();            

            // Parallel powers, ACTIVATE
            #region SSLv3,TLSv1.0-1.2
            Parallel.ForEach((ProtocolVersion[]) Enum.GetValues(typeof(ProtocolVersion)), protocolVersion =>
            {
                foreach (SSLv3AndUpCipherSuite cipherSuite in (SSLv3AndUpCipherSuite[])Enum.GetValues(typeof(SSLv3AndUpCipherSuite)))
                {
                    try
                    {
                        using (TcpClient tcpClient = new TcpClient(hostName, portNum))
                        {
                            using (NetworkStream netStream = tcpClient.GetStream())
                            {
                                if (protocolVersion == ProtocolVersion.SSLv20)
                                    continue;

                                // SSL3 and up require the client to generate random bytes in their ClientHellos
                                Random RNG = new Random();
                                RNG.NextBytes(clientRandom);

                                tcpClient.ReceiveTimeout = 3000;
                                tcpClient.SendTimeout = 3000;
                                netStream.ReadTimeout = 3000;
                                netStream.WriteTimeout = 3000;

                                List<byte> clientHello = new List<byte>();
                                List<byte> serverHello = new List<byte>();
                                UInt32 timeStamp = (UInt32)(DateTime.UtcNow - (new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc))).TotalSeconds;  // Total seconds elapsed since the Unix epoch began.
                                byte[] readBuffer = new byte[1];
                                byte[] timeStampBytes = (byte[])BitConverter.GetBytes(timeStamp);
                                byte[] version = (byte[])BitConverter.GetBytes((ushort)protocolVersion);
                                Array.Reverse(timeStampBytes);
                                Array.Reverse(version);
                                // version[0] = Major, version[1] = Minor

                                clientHello.Add(0x16);                                                         // Handshake        [Record Layer][0]
                                clientHello.AddRange(version);                                                 // Version Number   [Record Layer][1,2]
                                clientHello.AddRange(new byte[] { 0x00, 0x00 });                               // Message Length   [Record Layer][3,4]
                                clientHello.Add(0x01);                                                         // Client Hello     [Begin Handshake][5]
                                clientHello.Add(0x00);                                                         // Message Length   [6]
                                clientHello.Add(0x00);                                                         // Message Length   [7]
                                clientHello.Add(0x00);                                                         // Message Length   [8]
                                clientHello.AddRange(version);                                                 // Version Number   [9,10]
                                clientHello.AddRange(timeStampBytes);                                          // Unix Timestamp   [11-14]
                                clientHello.AddRange(clientRandom);                                            // 28 Random Bytes  [15-43]
                                clientHello.Add(0x00);                                                         // SessionID Length [44]
                                clientHello.Add(0x00);                                                         // Cipher Suite Length (2 bytes)
                                clientHello.Add(0x02);                                                         //
                                clientHello.AddRange(BitConverter.GetBytes((ushort)cipherSuite).Reverse());    // Add 1 cipher to the list (2 bytes.) If the server responds with a ServerHello, it supports that cipher.
                                clientHello.Add(0x02);                                                         // Compression List Length
                                clientHello.Add(0x01);                                                         // Deflate
                                clientHello.Add(0x00);                                                         // Null

                                int chLength = clientHello.ToArray().Length;                                   // Now that we have the actual length of the payload, go back and modify the length fields.
                                clientHello.RemoveRange(3, 2);
                                clientHello.InsertRange(3, (BitConverter.GetBytes((ushort)(chLength - 5))).Reverse());
                                clientHello.RemoveRange(7, 2);
                                clientHello.InsertRange(7, (BitConverter.GetBytes((ushort)(chLength - 9)).Reverse()));

                                netStream.Write(clientHello.ToArray(), 0, clientHello.ToArray().Length);
                                do
                                {
                                    netStream.Read(readBuffer, 0, readBuffer.Length);
                                    foreach (byte b in readBuffer)
                                        serverHello.Add(b);
                                }
                                while (netStream.DataAvailable);
                                if (serverHello.Count < 64)
                                    throw new Exception("Did not receive enough data from the server.");

                                if (serverHello[0] != 0x16) // Handshake protocol
                                    throw new Exception("Server did not send a Handshake message.");

                                // The third byte of the ServerHello will contain the minor version number, which 
                                // should match the version number we used in our ClientHello.
                                if (serverHello[2] != version[1])
                                    throw new Exception("ServerHello was a different version than was specified in the ClientHello.");

                                if (serverHello[5] != 0x02) // Server Hello
                                    throw new Exception("Server did not send a ServerHello message.");

                                if (protocolVersion == ProtocolVersion.SSLv30)
                                    sslv30CipherSuitesSupported.Add(protocolVersion + " Cipher: " + cipherSuite);
                                else if (protocolVersion == ProtocolVersion.TLSv10)
                                    tlsv10CipherSuitesSupported.Add(protocolVersion + " Cipher: " + cipherSuite);
                                else if (protocolVersion == ProtocolVersion.TLSv11)
                                    tlsv11CipherSuitesSupported.Add(protocolVersion + " Cipher: " + cipherSuite);
                                else if (protocolVersion == ProtocolVersion.TLSv12)
                                    tlsv12CipherSuitesSupported.Add(protocolVersion + " Cipher: " + cipherSuite);
                                else
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("ERROR: Protocol version was unexpected.");
                                    Console.ResetColor();
                                    Environment.Exit(1);
                                }
                            }
                        }
                    }
                    catch
                    {

                    }
                }                
            });
            #endregion
            
            // Changing all SLLv3 to YELLOW because of Poodle
            Console.ForegroundColor = ConsoleColor.Yellow;
            foreach (string line in sslv30CipherSuitesSupported)
                Console.WriteLine(line);
            
            Console.ResetColor();

            foreach (string line in tlsv10CipherSuitesSupported)
            {
                if (line.ToLower().Contains("md5") | line.ToLower().Contains("rc4"))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(line);
                    Console.ResetColor();
                }
                else
                    Console.WriteLine(line);
            }

            foreach (string line in tlsv11CipherSuitesSupported)
            {
                if (line.ToLower().Contains("md5") | line.ToLower().Contains("rc4"))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(line);
                    Console.ResetColor();
                }
                else
                    Console.WriteLine(line);
            }

            foreach (string line in tlsv12CipherSuitesSupported)
            {
                if (line.ToLower().Contains("md5") | line.ToLower().Contains("rc4"))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(line);
                    Console.ResetColor();
                }
                else
                    Console.WriteLine(line);
            }
            
            Console.ResetColor();
        }

        static void PrintHelpMessageAndExit()
        {            
            Console.WriteLine("\n" + productName + " " + productVersion + " 2014 by Joseph Ryan Ries | myotherpcisacloud.com\n");
            Console.WriteLine("Usage: C:\\>SharpTLSScan myhost.domain.com[:7000] [NoSchannel]\n");
            Console.WriteLine("SSL and TLS diagnostics on myhost.domain.com on port 7000.\n");
            Console.WriteLine("If no port number is given, a default of 443 is used.\n");
            Console.Write("Good things (such as a valid certificate) are highlighted in ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("GREEN.");
            Console.ResetColor();
            Console.Write("Bad things (such as SSLv2 support) are highlighted in ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("RED.");
            Console.ResetColor();
            Console.Write("OK but not great things (such as MD5 hashes) are highlighted in ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("YELLOW.\n");
            Console.ResetColor();
            Console.WriteLine("The NoSchannel parameter is optional, and if you specify it,");
            Console.WriteLine("an Schannel-based connection will not be attempted.\n");
            Environment.Exit(1);
        }

        private static bool CertificateValidationCallBack(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Certificate2 is better than Certificate1, right?
            X509Certificate2 cert = (X509Certificate2)certificate;

            string[] subjectPieces = splitDN(cert.Subject);

            Console.Write("Certificate Subject   : ");
            for (int x = 0; x < subjectPieces.Length; x++)
            {
                if (x == 0)
                    Console.WriteLine(subjectPieces[x]);
                else
                    Console.WriteLine("                        " + subjectPieces[x]);
            }

            string[] issuerPieces = splitDN(cert.Issuer);
            
            Console.Write("Certificate Issuer    : ");
            for (int x = 0; x < issuerPieces.Length; x++)
            {
                if (x == 0)
                    Console.WriteLine(issuerPieces[x]);
                else
                    Console.WriteLine("                        " + issuerPieces[x]);
            }

            Console.WriteLine("Certificate Begins    : " + cert.NotBefore);
            Console.WriteLine("Certificate Expires   : " + cert.NotAfter);
            Console.WriteLine("Certificate Version   : " + cert.Version);
            if (cert.SignatureAlgorithm.FriendlyName.ToLower().Contains("md5"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Signature Algorithm   : " + cert.SignatureAlgorithm.FriendlyName + " (" + cert.SignatureAlgorithm.Value + ")");
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine("Signature Algorithm   : " + cert.SignatureAlgorithm.FriendlyName + " (" + cert.SignatureAlgorithm.Value + ")");
            }
            Console.WriteLine("Key Exchange Algorithm: " + cert.PublicKey.Key.KeyExchangeAlgorithm);
            Console.WriteLine("Public Key Algorithm  : " + new System.Security.Cryptography.Oid(cert.GetKeyAlgorithm()).FriendlyName);
            Console.WriteLine("Public Key Size       : " + cert.PublicKey.Key.KeySize);
            foreach (X509Extension extension in cert.Extensions)
            {
                if (extension.Oid.FriendlyName == "Subject Alternative Name")
                {
                    AsnEncodedData asnData = new AsnEncodedData(extension.Oid, extension.RawData);                    
                    string[] sans = asnData.Format(false).Split(',');
                    Console.Write("Alternative Names     : ");
                    for (int x = 0; x < sans.Length; x++)
                    {
                        if (x == 0)
                            Console.WriteLine(sans[x]);
                        else
                            Console.WriteLine("                       " + sans[x]);
                    }
                }
            }
            Console.Write("Certificate Validated : ");
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Yes");
                Console.ResetColor();
            }
            else 
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("No (" + sslPolicyErrors + ")");
                Console.ResetColor();
            }
            return true;
        }

        private static string[] splitDN(string input)
        {
            string[] splitString = input.Split(',');
            List<string> correctedSplitString = new List<string>();
            int index = 0;
            foreach (string part in splitString)
            {
                if (part.Contains('='))
                {
                    correctedSplitString.Add(part.Trim());
                    index++;
                }
                else
                {
                    if (index > 0)
                        correctedSplitString[index - 1] = correctedSplitString[index - 1] + ", " + part.Trim();
                    else
                        correctedSplitString.Add(part.Trim());
                    index++;
                }
            }
            return correctedSplitString.ToArray();
        }
    }



    enum ProtocolVersion : ushort
    {
        SSLv20 = 0x0002,
        SSLv30 = 0x0300,
        TLSv10 = 0x0301,
        TLSv11 = 0x0302,
        TLSv12 = 0x0303
    }

    enum SSLv2CipherSuite
    {        
        RC4_128_WITH_MD5              = 0x010080,
        RC4_128_EXPORT40_WITH_MD5     = 0x020080,
        RC2_128_CBC_WITH_MD5          = 0x030080,
        RC2_128_CBC_EXPORT40_WITH_MD5 = 0x040080,
        IDEA_128_CBC_WITH_MD5         = 0x050080,
        DES_64_CBC_WITH_MD5           = 0x060040,
        DES_192_EDE3_CBC_WITH_MD5     = 0x0700C0
    }

    enum SSLv3AndUpCipherSuite
    {		
		NULL_WITH_NULL_NULL                          = 0x0000,
		RSA_WITH_NULL_MD5                            = 0x0001,
		RSA_WITH_NULL_SHA                            = 0x0002,
		RSA_EXPORT_WITH_RC4_40_MD5                   = 0x0003,
		RSA_WITH_RC4_128_MD5                         = 0x0004,
		RSA_WITH_RC4_128_SHA                         = 0x0005,
		RSA_EXPORT_WITH_RC2_CBC_40_MD5               = 0x0006,
		RSA_WITH_IDEA_CBC_SHA                        = 0x0007,
		RSA_EXPORT_WITH_DES40_CBC_SHA                = 0x0008,
		RSA_WITH_DES_CBC_SHA                         = 0x0009,
		RSA_WITH_3DES_EDE_CBC_SHA                    = 0x000A,
		DH_DSS_EXPORT_WITH_DES40_CBC_SHA             = 0x000B,
		DH_DSS_WITH_DES_CBC_SHA                      = 0x000C,
		DH_DSS_WITH_3DES_EDE_CBC_SHA                 = 0x000D,
		DH_RSA_EXPORT_WITH_DES40_CBC_SHA             = 0x000E,
		DH_RSA_WITH_DES_CBC_SHA                      = 0x000F,
		DH_RSA_WITH_3DES_EDE_CBC_SHA                 = 0x0010,
		DHE_DSS_EXPORT_WITH_DES40_CBC_SHA            = 0x0011,
		DHE_DSS_WITH_DES_CBC_SHA                     = 0x0012,
		DHE_DSS_WITH_3DES_EDE_CBC_SHA                = 0x0013,
		DHE_RSA_EXPORT_WITH_DES40_CBC_SHA            = 0x0014,
		DHE_RSA_WITH_DES_CBC_SHA                     = 0x0015,
		DHE_RSA_WITH_3DES_EDE_CBC_SHA                = 0x0016,
		DH_anon_EXPORT_WITH_RC4_40_MD5               = 0x0017,
		DH_anon_WITH_RC4_128_MD5                     = 0x0018,
		DH_anon_EXPORT_WITH_DES40_CBC_SHA            = 0x0019,
		DH_anon_WITH_DES_CBC_SHA                     = 0x001A,
		DH_anon_WITH_3DES_EDE_CBC_SHA                = 0x001B,
        // SSLv3 Only RFC 6101
        FORTEZZA_KEA_WITH_NULL_SHA                   = 0x001C,
        FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA           = 0x001D,
        // Kerberos RFC 2712
        KRB5_WITH_DES_CBC_SHA                        = 0x001E,
        KRB5_WITH_3DES_EDE_CBC_SHA                   = 0x001F,
        KRB5_WITH_RC4_128_SHA                        = 0x0020,
        KRB5_WITH_IDEA_CBC_SHA                       = 0x0021,
        KRB5_WITH_DES_CBC_MD5                        = 0x0022,
        KRB5_WITH_3DES_EDE_CBC_MD5                   = 0x0023,
        KRB5_WITH_RC4_128_MD5                        = 0x0024,
        KRB5_WITH_IDEA_CBC_MD5                       = 0x0025,
        KRB5_EXPORT_WITH_DES_CBC_40_SHA              = 0x0026,
        KRB5_EXPORT_WITH_RC2_CBC_40_SHA              = 0x0027,
        KRB5_EXPORT_WITH_RC4_40_SHA                  = 0x0028,
        KRB5_EXPORT_WITH_DES_CBC_40_MD5              = 0x0029,
        KRB5_EXPORT_WITH_RC2_CBC_40_MD5              = 0x002A,
        KRB5_EXPORT_WITH_RC4_40_MD5                  = 0x002B,
        // RFC 4785
        PSK_WITH_NULL_SHA                            = 0x002C,
        DHE_PSK_WITH_NULL_SHA                        = 0x002D,
        RSA_PSK_WITH_NULL_SHA                        = 0x002E,
        // TLS 1.1
        RSA_WITH_AES_128_CBC_SHA                     = 0x002F,
        DH_DSS_WITH_AES_128_CBC_SHA                  = 0x0030,
        DH_RSA_WITH_AES_128_CBC_SHA                  = 0x0031,
        DHE_DSS_WITH_AES_128_CBC_SHA                 = 0x0032,
        DHE_RSA_WITH_AES_128_CBC_SHA                 = 0x0033,
        DH_anon_WITH_AES_128_CBC_SHA                 = 0x0034,
        RSA_WITH_AES_256_CBC_SHA                     = 0x0035,
        DH_DSS_WITH_AES_256_CBC_SHA                  = 0x0036,
        DH_RSA_WITH_AES_256_CBC_SHA                  = 0x0037,
        DHE_DSS_WITH_AES_256_CBC_SHA                 = 0x0038,
        DHE_RSA_WITH_AES_256_CBC_SHA                 = 0x0039,
        DH_anon_WITH_AES_256_CBC_SHA                 = 0x003A,
        // TLS 1.2
        RSA_WITH_NULL_SHA256                         = 0x003B,
        RSA_WITH_AES_128_CBC_SHA256                  = 0x003C,
        RSA_WITH_AES_256_CBC_SHA256                  = 0x003D,
        DH_DSS_WITH_AES_128_CBC_SHA256               = 0x003E,
        DH_RSA_WITH_AES_128_CBC_SHA256               = 0x003F,
        DHE_DSS_WITH_AES_128_CBC_SHA256              = 0x0040,
        DHE_RSA_WITH_AES_128_CBC_SHA256              = 0x0067,
        DH_DSS_WITH_AES_256_CBC_SHA256               = 0x0068,
        DH_RSA_WITH_AES_256_CBC_SHA256               = 0x0069,
        DHE_DSS_WITH_AES_256_CBC_SHA256              = 0x006A,
        DHE_RSA_WITH_AES_256_CBC_SHA256              = 0x006B,
        DH_anon_WITH_AES_128_CBC_SHA256              = 0x006C,
        DH_anon_WITH_AES_256_CBC_SHA256              = 0x006D,
        // RFC 5932
        RSA_WITH_CAMELLIA_128_CBC_SHA                = 0x0041,
        DH_DSS_WITH_CAMELLIA_128_CBC_SHA             = 0x0042,
        DH_RSA_WITH_CAMELLIA_128_CBC_SHA             = 0x0043,
        DHE_DSS_WITH_CAMELLIA_128_CBC_SHA            = 0x0044,
        DHE_RSA_WITH_CAMELLIA_128_CBC_SHA            = 0x0045,
        DH_anon_WITH_CAMELLIA_128_CBC_SHA            = 0x0046,
        RSA_WITH_CAMELLIA_256_CBC_SHA                = 0x0084,
        DH_DSS_WITH_CAMELLIA_256_CBC_SHA             = 0x0085,
        DH_RSA_WITH_CAMELLIA_256_CBC_SHA             = 0x0086,
        DHE_DSS_WITH_CAMELLIA_256_CBC_SHA            = 0x0087,
        DHE_RSA_WITH_CAMELLIA_256_CBC_SHA            = 0x0088,
        DH_anon_WITH_CAMELLIA_256_CBC_SHA            = 0x0089,
        // Misc. TLS
        TLS_PSK_WITH_RC4_128_SHA                     = 0x008A,
        TLS_PSK_WITH_3DES_EDE_CBC_SHA                = 0x008B,
        TLS_PSK_WITH_AES_128_CBC_SHA                 = 0x008C,
        TLS_PSK_WITH_AES_256_CBC_SHA                 = 0x008D,
        TLS_DHE_PSK_WITH_RC4_128_SHA                 = 0x008E,
        TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA            = 0x008F,
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA             = 0x0090,
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA             = 0x0091,
        TLS_RSA_PSK_WITH_RC4_128_SHA                 = 0x0092,
        TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA            = 0x0093,
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA             = 0x0094,
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA             = 0x0095,
        TLS_RSA_WITH_SEED_CBC_SHA                    = 0x0096,
        TLS_DH_DSS_WITH_SEED_CBC_SHA                 = 0x0097,
        TLS_DH_RSA_WITH_SEED_CBC_SHA                 = 0x0098,
        TLS_DHE_DSS_WITH_SEED_CBC_SHA                = 0x0099,
        TLS_DHE_RSA_WITH_SEED_CBC_SHA                = 0x009A,
        TLS_DH_anon_WITH_SEED_CBC_SHA                = 0x009B,
        TLS_RSA_WITH_AES_128_GCM_SHA256              = 0x009C,
        TLS_RSA_WITH_AES_256_GCM_SHA384              = 0x009D,
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256          = 0x009E,
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384          = 0x009F,
        TLS_DH_RSA_WITH_AES_128_GCM_SHA256           = 0x00A0,
        TLS_DH_RSA_WITH_AES_256_GCM_SHA384           = 0x00A1,
        TLS_DHE_DSS_WITH_AES_128_GCM_SHA256          = 0x00A2,
        TLS_DHE_DSS_WITH_AES_256_GCM_SHA384          = 0x00A3,
        TLS_DH_DSS_WITH_AES_128_GCM_SHA256           = 0x00A4,
        TLS_DH_DSS_WITH_AES_256_GCM_SHA384           = 0x00A5,
        TLS_DH_anon_WITH_AES_128_GCM_SHA256          = 0x00A6,
        TLS_DH_anon_WITH_AES_256_GCM_SHA384          = 0x00A7,
        TLS_PSK_WITH_AES_128_GCM_SHA256              = 0x00A8,
        TLS_PSK_WITH_AES_256_GCM_SHA384              = 0x00A9,
        TLS_DHE_PSK_WITH_AES_128_GCM_SHA256          = 0x00AA,
        TLS_DHE_PSK_WITH_AES_256_GCM_SHA384          = 0x00AB,
        TLS_RSA_PSK_WITH_AES_128_GCM_SHA256          = 0x00AC,
        TLS_RSA_PSK_WITH_AES_256_GCM_SHA384          = 0x00AD,
        TLS_PSK_WITH_AES_128_CBC_SHA256              = 0x00AE,
        TLS_PSK_WITH_AES_256_CBC_SHA384              = 0x00AF,
        TLS_PSK_WITH_NULL_SHA256                     = 0x00B0,
        TLS_PSK_WITH_NULL_SHA384                     = 0x00B1,
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA256          = 0x00B2,
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA384          = 0x00B3,
        TLS_DHE_PSK_WITH_NULL_SHA256                 = 0x00B4,
        TLS_DHE_PSK_WITH_NULL_SHA384                 = 0x00B5,
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA256          = 0x00B6,
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA384          = 0x00B7,
        TLS_RSA_PSK_WITH_NULL_SHA256                 = 0x00B8,
        TLS_RSA_PSK_WITH_NULL_SHA384                 = 0x00B9,
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256         = 0x00BA,
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256      = 0x00BB,
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256      = 0x00BC,
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256     = 0x00BD,
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256     = 0x00BE,
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256     = 0x00BF,
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256         = 0x00C0,
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256      = 0x00C1,
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256      = 0x00C2,
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256     = 0x00C3,
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256     = 0x00C4,
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256     = 0x00C5,
        TLS_ECDH_ECDSA_WITH_NULL_SHA                 = 0xC001,
        TLS_ECDH_ECDSA_WITH_RC4_128_SHA              = 0xC002,
        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA         = 0xC003,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA          = 0xC004,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA          = 0xC005,
        TLS_ECDHE_ECDSA_WITH_NULL_SHA                = 0xC006,
        TLS_ECDHE_ECDSA_WITH_RC4_128_SHA             = 0xC007,
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA        = 0xC008,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA         = 0xC009,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA         = 0xC00A,
        TLS_ECDH_RSA_WITH_NULL_SHA                   = 0xC00B,
        TLS_ECDH_RSA_WITH_RC4_128_SHA                = 0xC00C,
        TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA           = 0xC00D,
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA            = 0xC00E,
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA            = 0xC00F,
        TLS_ECDHE_RSA_WITH_NULL_SHA                  = 0xC010,
        TLS_ECDHE_RSA_WITH_RC4_128_SHA               = 0xC011,
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA          = 0xC012,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA           = 0xC013,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA           = 0xC014,
        TLS_ECDH_anon_WITH_NULL_SHA                  = 0xC015,
        TLS_ECDH_anon_WITH_RC4_128_SHA               = 0xC016,
        TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA          = 0xC017,
        TLS_ECDH_anon_WITH_AES_128_CBC_SHA           = 0xC018,
        TLS_ECDH_anon_WITH_AES_256_CBC_SHA           = 0xC019,
        TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA            = 0xC01A,
        TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA        = 0xC01B,
        TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA        = 0xC01C,
        TLS_SRP_SHA_WITH_AES_128_CBC_SHA             = 0xC01D,
        TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA         = 0xC01E,
        TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA         = 0xC01F,
        TLS_SRP_SHA_WITH_AES_256_CBC_SHA             = 0xC020,
        TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA         = 0xC021,
        TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA         = 0xC022,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256      = 0xC023,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384      = 0xC024,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256       = 0xC025,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384       = 0xC026,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256        = 0xC027,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384        = 0xC028,
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256         = 0xC029,
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384         = 0xC02A,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      = 0xC02B,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384      = 0xC02C,
        TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256       = 0xC02D,
        TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384       = 0xC02E,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256        = 0xC02F,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384        = 0xC030,
        TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256         = 0xC031,
        TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384         = 0xC032,
        TLS_ECDHE_PSK_WITH_RC4_128_SHA               = 0xC033,
        TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA          = 0xC034,
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA           = 0xC035,
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA           = 0xC036,
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256        = 0xC037,
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384        = 0xC038,
        TLS_ECDHE_PSK_WITH_NULL_SHA                  = 0xC039,
        TLS_ECDHE_PSK_WITH_NULL_SHA256               = 0xC03A,
        TLS_ECDHE_PSK_WITH_NULL_SHA384               = 0xC03B,
        TLS_RSA_WITH_ARIA_128_CBC_SHA256             = 0xC03C,
        TLS_RSA_WITH_ARIA_256_CBC_SHA384             = 0xC03D,
        TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256          = 0xC03E,
        TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384          = 0xC03F,
        TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256          = 0xC040,
        TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384          = 0xC041,
        TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256         = 0xC042,
        TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384         = 0xC043,
        TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256         = 0xC044,
        TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384         = 0xC045,
        TLS_DH_anon_WITH_ARIA_128_CBC_SHA256         = 0xC046,
        TLS_DH_anon_WITH_ARIA_256_CBC_SHA384         = 0xC047,
        TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256     = 0xC048,
        TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384     = 0xC049,
        TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256      = 0xC04A,
        TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384      = 0xC04B,
        TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256       = 0xC04C,
        TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384       = 0xC04D,
        TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256        = 0xC04E,
        TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384        = 0xC04F,
        TLS_RSA_WITH_ARIA_128_GCM_SHA256             = 0xC050,
        TLS_RSA_WITH_ARIA_256_GCM_SHA384             = 0xC051,
        TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256         = 0xC052,
        TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384         = 0xC053,
        TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256          = 0xC054,
        TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384          = 0xC055,
        TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256         = 0xC056,
        TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384         = 0xC057,
        TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256          = 0xC058,
        TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384          = 0xC059,
        TLS_DH_anon_WITH_ARIA_128_GCM_SHA256         = 0xC05A,
        TLS_DH_anon_WITH_ARIA_256_GCM_SHA384         = 0xC05B,
        TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256     = 0xC05C,
        TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384     = 0xC05D,
        TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256      = 0xC05E,
        TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384      = 0xC05F,
        TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256       = 0xC060,
        TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384       = 0xC061,
        TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256        = 0xC062,
        TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384        = 0xC063,
        TLS_PSK_WITH_ARIA_128_CBC_SHA256             = 0xC064,
        TLS_PSK_WITH_ARIA_256_CBC_SHA384             = 0xC065,
        TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256         = 0xC066,
        TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384         = 0xC067,
        TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256         = 0xC068,
        TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384         = 0xC069,
        TLS_PSK_WITH_ARIA_128_GCM_SHA256             = 0xC06A,
        TLS_PSK_WITH_ARIA_256_GCM_SHA384             = 0xC06B,
        TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256         = 0xC06C,
        TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384         = 0xC06D,
        TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256         = 0xC06E,
        TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384         = 0xC06F,
        TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256       = 0xC070,
        TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384       = 0xC071,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC072,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC073,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  = 0xC074,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  = 0xC075,
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   = 0xC076,
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384   = 0xC077,
        TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256    = 0xC078,
        TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384    = 0xC079,
        TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256         = 0xC07A,
        TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384         = 0xC07B,
        TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256     = 0xC07C,
        TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384     = 0xC07D,
        TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256      = 0xC07E,
        TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384      = 0xC07F,
        TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256     = 0xC080,
        TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384     = 0xC081,
        TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256      = 0xC082,
        TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384      = 0xC083,
        TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256     = 0xC084,
        TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384     = 0xC085,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC086,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC087,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  = 0xC088,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  = 0xC089,
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256   = 0xC08A,
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384   = 0xC08B,
        TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256    = 0xC08C,
        TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384    = 0xC08D,
        TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256         = 0xC08E,
        TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384         = 0xC08F,
        TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256     = 0xC090,
        TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384     = 0xC091,
        TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256     = 0xC092,
        TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384     = 0xC093,
        TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256         = 0xC094,
        TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384         = 0xC095,
        TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256     = 0xC096,
        TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384     = 0xC097,
        TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256     = 0xC098,
        TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384     = 0xC099,
        TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256   = 0xC09A,
        TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384   = 0xC09B,
        TLS_RSA_WITH_AES_128_CCM                     = 0xC09C,
        TLS_RSA_WITH_AES_256_CCM                     = 0xC09D,
        TLS_DHE_RSA_WITH_AES_128_CCM                 = 0xC09E,
        TLS_DHE_RSA_WITH_AES_256_CCM                 = 0xC09F,
        TLS_RSA_WITH_AES_128_CCM_8                   = 0xC0A0,
        TLS_RSA_WITH_AES_256_CCM_8                   = 0xC0A1,
        TLS_DHE_RSA_WITH_AES_128_CCM_8               = 0xC0A2,
        TLS_DHE_RSA_WITH_AES_256_CCM_8               = 0xC0A3,
        TLS_PSK_WITH_AES_128_CCM                     = 0xC0A4,
        TLS_PSK_WITH_AES_256_CCM                     = 0xC0A5,
        TLS_DHE_PSK_WITH_AES_128_CCM                 = 0xC0A6,
        TLS_DHE_PSK_WITH_AES_256_CCM                 = 0xC0A7,
        TLS_PSK_WITH_AES_128_CCM_8                   = 0xC0A8,
        TLS_PSK_WITH_AES_256_CCM_8                   = 0xC0A9,
        TLS_PSK_DHE_WITH_AES_128_CCM_8               = 0xC0AA,
        TLS_PSK_DHE_WITH_AES_256_CCM_8               = 0xC0AB
    }
}
