using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Exaspher.WxPay.Core.Util
{
	/// <summary>
	/// RSA算法类型
	/// </summary>
	public enum RSAType
	{
		/// <summary>
		/// SHA1
		/// </summary>
		RSA = 0,

		/// <summary>
		/// RSA2 密钥长度至少为2048
		/// SHA256
		/// </summary>
		RSA2
	}

	public class RSAHelper
	{
		private readonly RSA _privateKeyRsaProvider;
		private readonly RSA _publicKeyRsaProvider;
		private readonly HashAlgorithmName _hashAlgorithmName;
		private readonly Encoding _encoding;

		/// <summary>
		/// 实例化RSAHelper
		/// </summary>
		/// <param name="rsaType">加密算法类型 RSA SHA1;RSA2 SHA256 密钥长度至少为2048</param>
		/// <param name="encoding">编码类型</param>
		/// <param name="privateKey">私钥</param>
		/// <param name="publicKey">公钥</param>
		public RSAHelper(RSAType rsaType, Encoding encoding, string privateKey, string publicKey = null)
		{
			_encoding = encoding;
			if (!string.IsNullOrEmpty(privateKey))
			{
				_privateKeyRsaProvider = CreateRsaProviderFromPrivateKey(privateKey);
			}

			if (!string.IsNullOrEmpty(publicKey))
			{
				_publicKeyRsaProvider = CreateRsaProviderFromPublicKey(publicKey);
			}

			_hashAlgorithmName = rsaType == RSAType.RSA ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
		}

		public string Encrypt(string text)
		{
			if (_publicKeyRsaProvider == null)
			{
				throw new Exception("_publicKeyRsaProvider is null");
			}
			return Convert.ToBase64String(_publicKeyRsaProvider.Encrypt(Encoding.UTF8.GetBytes(text), RSAEncryptionPadding.Pkcs1));
		}

		public RSA CreateRsaProviderFromPublicKey(string publicKeyString)
		{
			// encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
			byte[] seqOid = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
			byte[] seq = new byte[15];

			var x509Key = Convert.FromBase64String(publicKeyString);

			// ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
			using (MemoryStream mem = new MemoryStream(x509Key))
			{
				using (BinaryReader binr = new BinaryReader(mem))  //wrap Memory Stream with BinaryReader for easy reading
				{
					byte bt = 0;
					ushort twobytes = 0;

					twobytes = binr.ReadUInt16();
					if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
						binr.ReadByte();    //advance 1 byte
					else if (twobytes == 0x8230)
						binr.ReadInt16();   //advance 2 bytes
					else
						return null;

					seq = binr.ReadBytes(15);       //read the Sequence OID
					if (!CompareBytearrays(seq, seqOid))    //make sure Sequence for OID is correct
						return null;

					twobytes = binr.ReadUInt16();
					if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
						binr.ReadByte();    //advance 1 byte
					else if (twobytes == 0x8203)
						binr.ReadInt16();   //advance 2 bytes
					else
						return null;

					bt = binr.ReadByte();
					if (bt != 0x00)     //expect null byte next
						return null;

					twobytes = binr.ReadUInt16();
					if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
						binr.ReadByte();    //advance 1 byte
					else if (twobytes == 0x8230)
						binr.ReadInt16();   //advance 2 bytes
					else
						return null;

					twobytes = binr.ReadUInt16();
					byte lowbyte = 0x00;
					byte highbyte = 0x00;

					if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
						lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
					else if (twobytes == 0x8202)
					{
						highbyte = binr.ReadByte(); //advance 2 bytes
						lowbyte = binr.ReadByte();
					}
					else
						return null;
					byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
					int modsize = BitConverter.ToInt32(modint, 0);

					int firstbyte = binr.PeekChar();
					if (firstbyte == 0x00)
					{   //if first byte (highest order) of modulus is zero, don't include it
						binr.ReadByte();    //skip this null byte
						modsize -= 1;   //reduce modulus buffer size by 1
					}

					byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

					if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
						return null;
					int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
					byte[] exponent = binr.ReadBytes(expbytes);

					// ------- create RSACryptoServiceProvider instance and initialize with public key -----
					var rsa = RSA.Create();
					RSAParameters rsaKeyInfo = new RSAParameters
					{
						Modulus = modulus,
						Exponent = exponent
					};
					rsa.ImportParameters(rsaKeyInfo);

					return rsa;
				}
			}
		}

		private bool CompareBytearrays(byte[] a, byte[] b)
		{
			if (a.Length != b.Length)
				return false;
			int i = 0;
			foreach (byte c in a)
			{
				if (c != b[i])
					return false;
				i++;
			}
			return true;
		}

		public RSA CreateRsaProviderFromPrivateKey(string privateKey)
		{
			var privateKeyBits = Convert.FromBase64String(privateKey);

			var rsa = RSA.Create();
			var rsaParameters = new RSAParameters();

			using (BinaryReader binr = new BinaryReader(new MemoryStream(privateKeyBits)))
			{
				byte bt = 0;
				ushort twobytes = 0;
				twobytes = binr.ReadUInt16();
				if (twobytes == 0x8130)
					binr.ReadByte();
				else if (twobytes == 0x8230)
					binr.ReadInt16();
				else
					throw new Exception("Unexpected value read binr.ReadUInt16()");

				twobytes = binr.ReadUInt16();
				if (twobytes != 0x0102)
					throw new Exception("Unexpected version");

				bt = binr.ReadByte();
				if (bt != 0x00)
					throw new Exception("Unexpected value read binr.ReadByte()");

				rsaParameters.Modulus = binr.ReadBytes(GetIntegerSize(binr));
				rsaParameters.Exponent = binr.ReadBytes(GetIntegerSize(binr));
				rsaParameters.D = binr.ReadBytes(GetIntegerSize(binr));
				rsaParameters.P = binr.ReadBytes(GetIntegerSize(binr));
				rsaParameters.Q = binr.ReadBytes(GetIntegerSize(binr));
				rsaParameters.DP = binr.ReadBytes(GetIntegerSize(binr));
				rsaParameters.DQ = binr.ReadBytes(GetIntegerSize(binr));
				rsaParameters.InverseQ = binr.ReadBytes(GetIntegerSize(binr));
			}

			rsa.ImportParameters(rsaParameters);
			return rsa;
		}

		private int GetIntegerSize(BinaryReader binr)
		{
			byte bt = 0;
			int count = 0;
			bt = binr.ReadByte();
			if (bt != 0x02)
				return 0;
			bt = binr.ReadByte();

			if (bt == 0x81)
				count = binr.ReadByte();
			else
			if (bt == 0x82)
			{
				var highbyte = binr.ReadByte();
				var lowbyte = binr.ReadByte();
				byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
				count = BitConverter.ToInt32(modint, 0);
			}
			else
			{
				count = bt;
			}

			while (binr.ReadByte() == 0x00)
			{
				count -= 1;
			}
			binr.BaseStream.Seek(-1, SeekOrigin.Current);
			return count;
		}
	}

	public class EncryptUtil
	{
		public static string RSAEncrypt(string text, byte[] publicKey)
		{
			var rsa = RSA.Create();

			rsa.ImportRSAPublicKey(publicKey, out var bytesRead);

			var encrypt = rsa.Encrypt(System.Text.Encoding.Default.GetBytes(text), RSAEncryptionPadding.OaepSHA256);

			return Convert.ToBase64String(encrypt);
		}

		public static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
		{
			try
			{
				byte[] encryptedData;
				//Create a new instance of RSACryptoServiceProvider.
				using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
				{
					//Import the RSA Key information. This only needs
					//toinclude the public key information.
					RSA.ImportParameters(RSAKeyInfo);

					//Encrypt the passed byte array and specify OAEP padding.
					//OAEP padding is only available on Microsoft Windows XP or
					//later.
					encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
				}
				return encryptedData;
			}
			//Catch and display a CryptographicException
			//to the console.
			catch (CryptographicException e)
			{
				Console.WriteLine(e.Message);

				return null;
			}
		}

		private static X509Certificate2 GetCertificateFromStore(string certName)
		{
			// Get the certificate store for the current user.
			X509Store store = new X509Store(StoreLocation.CurrentUser);
			try
			{
				store.Open(OpenFlags.ReadOnly);

				// Place all certificates in an X509Certificate2Collection object.
				X509Certificate2Collection certCollection = store.Certificates;
				// If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
				// currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
				X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
				X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
				if (signingCert.Count == 0)
					return null;
				// Return the first certificate in the collection, has the right name and is current.
				return signingCert[0];
			}
			finally
			{
				store.Close();
			}
		}

		/// <summary>
		///
		/// </summary>
		/// <param name="data"></param>
		/// <param name="keyFile"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public static string SHA256WithRSA(string data, string keyFile, string password)
		{
			// using RSACryptoServiceProvider sha256 = new RSACryptoServiceProvider();

			CspParameters RSAParams = new CspParameters();
			RSAParams.Flags = CspProviderFlags.UseMachineKeyStore;
			System.Security.Cryptography.RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024, RSAParams);

			var privateKey = GetPrivateKey(keyFile, password);
			var dataInBytes = Encoding.UTF8.GetBytes(data);
			rsa.FromXmlString(privateKey);
			var inArray = rsa.SignData(dataInBytes, CryptoConfig.MapNameToOID("SHA256"));
			var sign = Convert.ToBase64String(inArray);
			return sign;
		}

		private static string GetPrivateKey(string path, string password)
		{
			try
			{
				var cert = new X509Certificate2(path, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
				return cert.PrivateKey.ToXmlString(true);
			}
			catch (Exception e)
			{
				return "";
			}
		}
	}
}