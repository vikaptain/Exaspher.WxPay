using System;
using System.IO;
using System.Security.Cryptography;

namespace Exaspher.WxPay.Core
{
	public class SHAFile
	{
		/// <summary>
		/// 计算文件的 SHA256 值
		/// </summary>
		/// <param name="fileName">要计算 SHA256 值的文件名和路径</param>
		/// <returns>SHA256值16进制字符串</returns>
		public static string SHA256File(string fileName)
		{
			return HashFile(fileName, "sha256");
		}

		/// <summary>
		/// 计算文件的哈希值
		/// </summary>
		/// <param name="fileName">要计算哈希值的文件名和路径</param>
		/// <param name="algName">算法:sha1,md5</param>
		/// <returns>哈希值16进制字符串</returns>
		private static string HashFile(string fileName, string algName)
		{
			if (!System.IO.File.Exists(fileName))
				return string.Empty;

			FileStream fs = new FileStream(fileName, FileMode.Open, FileAccess.Read);
			byte[] hashBytes = HashData(fs, algName);
			fs.Close();
			return ByteArrayToHexString(hashBytes);
		}

		/// <summary>
		/// 字节数组转换为16进制表示的字符串
		/// </summary>
		private static string ByteArrayToHexString(byte[] buf)
		{
			string returnStr = "";
			if (buf != null)
			{
				for (int i = 0; i < buf.Length; i++)
				{
					returnStr += buf[i].ToString("X2");
				}
			}
			return returnStr;
		}

		/// <summary>
		/// 计算哈希值
		/// </summary>
		/// <param name="stream">要计算哈希值的 Stream</param>
		/// <param name="algName">算法:sha1,md5</param>
		/// <returns>哈希值字节数组</returns>
		private static byte[] HashData(Stream stream, string algName)
		{
			HashAlgorithm algorithm;
			if (algName == null)
			{
				throw new ArgumentNullException("algName 不能为 null");
			}
			if (string.Compare(algName, "sha256", true) == 0)
			{
				algorithm = SHA256.Create();
			}
			else
			{
				if (string.Compare(algName, "md5", true) != 0)
				{
					throw new Exception("algName 只能使用 sha256 或 md5");
				}
				algorithm = MD5.Create();
			}
			return algorithm.ComputeHash(stream);
		}
	}
}