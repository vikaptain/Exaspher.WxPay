using Exaspher.WxPay.Core.Util;
using System;
using System.Collections.Generic;
using System.Text;

namespace Exaspher.WxPay.Core
{
	public class SignUtil
	{
		public static string GetSign(string method, string url, string nonce_str, string content, string keyFile, string password)
		{
			var list = new List<string> { method, url, nonce_str, content };
			var data = string.Join("\n", list);
			var p = EncryptUtil.SHA256WithRSA(data, keyFile, password);
			return Convert.ToBase64String(Encoding.UTF8.GetBytes(p));
		}
	}
}