using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Exaspher.WxPay.Core
{
	public class HttpHandler : DelegatingHandler
	{
		private readonly string _merchantId;
		private readonly string _serialNo;
		private readonly RSA _privateKey;
		private readonly string _json;
		private readonly X509Certificate2 _merchantCertificate;
		private readonly string _platformSerialNo;

		/// <summary>
		/// 构造方法
		/// </summary>
		/// <param name="merchantId">商户号</param>
		/// <param name="merchantSerialNo">平台证书序列号</param>
		/// <param name="platformSerialNo"></param>
		/// <param name="privateKey"> 私钥不包括私钥文件起始的-----BEGIN PRIVATE KEY-----        亦不包括结尾的-----END PRIVATE KEY-----</param>
		/// <param name="merchantCertificate"></param>
		/// <param name="certPassword"></param>
		/// <param name="json">签名json数据,默认不需要传入，获取body内容，如传入签名传入参数上传图片时需传入</param>
		public HttpHandler(string merchantId, string merchantSerialNo, string platformSerialNo, RSA privateKey, X509Certificate2 merchantCertificate, string json = default(string))
		{
			var handler = new HttpClientHandler
			{
				ClientCertificateOptions = ClientCertificateOption.Manual,
				SslProtocols = SslProtocols.Tls12
			};
			try
			{
				handler.ClientCertificates.Add(merchantCertificate);
			}
			catch (Exception e)
			{
				throw new Exception("ca err(证书错误)");
			}
			handler.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls;
			handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
			InnerHandler = handler;
			_merchantId = merchantId;
			_serialNo = merchantSerialNo;
			_privateKey = privateKey;
			_json = json;
			_merchantCertificate = merchantCertificate;
			_platformSerialNo = platformSerialNo;
		}

		protected override async Task<HttpResponseMessage> SendAsync(
			HttpRequestMessage request,
			CancellationToken cancellationToken)
		{
			var auth = await BuildAuthAsync(request);
			request.Headers.Add("Authorization", $"WECHATPAY2-SHA256-RSA2048 {auth}");
			request.Headers.Add("Wechatpay-Serial", _platformSerialNo);
			request.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36");
			MediaTypeWithQualityHeaderValue mediaTypeWithQualityHeader = new MediaTypeWithQualityHeaderValue("application/json");
			request.Headers.Accept.Add(mediaTypeWithQualityHeader);
			request.Headers.AcceptCharset.Add(new StringWithQualityHeaderValue("utf-8"));
			return await base.SendAsync(request, cancellationToken);
		}

		protected async Task<string> BuildAuthAsync(HttpRequestMessage request)
		{
			var method = request.Method.ToString();
			var body = "";
			if (method == "POST" || method == "PUT" || method == "PATCH")
			{
				if (!string.IsNullOrEmpty(_json))
				{
					body = _json;
				}
				else
				{
					var content = request.Content;
					body = await content.ReadAsStringAsync();
				}
			}
			var uri = request.RequestUri.PathAndQuery;
			var timestamp = DateTimeOffset.Now.ToUnixTimeSeconds();
			var nonce = Guid.NewGuid().ToString("n");
			var message = $"{method}\n{uri}\n{timestamp}\n{nonce}\n{body}\n";
			var signature = Sign(message);
			return $"mchid=\"{_merchantId}\",nonce_str=\"{nonce}\",timestamp=\"{timestamp}\",serial_no=\"{_serialNo}\",signature=\"{signature}\"";
		}

		protected string Sign(string message)
		{
			// using var cngKey = CngKey.Import(Convert.FromBase64String(), CngKeyBlobFormat.Pkcs8PrivateBlob);

			var privateKey = @"MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQCuer7ujvbwQfjD
oPDC5k96oNeiAhK16B4EZJX1iv2xapfaeVlTHE3XUQmW3sFcZk7MC3zQK3qj5SVr
VkD41dg/KdKoWx589O75Mm3qhKl9nqR2jth07ruAEk3dbKRNbS1JvrXpa1rLDs/y
7kNzdoehFytekpTbCwVvhgRFYG65ECM/JE6gHv2TpOcsDtvz2D+MdeS4l3XRgiQf
khtRdRP59mwa+wI7BNWIphHMbQQ9Kbl/fkxlIsjM5RZdLJ2il6DYceBeiTLX2IpW
oitc5sDZpnwNYfZVQEu/JUALX5U4BK9IJwJRvK7lKPSTXYpC4R+Xxr1CnCFd0ILf
9lyUMCnzAgMBAAECggEBAIpjpz82O9zSpsobw/sCi7W7D21bcZXAttZLJbos9Q2c
ezd5GoVWJNOMXivBIOL17rfewK+oXMzUOnrJXh1AGBX5STHpm+QGrekPu6jQclLF
2rKCmGMe2684VXQz8JnM56ffURAD6261n/CSVQOm1urJosePQev+8N/FD2wrkYbM
Wo3dIXBdJIT1U9n9W76nUnAUVToCGhXLf7G3yUDL02Dy1e49l0VdtrJlrDJwhngA
HCZQpS56737NnFtT9PC6r+hsTzTn1xeewzxm7Q2LZmIfj0FfVacGCwWsG3WGisEo
KojYLx9702hixCtxFiNZ0nxRBkNak6ao8/tzhB0olWECgYEA5ZyZuWTiQlARXDrZ
+7iE61B8RDkqC0UlL2a0QSIa8B+xM48VLBMOhR65W9VYIQkeN2GqDZEuDdtOpR95
Tj+c6eAtgM17nToinFiTHjbjLtHD9frbNeWSVfsJYcE0+t4aOGyUUDV9mfbmF99n
5iqnZ7lDBJvsm3h7jdc01qrmEKMCgYEAwogZ6kCEzX7QQe8tLLmQhSp2n6xy8kYC
JMw2zjg2KbghTepGizgqQutHliyuLf6r1Pr7Tp3SN4KH+2xqkD0sRASIrF526avs
sKg99WS8JTLEGxbw6snV+DDECZTIgMDSUbMP+FDrEFwAWBCvEI2TW1H7DZkzvbzi
xAyk5t+1BnECgYEAxeh897dk7hNlY0G2sakRqGHvOj6rZptqubiklZ936JDog7BI
Z3zlfwhEbEsvcwoQ6Vtc3+TK9VaaKuk9/ZwG++8mSWbTrWl2e5w88kYM+0YCyfo3
B/WgdEu0gnWt3K2jnA66p4fzgsm0+c6uF02cjWK5yTc8caUfmdpsyLr1IlECgYEA
kKceBif12Mzs1aqhv/k4sx0xWmikjO1sGKrWMiBwfjNSaJrF3C5mlp5X/B67Yq5W
XihHiV0n/WkN7vLehuVGLknky6/u4rGabn6cnAZNNaf7VV2Ixj5R4p14mNtPARbh
DimFvZOGSALxqoq1cyyjn6tlcOY0KGn1ge0ZDijZdrECgYEAvM1u51zibVU8lp5T
76RkEVWoVNThkW3yWy2wyFU3OT25QC583sCzLLQ2EAbGX4MEf1n6rHCduUuduDs8
uJI60i7Fxfr6wEefozHLvO/JDBhdwzzYDemTQKxR708ZO/IV1zhFIdWXy3HtKnHK
qkIlerjtpwO6pXtg0tUgqt74ySI=";


			byte[] keyData = Convert.FromBase64String(privateKey);
			using (CngKey cngKey = CngKey.Import(keyData, CngKeyBlobFormat.Pkcs8PrivateBlob))
			using (RSACng rsa = new RSACng(cngKey))
			{
				byte[] data = System.Text.Encoding.UTF8.GetBytes(message);
				return Convert.ToBase64String(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
			}

			//using var rsa = new RSACng(cngKey);

			//var data = System.Text.Encoding.UTF8.GetBytes(message);
			//return Convert.ToBase64String(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
		}
	}
}