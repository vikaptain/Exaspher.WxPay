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
		private readonly string merchantId;
		private readonly string serialNo;
		private readonly string privateKey;
		private readonly string json;

		/// <summary>
		/// 构造方法
		/// </summary>
		/// <param name="merchantId">商户号</param>
		/// <param name="merchantSerialNo">证书序列号</param>
		/// <param name="privateKey"> 私钥不包括私钥文件起始的-----BEGIN PRIVATE KEY-----        亦不包括结尾的-----END PRIVATE KEY-----</param>
		/// <param name="json">签名json数据,默认不需要传入，获取body内容，如传入签名传入参数上传图片时需传入</param>
		public HttpHandler(string merchantId, string merchantSerialNo, string privateKey, string json = "")
		{
			var handler = new HttpClientHandler
			{
				ClientCertificateOptions = ClientCertificateOption.Manual,
				SslProtocols = SslProtocols.Tls12
			};
			try
			{
				string certPath = System.IO.Path.Combine(Environment.CurrentDirectory, @"cert\apiclient_cert.p12");
				handler.ClientCertificates.Add(new X509Certificate2(certPath, "1596462601",
					X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet));
			}
			catch (Exception e)
			{
				throw new Exception("ca err(证书错误)");
			}
			handler.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls;
			handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
			InnerHandler = handler;
			this.merchantId = merchantId;
			this.serialNo = merchantSerialNo;
			this.privateKey = privateKey;
			this.json = json;
		}

		protected override async Task<HttpResponseMessage> SendAsync(
			HttpRequestMessage request,
			CancellationToken cancellationToken)
		{
			var auth = await BuildAuthAsync(request);
			string value = $"WECHATPAY2-SHA256-RSA2048 {auth}";
			request.Headers.Add("Authorization", value);
			request.Headers.Add("Wechatpay-Serial", serialNo);
			request.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36");
			MediaTypeWithQualityHeaderValue mediaTypeWithQualityHeader = new MediaTypeWithQualityHeaderValue("application/json");
			request.Headers.Accept.Add(mediaTypeWithQualityHeader);
			request.Headers.AcceptCharset.Add(new StringWithQualityHeaderValue("utf-8"));
			return await base.SendAsync(request, cancellationToken);
		}

		protected async Task<string> BuildAuthAsync(HttpRequestMessage request)
		{
			string method = request.Method.ToString();
			string body = "";
			if (method == "POST" || method == "PUT" || method == "PATCH")
			{
				if (!string.IsNullOrEmpty(json))
					body = json;
				else
				{
					var content = request.Content;
					body = await content.ReadAsStringAsync();
				}
			}
			string uri = request.RequestUri.PathAndQuery;
			var timestamp = DateTimeOffset.Now.ToUnixTimeSeconds();
			string nonce = Guid.NewGuid().ToString("n");
			string message = $"{method}\n{uri}\n{timestamp}\n{nonce}\n{body}\n";
			string signature = Sign(message);
			return $"mchid=\"{merchantId}\",nonce_str=\"{nonce}\",timestamp=\"{timestamp}\",serial_no=\"{serialNo}\",signature=\"{signature}\"";
		}

		protected string Sign(string message)
		{
			byte[] keyData = Convert.FromBase64String(privateKey);
			using (CngKey cngKey = CngKey.Import(keyData, CngKeyBlobFormat.Pkcs8PrivateBlob))
			using (RSACng rsa = new RSACng(cngKey))
			{
				byte[] data = System.Text.Encoding.UTF8.GetBytes(message);
				return Convert.ToBase64String(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
			}
		}
	}
}