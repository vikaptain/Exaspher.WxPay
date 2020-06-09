using Exaspher.WxPay.Core.Dto;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using RSAExtensions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using JsonSerializer = System.Text.Json.JsonSerializer;

namespace Exaspher.WxPay.Core
{
	public class WxPayService : IWxPayService
	{
		private readonly IConfiguration _configuration;
		private readonly IHostEnvironment _hostEnvironment;

		private readonly string _mchId;
		private readonly string _serialNo;

		public WxPayService(IConfiguration configuration, IHostEnvironment hostEnvironment)
		{
			_configuration = configuration;
			_hostEnvironment = hostEnvironment;
			_mchId = _configuration.GetValue<string>("WxPay:MchId");
			_serialNo = _configuration.GetValue<string>("WxPay:SerialNo");
		}

		public async Task<object> ApplyMent()
		{
			var nonce = GenerateNonce();

			#region 传入数据

			var applyment = new ApplyMentDto();
			applyment.BusinessCode = "X00000000001";
			applyment.ContactInfo = new ApplyMentContactInfoDto()
			{
				ContactName = "张三",
				// OpenId = "1312321",
				ContactIdNumber = "511111111111111111",
				MobilePhone = "13333333333",
				ContactEmail = "11@gmail.com",
			};
			applyment.SubjectInfo = new ApplyMentSubjectInfo()
			{
				SubjectType = "SUBJECT_TYPE_INDIVIDUAL",
				BusinessLicenseInfo = new ApplyMentBusinessLicenseInfo()
				{
					LicenseCopy = "tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk",
					LicenseNumber = "91440300MA5EYUKH2K",
					MerchantName = "张三餐饮店",
					LegalPerson = "张三"
				},
				IdentityInfo = new ApplyMentIdentityInfo()
				{
					IdDocType = "IDENTIFICATION_TYPE_IDCARD",
					IdCardInfo = new ApplyMentIdCardInfo()
					{
						IdCardCopy = "tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk",
						IdCardNational = "tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk",
						IdCardName = "张三",
						IdCardNumber = "511111111111111111",
						CardPeriodBegin = "2010-01-01",
						CardPeriodEnd = "长期",
					},
					Owner = true
				},
			};
			applyment.BusinessInfo = new ApplyMentBusinessInfo()
			{
				MerchantShortName = "张三餐饮店",
				ServicePhone = "13333333333",
				SalesInfo = new ApplyMentSalesInfo()
				{
					SalesScenesType = new List<string>() { "SALES_SCENES_STORE" },
					BizStorInfo = new ApplyMentBizStorInfo()
					{
						BizStoreName = "张三餐饮店",
						BizAddressCode = "440305",
						BizStoreAddress = "南山区xx大厦x层xxxx室",
						StoreEntrancePic = new List<string>()
						{
							"tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk"
						},
						IndoorPic = new List<string>()
						{
							"tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk"
						}
					}
				}
			};
			applyment.SettlementInfo = new ApplyMentSettlementInfo()
			{
				SettlementId = "719",
				QualificationType = "餐饮",
				Qualifications = new List<string>()
				{
					"tV7icXfN8VX58X0D187-NV08cFGRlx6LPg261cpQDI-asaq-0MXen3N7OVE5lDbStaS8nBBbBlv6hL3er8bDK-djRp4PtWGArfr9Numqxsk"
				},
				ActivitiesAdditions = new List<string>(),
			};
			applyment.Encrypt(GetPublicCertificate().PublicKey.Key as RSA);

			#endregion 传入数据

			var jsonContent = JsonSerializer.Serialize(applyment);

			var httpHandler = new HttpHandler(_mchId, _serialNo, GetPublicCertificate().SerialNumber, GetPrivateCertificate(), GetMerchantCertificate());
			var client = new HttpClient(httpHandler);

			var request = new HttpRequestMessage(HttpMethod.Post,
				"https://api.mch.weixin.qq.com/v3/applyment4sub/applyment/")
			{
				Content = new StringContent(jsonContent, Encoding.UTF8, "application/json")
			};

			var response = await client.SendAsync(request);
			var result = await response.Content.ReadAsStringAsync();
			if (response.StatusCode != HttpStatusCode.OK)
			{
			}

			return string.Empty;
		}

		public async Task GetCertificates()
		{
			HttpClient client = new HttpClient();

			var mchid = _configuration.GetValue<string>("WxPay:MchId");
			var serial_no = _configuration.GetValue<string>("WxPay:SerialNo");

			var nonce_str = Guid.NewGuid().ToString();
			TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
			var timestamp = Convert.ToInt64(ts.TotalSeconds).ToString();

			HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "https://api.mch.weixin.qq.com/v3/certificates");

			client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("WECHATPAY2-SHA256-RSA2048", await BuildAuthAsync(request, mchid, serial_no, nonce_str));
			client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

			var response = await client.SendAsync(request);
			var result = await response.Content.ReadAsStringAsync();
			if (response.StatusCode != HttpStatusCode.OK)
			{
			}
		}

		public async Task<string> Upload(string fileName, byte[] buffer)
		{
			var boundary = $"--{DateTime.Now.Ticks:x}";

			#region 文件SHA256

			HashAlgorithm algorithm = SHA256.Create();
			var hashBytes = algorithm.ComputeHash(buffer);

			var sb = new StringBuilder();
			foreach (var b in hashBytes)
			{
				sb.Append(Convert.ToString(b, 16).PadLeft(2, '0'));
			}

			var sha256 = sb.ToString().ToUpper();

			#endregion

			var meta = new
			{
				sha256 = sha256,
				filename = fileName
			};

			var jsonContent = JsonConvert.SerializeObject(meta);

			var httpHandler = new HttpHandler(_mchId, _serialNo, GetPublicCertificate().SerialNumber, GetPrivateCertificate(), GetMerchantCertificate(), jsonContent);
			var client = new HttpClient(httpHandler);
			using var requestContent = new MultipartFormDataContent(boundary);
			requestContent.Headers.ContentType = MediaTypeHeaderValue.Parse("multipart/form-data"); //这里必须添加
			requestContent.Add(new StringContent(jsonContent, Encoding.UTF8, "application/json"), "\"meta\"");
			
			var byteArrayContent = new ByteArrayContent(buffer);
			byteArrayContent.Headers.ContentType = new MediaTypeHeaderValue("image/jpg");
			requestContent.Add(byteArrayContent, "\"file\"", "\"" + meta.filename + "\"");  //这里主要必须要双引号
			using var response = await client.PostAsync("https://api.mch.weixin.qq.com/v3/merchant/media/upload", requestContent);
			using var responseContent = response.Content;
			var responseBody = await responseContent.ReadAsStringAsync(); //这里就可以拿到图片id了
			// return ResultHelper.QuickReturn(responseBody);
			return string.Empty;
			//}
		}

		protected async Task<string> BuildAuthAsync(HttpRequestMessage request, string mchid, string serialNo, string nonce, string jsonStr = "")
		{
			string method = request.Method.ToString();
			string body = "";
			if (method == "POST" || method == "PUT" || method == "PATCH")
			{
				var content = request.Content;
				if (content is StringContent)
				{
					body = await content.ReadAsStringAsync();
				}

				if (string.IsNullOrWhiteSpace(body))
				{
					body = jsonStr;
				}
			}

			string uri = request.RequestUri.PathAndQuery;
			var timestamp = DateTimeOffset.Now.ToUnixTimeSeconds();
			// string nonce = Path.GetRandomFileName();

			string message = $"{method}\n{uri}\n{timestamp}\n{nonce}\n{body}\n";
			string signature = string.Empty; // Sign(message);
			return $"mchid=\"{mchid}\",nonce_str=\"{nonce}\",timestamp=\"{timestamp}\",serial_no=\"{serialNo}\",signature=\"{signature}\"";
		}

		//protected string Sign(string message)
		//{
		//	// NOTE： 私钥不包括私钥文件起始的-----BEGIN PRIVATE KEY-----
		//	//        亦不包括结尾的-----END PRIVATE KEY-----

		//	byte[] keyData = Convert.FromBase64String(privateKey);
		//	using (CngKey cngKey = CngKey.Import(keyData, CngKeyBlobFormat.Pkcs8PrivateBlob))
		//	using (RSACng rsa = new RSACng(cngKey))
		//	{
		//		byte[] data = System.Text.Encoding.UTF8.GetBytes(message);
		//		return Convert.ToBase64String(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
		//	}

		//	return string.Empty;
		//}

		public X509Certificate2 GetPublicCertificate()
		{
			var path = _hostEnvironment.ContentRootPath + _configuration.GetValue<string>("WxPay:PublicKey");
			var cert = new X509Certificate2(path, string.Empty,
				X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
			// cert.PublicKey.Key
			return cert;

			//var path = _hostEnvironment.ContentRootPath + _configuration.GetValue<string>("WxPay:PublicKey");
			//var pemContents = System.IO.File.ReadAllText(path);
			//const string RsaPublicKeyHeader = "-----BEGIN CERTIFICATE-----";
			//const string RsaPublicKeyFooter = "-----END CERTIFICATE-----";

			//if (!pemContents.StartsWith(RsaPublicKeyHeader))
			//{
			//	throw new InvalidOperationException("公钥加载失败");
			//}
			//var endIdx = pemContents.IndexOf(
			//	RsaPublicKeyFooter,
			//	RsaPublicKeyHeader.Length,
			//	StringComparison.Ordinal);

			//var base64 = pemContents.Substring(
			//	RsaPublicKeyHeader.Length,
			//	endIdx - RsaPublicKeyHeader.Length);

			//var der = Convert.FromBase64String(base64);
			//var rsa = RSA.Create();
			//rsa.ImportRSAPrivateKey(der, out _);
			//return rsa;
		}

		public RSA GetPrivateCertificate()
		{
			var path = _hostEnvironment.ContentRootPath + _configuration.GetValue<string>("WxPay:PrivateKey");
			var pemContents = System.IO.File.ReadAllText(path);
			//const string RsaPrivateKeyHeader = "-----BEGIN PRIVATE KEY-----";
			//const string RsaPrivateKeyFooter = "-----END PRIVATE KEY-----";

			//if (!pemContents.StartsWith(RsaPrivateKeyHeader))
			//{
			//	throw new InvalidOperationException("私钥加载失败");
			//}
			//var endIdx = pemContents.IndexOf(
			//	RsaPrivateKeyFooter,
			//	RsaPrivateKeyHeader.Length,
			//	StringComparison.Ordinal);

			//var base64 = pemContents.Substring(
			//	RsaPrivateKeyHeader.Length,
			//	endIdx - RsaPrivateKeyHeader.Length);

			//var der = Convert.FromBase64String(base64);
			//var rsa = RSA.Create();
			//rsa.ImportRSAPrivateKey(der, out _);
			//return rsa;

			var rsa = RSA.Create();

			rsa.ImportPrivateKey(RSAKeyType.Pkcs8, pemContents, true);
			return rsa;
		}

		private string GenerateNonce()
		{
			return Guid.NewGuid().ToString();
		}

		public X509Certificate2 GetMerchantCertificate()
		{
			var path = _hostEnvironment.ContentRootPath + _configuration.GetValue<string>("WxPay:MerchantCertificate");
			var cert = new X509Certificate2(path, _configuration.GetValue<string>("WxPay:PrivateKeyPassword"),
				X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
			var rsa = RSA.Create();
			return cert;
		}
	}
}