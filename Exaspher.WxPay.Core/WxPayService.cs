using Exaspher.WxPay.Core.Dto;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JsonSerializer = System.Text.Json.JsonSerializer;

namespace Exaspher.WxPay.Core
{
	public class WxPayService : IWxPayService
	{
		private readonly IConfiguration _configuration;
		private readonly IHostEnvironment _hostEnvironment;

		private string privateKey = @"MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQCuer7ujvbwQfjD
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

		public WxPayService(IConfiguration configuration, IHostEnvironment hostEnvironment)
		{
			_configuration = configuration;
			_hostEnvironment = hostEnvironment;
		}

		public async Task<object> ApplyMent()
		{
			HttpClient client = new HttpClient();

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
					LicenseNumber = "1232321321321",
					MerchantName = "腾讯科技有限公司",
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
						BizStoreName = "大郎烧饼",
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

			string publicKeyStr = @"
MIID9jCCAt6gAwIBAgIUTx7IYrSYLGnDvK40/E02coyFez4wDQYJKoZIhvcNAQEL
BQAwXjELMAkGA1UEBhMCQ04xEzARBgNVBAoTClRlbnBheS5jb20xHTAbBgNVBAsT
FFRlbnBheS5jb20gQ0EgQ2VudGVyMRswGQYDVQQDExJUZW5wYXkuY29tIFJvb3Qg
Q0EwHhcNMjAwNjAxMDIxNTM4WhcNMjUwNTMxMDIxNTM4WjCBhzETMBEGA1UEAwwK
MTU5NjQ2MjYwMTEbMBkGA1UECgwS5b6u5L+h5ZWG5oi357O757ufMTMwMQYDVQQL
DCrph43luobmsYflmInml7bku6PnlLXlrZDllYbliqHmnInpmZDlhazlj7gxCzAJ
BgNVBAYMAkNOMREwDwYDVQQHDAhTaGVuWmhlbjCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAK56vu6O9vBB+MOg8MLmT3qg16ICErXoHgRklfWK/bFql9p5
WVMcTddRCZbewVxmTswLfNAreqPlJWtWQPjV2D8p0qhbHnz07vkybeqEqX2epHaO
2HTuu4ASTd1spE1tLUm+telrWssOz/LuQ3N2h6EXK16SlNsLBW+GBEVgbrkQIz8k
TqAe/ZOk5ywO2/PYP4x15LiXddGCJB+SG1F1E/n2bBr7AjsE1YimEcxtBD0puX9+
TGUiyMzlFl0snaKXoNhx4F6JMtfYilaiK1zmwNmmfA1h9lVAS78lQAtflTgEr0gn
AlG8ruUo9JNdikLhH5fGvUKcIV3Qgt/2XJQwKfMCAwEAAaOBgTB/MAkGA1UdEwQC
MAAwCwYDVR0PBAQDAgTwMGUGA1UdHwReMFwwWqBYoFaGVGh0dHA6Ly9ldmNhLml0
cnVzLmNvbS5jbi9wdWJsaWMvaXRydXNjcmw/Q0E9MUJENDIyMEU1MERCQzA0QjA2
QUQzOTc1NDk4NDZDMDFDM0U4RUJEMjANBgkqhkiG9w0BAQsFAAOCAQEABy+maotA
Ye2//1fwzrFirwAaduzVY+HINd8gzhj59YpYMaB2QQ1pm6gLutNpRsjqUYvYyAEi
Cbd0J1MI5XhlE+hJn9zzqvivXgW9ySHPcE4dbUzsj0rAtCn3/8KrDI3oK25tMHll
gmuN720WQu+Q3FZ+wif4exYUwuHO0+yrqqg3KrP4ReU/O5c3VjxFu/YKLyTCajXc
dgOnXMjvxbTmum3PZdRH2Biu9LXLcy/1PDPpSqTEJ7Clh6gs0ARRzmXVP38tTMfw
W5ZvS0R4mIlA5C5cjc7WEtijNh4coYEpaloNBGRnnYi6tkfpgPWKDThorrbnfTtC
7IX2aTdgjG+b8g==
";

			applyment.Encrypt(Encoding.UTF8.GetBytes(publicKeyStr));

			// var jsonStr = JsonConvert.SerializeObject(applyment);

			var jsonStr = JsonSerializer.Serialize(applyment);

			var mchid = _configuration.GetValue<string>("WxPay:MchId");
			var serial_no = _configuration.GetValue<string>("WxPay:SerialNo");

			var nonce_str = Guid.NewGuid().ToString();

			TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
			var timestamp = Convert.ToInt64(ts.TotalSeconds).ToString();

			var path = _hostEnvironment.ContentRootPath + _configuration.GetValue<string>("WxPay:CertPath");

			//var signature = SignUtil.GetSign("POST", "/v3/applyment4sub/applyment", nonce_str, jsonStr, path
			//	, _configuration.GetValue<string>("WxPay:CertPwd"));

			//var authorization =
			//	$"mchid=\"{mchid}\",serial_no=\"{serial_no}\",nonce_str=\"{nonce_str}\",timestamp=\"{timestamp}\",signature=\"{signature}\"";
			HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "https://api.mch.weixin.qq.com/v3/applyment4sub/applyment/");
			request.Content = new StringContent(jsonStr, Encoding.UTF8, "application/json");

			client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("WECHATPAY2-SHA256-RSA2048", await BuildAuthAsync(request, mchid, serial_no, nonce_str));
			client.DefaultRequestHeaders.Add("Wechatpay-Serial", _configuration.GetValue<string>("WxPay:SerialNo"));
			client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36");
			client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
			// client.DefaultRequestHeaders.Add("Content-Type", "application/json");
			// client.DefaultRequestHeaders.

			// var response = await client.PostAsync(new Uri("https://api.mch.weixin.qq.com/v3/applyment4sub/applyment/"), byteContent);

			var response = await client.SendAsync(request);
			var result = await response.Content.ReadAsStringAsync();
			if (response.StatusCode != HttpStatusCode.OK)
			{
				//logger.Error($"GetAsync End, url:{url}, HttpStatusCode:{response.StatusCode}, result:{result}");
				// return new T();
			}

			return null;
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

			//var signature = SignUtil.GetSign("POST", "/v3/applyment4sub/applyment", nonce_str, "",
			//	_configuration.GetValue<string>("WxPay:CertPath"), _configuration.GetValue<string>("WxPay:CertPwd"));

			/// var signature=

			//var authorization =
			//	$"mchid={mchid},serial_no={serial_no},nonce_str={nonce_str},timestamp={timestamp},signature={signature}";

			client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("WECHATPAY2-SHA256-RSA2048", await BuildAuthAsync(request, mchid, serial_no, nonce_str));
			client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

			var response = await client.SendAsync(request);
			var result = await response.Content.ReadAsStringAsync();
			if (response.StatusCode != HttpStatusCode.OK)
			{
			}
		}

		public async Task<string> Upload1(string fileName, byte[] buffer)
		{
			var hashValueStr = string.Empty;
			using (var mySHA256 = SHA256.Create())
			{
				try
				{
					var sha = new SHA256Managed();
					var checksum = sha.ComputeHash(buffer);
					hashValueStr = BitConverter.ToString(checksum).Replace("-", String.Empty);
				}
				catch (IOException e)
				{
					Console.WriteLine($"I/O Exception: {e.Message}");
				}
				catch (UnauthorizedAccessException e)
				{
					Console.WriteLine($"Access Exception: {e.Message}");
				}
			}

			var boundary = $"{DateTime.Now.Ticks:x}";

			var meta = new
			{
				filename = fileName,
				sha256 = hashValueStr
			};

			var jsonStr = JsonSerializer.Serialize(meta);

			var mchid = _configuration.GetValue<string>("WxPay:MchId");
			var serial_no = _configuration.GetValue<string>("WxPay:SerialNo");

			var nonce_str = Guid.NewGuid().ToString();

			var path = _hostEnvironment.ContentRootPath + _configuration.GetValue<string>("WxPay:CertPath");

			var httpHandler = new HttpHandler(mchid, serial_no, privateKey, jsonStr);
			var client = new HttpClient(httpHandler);

			var request = new HttpRequestMessage(HttpMethod.Post, "https://api.mch.weixin.qq.com/v3/merchant/media/upload");

			var requestContent = new MultipartFormDataContent("--" + boundary);
			requestContent.Add(new StringContent(jsonStr, Encoding.UTF8, "application/json"), "\"meta\"");

			var byteArrayContent = new ByteArrayContent(buffer);
			byteArrayContent.Headers.ContentType = new MediaTypeHeaderValue("image/jpg");
			requestContent.Add(byteArrayContent, "\"file\"", "\"" + meta.filename + "\"");

			//client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("WECHATPAY2-SHA256-RSA2048", await BuildAuthAsync(request, mchid, serial_no, nonce_str, jsonStr));
			//client.DefaultRequestHeaders.Add("Wechatpay-Serial", _configuration.GetValue<string>("WxPay:SerialNo"));
			//client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36");
			//client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

			var response = await client.PostAsync("https://api.mch.weixin.qq.com/v3/merchant/media/upload", requestContent);  // await client.SendAsync(request);
			var result = await response.Content.ReadAsStringAsync();
			if (response.StatusCode != HttpStatusCode.OK)
			{
				//logger.Error($"GetAsync End, url:{url}, HttpStatusCode:{response.StatusCode}, result:{result}");
				// return new T();
			}

			return null;
		}

		public async Task<string> Upload(string fileName, byte[] buffer)
		{
			string mchid = "1596462601";
			string serialNo = "4F1EC862B4982C69C3BCAE34FC4D36728C857B3E";
			string boundary = $"--{DateTime.Now.Ticks:x}";

			var sha256 = SHAFile.SHA256File(_hostEnvironment.ContentRootPath + "/images/1.png");
			var meta = new
			{
				sha256 = sha256,
				filename = "1.png"
			};

			var json = JsonConvert.SerializeObject(meta);
			var httpHandler = new HttpHandler(mchid, serialNo, privateKey, json);
			HttpClient client = new HttpClient(httpHandler);
			using (var requestContent = new MultipartFormDataContent(boundary))
			{
				requestContent.Headers.ContentType = MediaTypeHeaderValue.Parse("multipart/form-data"); //这里必须添加
				requestContent.Add(new StringContent(json, Encoding.UTF8, "application/json"), "\"meta\"");
				// 这里主要必须要双引号
				//var fileInfo = new FileInfo(filePath);
				//using (var fileStream = fileInfo.OpenRead())
				//{
				//var content = new byte[fileStream.Length];
				//fileStream.Read(content, 0, content.Length);
				var byteArrayContent = new ByteArrayContent(buffer);
				byteArrayContent.Headers.ContentType = new MediaTypeHeaderValue("image/jpg");
				requestContent.Add(byteArrayContent, "\"file\"", "\"" + meta.filename + "\"");  //这里主要必须要双引号
				using (var response = await client.PostAsync("https://api.mch.weixin.qq.com/v3/merchant/media/upload", requestContent)) //上传
				using (var responseContent = response.Content)
				{
					string responseBody = await responseContent.ReadAsStringAsync(); //这里就可以拿到图片id了
																					 // return ResultHelper.QuickReturn(responseBody);
					return string.Empty;
				}
				//}
			}
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
			string signature = Sign(message);
			return $"mchid=\"{mchid}\",nonce_str=\"{nonce}\",timestamp=\"{timestamp}\",serial_no=\"{serialNo}\",signature=\"{signature}\"";
		}

		protected string Sign(string message)
		{
			// NOTE： 私钥不包括私钥文件起始的-----BEGIN PRIVATE KEY-----
			//        亦不包括结尾的-----END PRIVATE KEY-----

			byte[] keyData = Convert.FromBase64String(privateKey);
			using (CngKey cngKey = CngKey.Import(keyData, CngKeyBlobFormat.Pkcs8PrivateBlob))
			using (RSACng rsa = new RSACng(cngKey))
			{
				byte[] data = System.Text.Encoding.UTF8.GetBytes(message);
				return Convert.ToBase64String(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
			}

			return string.Empty;
		}
	}
}