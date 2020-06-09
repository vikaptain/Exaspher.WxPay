using Exaspher.WxPay.Core;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using System.Threading.Tasks;

namespace Exaspher.WxPay.WebCore.Controllers
{
	[Route("api/[controller]/[action]")]

	[ApiController]
	public class TestController : ControllerBase
	{
		private readonly IWxPayService _wxPayService;
		private readonly IHostEnvironment _hostEnvironment;

		public TestController(IWxPayService wxPayService, IHostEnvironment hostEnvironment)
		{
			_wxPayService = wxPayService;
			_hostEnvironment = hostEnvironment;
		}

		[HttpGet]
		public async Task<string> Get()
		{
			var result = await _wxPayService.ApplyMent();
			return JsonConvert.SerializeObject(result);
		}

		[HttpGet]
		public async Task<string> Upload()
		{
			var buffer = System.IO.File.ReadAllBytes(_hostEnvironment.ContentRootPath + "/images/1.png");
			var result = await _wxPayService.Upload("1.png", buffer);
			return result;
		}
	}
}