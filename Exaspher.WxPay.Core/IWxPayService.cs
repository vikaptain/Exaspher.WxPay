using System.Threading.Tasks;

namespace Exaspher.WxPay.Core
{
	public interface IWxPayService
	{
		Task<object> ApplyMent();

		Task GetCertificates();

		Task<string> Upload(string filename, byte[] buffer);
	}
}