using Exaspher.WxPay.Core.Util;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Exaspher.WxPay.Core.Dto
{
	public class ApplyMentDto
	{
		[JsonPropertyName("business_code")]
		public string BusinessCode { get; set; }

		/// <summary>
		/// 超级管理员信息
		/// </summary>
		[JsonPropertyName("contact_info")]
		public ApplyMentContactInfoDto ContactInfo { get; set; }

		/// <summary>
		/// 主体资料
		/// </summary>
		[JsonPropertyName("subject_info")]
		public ApplyMentSubjectInfo SubjectInfo { get; set; }

		/// <summary>
		/// 经营资料
		/// </summary>
		[JsonPropertyName("business_info")]
		public ApplyMentBusinessInfo BusinessInfo { get; set; }

		/// <summary>
		/// 结算规则
		/// </summary>
		[JsonPropertyName("settlement_info")]
		public ApplyMentSettlementInfo SettlementInfo { get; set; }

		/// <summary>
		/// 结算银行账户
		/// </summary>
		[JsonPropertyName("bank_account_info")]
		public ApplyMentBankAccountInfo BankAccountInfo { get; set; }

		[JsonPropertyName("addition_info")]
		public ApplyMentAdditionInfo AdditionInfo { get; set; }

		public void Encrypt(byte[] publicKey)
		{
			ContactInfo.Encrypt(publicKey);
			SubjectInfo.Encrypt(publicKey);
			BankAccountInfo?.Encrypt(publicKey);
		}
	}

	public class ApplyMentContactInfoDto
	{
		/// <summary>
		/// 超级管理员姓名
		/// 需要加密
		/// </summary>
		[JsonPropertyName("contact_name")]
		public string ContactName { get; set; }

		/// <summary>
		/// 超级管理员身份证件号码
		/// 需要加密
		/// </summary>
		[JsonPropertyName("contact_id_number")]
		public string ContactIdNumber { get; set; }

		/// <summary>
		/// 超级管理员微信openid
		/// 需要加密
		/// </summary>
		[JsonPropertyName("openid")]
		public string OpenId { get; set; }

		/// <summary>
		/// 联系手机
		/// 需要加密
		/// </summary>
		[JsonPropertyName("mobile_phone")]
		public string MobilePhone { get; set; }

		/// <summary>
		/// 联系邮箱
		/// 需要加密
		/// </summary>
		[JsonPropertyName("contact_email")]
		public string ContactEmail { get; set; }

		public void Encrypt(byte[] publicKey)
		{
			if (!string.IsNullOrWhiteSpace(ContactName))
			{
				this.ContactName = EncryptUtil.RSAEncrypt(this.ContactName, publicKey);
			}

			if (!string.IsNullOrWhiteSpace(ContactIdNumber))
			{
				this.ContactIdNumber = EncryptUtil.RSAEncrypt(this.ContactIdNumber, publicKey);
			}

			if (!string.IsNullOrWhiteSpace(MobilePhone))
			{
				this.MobilePhone = EncryptUtil.RSAEncrypt(this.MobilePhone, publicKey);
			}

			if (!string.IsNullOrWhiteSpace(ContactEmail))
			{
				this.ContactEmail = EncryptUtil.RSAEncrypt(this.ContactEmail, publicKey);
			}
		}
	}

	public class ApplyMentSubjectInfo
	{
		/// <summary>
		/// 类型
		/// </summary>
		[JsonPropertyName("subject_type")]
		public string SubjectType { get; set; }

		/// <summary>
		/// 营业执照
		/// 主体为个体户/企业(必填)
		/// </summary>
		[JsonPropertyName("business_license_info")]
		public ApplyMentBusinessLicenseInfo BusinessLicenseInfo { get; set; }

		/// <summary>
		/// 登记证书
		/// 主体为党政、机关及事业单位/其他组织(必填)
		/// </summary>
		[JsonPropertyName("certificate_info")]
		public ApplyMentCertificateInfo CertificateInfo { get; set; }

		/// <summary>
		/// 组织机构代码证
		/// 主体为企业/党政、机关及事业单位/其他组织，且证件号码不是18位时必填。
		/// </summary>
		[JsonPropertyName("organization_info")]
		public ApplyMentOrganizationInfo OrganizationInfo { get; set; }

		/// <summary>
		/// 单位证明函照片
		/// 主体类型为党政、机关及事业单位必填。
		/// </summary>
		[JsonPropertyName("certificate_letter_copy")]
		public string CertificateLetterCopy { get; set; }

		/// <summary>
		/// 经营者/法人身份证件
		/// 个体户：请上传经营者的身份证件。
		/// 企业/党政、机关及事业单位/其他组织：请上传法人的身份证件。
		/// </summary>
		[JsonPropertyName("identity_info")]
		public ApplyMentIdentityInfo IdentityInfo { get; set; }

		/// <summary>
		/// 最终受益人信息(UBO)
		/// 若经营者/法人不是最终受益所有人，则需提填写受益所有人信息。
		/// </summary>
		[JsonPropertyName("ubo_info")]
		public ApplyMentUboInfo UboInfo { get; set; }

		public void Encrypt(byte[] publicKey)
		{
			IdentityInfo.Encrypt(publicKey);
		}
	}

	public class ApplyMentBusinessLicenseInfo
	{
		/// <summary>
		/// 营业执照照片
		/// 可上传1张图片，请填写通过图片上传接口生成好的MediaID
		/// 请上传彩色照片or彩色扫描件or复印件（需加盖公章鲜章），可添加“微信支付”相关水印（如微信支付认证）
		/// </summary>
		[JsonPropertyName("license_copy")]
		public string LicenseCopy { get; set; }

		/// <summary>
		/// 注册号/统一社会信用代码
		/// </summary>
		[JsonPropertyName("license_number")]
		public string LicenseNumber { get; set; }

		/// <summary>
		/// 商户名称
		/// </summary>
		[JsonPropertyName("merchant_name")]
		public string MerchantName { get; set; }

		/// <summary>
		/// 个体户经营者/法人姓名
		/// </summary>
		[JsonPropertyName("legal_person")]
		public string LegalPerson { get; set; }
	}

	public class ApplyMentCertificateInfo
	{
		/// <summary>
		/// 登记证书照片
		/// </summary>
		[JsonPropertyName("cert_copy")]
		public string CertCopy { get; set; }

		/// <summary>
		/// 登记证书类型
		/// </summary>
		[JsonPropertyName("cert_type")]
		public string CertType { get; set; }

		/// <summary>
		/// 证书号
		/// </summary>
		[JsonPropertyName("cert_number")]
		public string CertNumber { get; set; }

		/// <summary>
		/// 商户名称
		/// </summary>
		[JsonPropertyName("merchant_name")]
		public string MerchantName { get; set; }

		/// <summary>
		/// 注册地址
		/// </summary>
		[JsonPropertyName("company_address")]
		public string CompanyAddress { get; set; }

		/// <summary>
		/// 法人姓名
		/// </summary>
		[JsonPropertyName("legal_person")]
		public string LegalPerson { get; set; }

		/// <summary>
		/// 有效期限开始日期
		/// </summary>
		[JsonPropertyName("period_begin")]
		public string PeriodBegin { get; set; }

		/// <summary>
		/// 有效期限结束日期
		/// </summary>
		[JsonPropertyName("period_end")]
		public string PeriodEnd { get; set; }
	}

	public class ApplyMentOrganizationInfo
	{
		/// <summary>
		/// 组织机构代码证照片
		/// </summary>
		[JsonPropertyName("organization_copy")]
		public string OrganizationCopy { get; set; }

		/// <summary>
		/// 组织机构代码
		/// </summary>
		[JsonPropertyName("organization_code")]
		public string OrganizationCode { get; set; }

		/// <summary>
		/// 组织机构代码证有效期开始日期
		/// </summary>
		[JsonPropertyName("org_period_begin")]
		public string OrgPeriodBegin { get; set; }

		/// <summary>
		/// 组织机构代码证有效期结束日期
		/// </summary>
		[JsonPropertyName("org_period_end")]
		public string OrgPeriodEnd { get; set; }
	}

	public class ApplyMentIdentityInfo
	{
		/// <summary>
		/// 证件类型
		/// </summary>
		[JsonPropertyName("id_doc_type")]
		public string IdDocType { get; set; }

		/// <summary>
		/// 身份证信息
		/// 证件类型为“身份证”时填写。
		/// </summary>
		[JsonPropertyName("id_card_info")]
		public ApplyMentIdCardInfo IdCardInfo { get; set; }

		/// <summary>
		/// 其他类型证件信息
		/// 证件类型为“来往内地通行证、来往大陆通行证、护照”时填写。
		/// </summary>
		[JsonPropertyName("id_doc_info")]
		public ApplyMentIdDocInfo IdDocInfo { get; set; }

		[JsonPropertyName("owner")]
		public bool Owner { get; set; }

		public void Encrypt(byte[] publicKey)
		{
			IdCardInfo.Encrypt(publicKey);
		}
	}

	public class ApplyMentIdCardInfo
	{
		[JsonPropertyName("id_card_copy")]
		public string IdCardCopy { get; set; }

		[JsonPropertyName("id_card_national")]
		public string IdCardNational { get; set; }

		[JsonPropertyName("id_card_name")]
		public string IdCardName { get; set; }

		[JsonPropertyName("id_card_number")]
		public string IdCardNumber { get; set; }

		[JsonPropertyName("card_period_begin")]
		public string CardPeriodBegin { get; set; }

		[JsonPropertyName("card_period_end")]
		public string CardPeriodEnd { get; set; }

		public void Encrypt(byte[] publicKey)
		{
			if (!string.IsNullOrWhiteSpace(IdCardName))
			{
				this.IdCardName = EncryptUtil.RSAEncrypt(this.IdCardName, publicKey);
			}

			if (!string.IsNullOrWhiteSpace(IdCardNumber))
			{
				this.IdCardNumber = EncryptUtil.RSAEncrypt(this.IdCardNumber, publicKey);
			}
		}
	}

	public class ApplyMentIdDocInfo
	{
		[JsonPropertyName("id_doc_copy")]
		public string IdDocCopy { get; set; }

		[JsonPropertyName("id_doc_name")]
		public string IdDocName { get; set; }

		[JsonPropertyName("id_doc_number")]
		public string IdDocNumber { get; set; }

		[JsonPropertyName("doc_period_begin")]
		public string DocPeriodBegin { get; set; }

		[JsonPropertyName("doc_period_end")]
		public string DocPeriodEnd { get; set; }
	}

	public class ApplyMentUboInfo
	{
		[JsonPropertyName("id_type")]
		public string IdType { get; set; }

		[JsonPropertyName("id_card_copy")]
		public string IdCardCopy { get; set; }

		[JsonPropertyName("id_card_national")]
		public string IdCardNational { get; set; }

		[JsonPropertyName("id_doc_copy")]
		public string IdDocCopy { get; set; }

		[JsonPropertyName("name")]
		public string Name { get; set; }

		[JsonPropertyName("id_number")]
		public string IdNumber { get; set; }

		[JsonPropertyName("id_period_begin")]
		public string IdPeriodBegin { get; set; }

		[JsonPropertyName("id_period_end")]
		public string IdPeriodEnd { get; set; }
	}

	/// <summary>
	///
	/// </summary>
	public class ApplyMentBusinessInfo
	{
		/// <summary>
		/// 商户简称
		/// </summary>
		[JsonPropertyName("merchant_shortname")]
		public string MerchantShortName { get; set; }

		/// <summary>
		/// 客服电话
		/// </summary>
		[JsonPropertyName("service_phone")]
		public string ServicePhone { get; set; }

		/// <summary>
		/// 经营场景
		/// </summary>
		[JsonPropertyName("sales_info")]
		public ApplyMentSalesInfo SalesInfo { get; set; }
	}

	public class ApplyMentSalesInfo
	{
		/// <summary>
		/// 经营场景类型
		/// </summary>
		[JsonPropertyName("sales_scenes_type")]
		public List<string> SalesScenesType { get; set; }

		/// <summary>
		/// 线下门店场景
		/// </summary>
		[JsonPropertyName("biz_store_info")]
		public ApplyMentBizStorInfo BizStorInfo { get; set; }

		/// <summary>
		/// 公众号场景
		/// </summary>
		[JsonPropertyName("mp_info")]
		public ApplyMentMpInfo MpInfo { get; set; }

		/// <summary>
		/// 小程序场景
		/// </summary>
		[JsonPropertyName("mini_program_info")]
		public ApplyMentMiniProgramInfo MiniProgramInfo { get; set; }

		/// <summary>
		/// APP场景
		/// </summary>
		[JsonPropertyName("app_info")]
		public ApplyMentAppInfo AppInfo { get; set; }

		/// <summary>
		/// 互联网网站场景
		/// </summary>
		[JsonPropertyName("web_info")]
		public ApplyMentWebInfo WebInfo { get; set; }

		/// <summary>
		/// 企业微信场景
		/// </summary>
		[JsonPropertyName("wework_info")]
		public ApplyMentWeWorkInfo WeWorkInfo { get; set; }
	}

	public class ApplyMentBizStorInfo
	{
		[JsonPropertyName("biz_store_name")]
		public string BizStoreName { get; set; }

		[JsonPropertyName("biz_address_code")]
		public string BizAddressCode { get; set; }

		[JsonPropertyName("biz_store_address")]
		public string BizStoreAddress { get; set; }

		[JsonPropertyName("store_entrance_pic")]
		public List<string> StoreEntrancePic { get; set; }

		[JsonPropertyName("indoor_pic")]
		public List<string> IndoorPic { get; set; }

		[JsonPropertyName("biz_sub_appid")]
		public string BizSubAppId { get; set; }
	}

	public class ApplyMentMpInfo
	{
		[JsonPropertyName("mp_appid")]
		public string MpAppId { get; set; }

		[JsonPropertyName("mp_sub_appid")]
		public string MpSubAppId { get; set; }

		[JsonPropertyName("mp_pics")]
		public string MpPics { get; set; }
	}

	public class ApplyMentMiniProgramInfo
	{
		[JsonPropertyName("mini_program_appid")]
		public string MiniProgramAppId { get; set; }

		[JsonPropertyName("mini_program_sub_appid")]
		public string MiniProgramSubAppId { get; set; }

		[JsonPropertyName("mini_program_pics")]
		public string MiniProgramPics { get; set; }
	}

	public class ApplyMentAppInfo
	{
		[JsonPropertyName("app_appid")]
		public string AppAppId { get; set; }

		[JsonPropertyName("app_sub_appid")]
		public string AppSubAppId { get; set; }

		[JsonPropertyName("app_pics")]
		public string AppPics { get; set; }
	}

	public class ApplyMentWebInfo
	{
		[JsonPropertyName("domain")]
		public string Domain { get; set; }

		[JsonPropertyName("web_authorisation")]
		public string WebAuthorisation { get; set; }

		[JsonPropertyName("web_appid")]
		public string WebAppId { get; set; }
	}

	public class ApplyMentWeWorkInfo
	{
		[JsonPropertyName("sub_corp_id")]
		public string SubCorpId { get; set; }

		[JsonPropertyName("wework_pics")]
		public string WeWordPics { get; set; }
	}

	public class ApplyMentSettlementInfo
	{
		/// <summary>
		/// 入驻结算规则ID
		/// 配置: WxPay.SettlementId
		/// </summary>
		[JsonPropertyName("settlement_id")]
		public string SettlementId { get; set; }

		/// <summary>
		/// 所属行业
		/// </summary>
		[JsonPropertyName("qualification_type")]
		public string QualificationType { get; set; }

		/// <summary>
		/// 特殊资质图片
		/// </summary>
		[JsonPropertyName("qualifications")]
		public List<string> Qualifications { get; set; }

		/// <summary>
		/// 优惠费率活动ID
		/// </summary>
		[JsonPropertyName("activities_id")]
		public string ActivitiesId { get; set; }

		/// <summary>
		/// 优惠费率活动值
		/// </summary>
		[JsonPropertyName("activities_rate")]
		public string ActivitiesRate { get; set; }

		/// <summary>
		/// 优惠费率活动补充材料
		/// </summary>
		[JsonPropertyName("activities_additions")]
		public List<string> ActivitiesAdditions { get; set; }
	}

	public class ApplyMentBankAccountInfo
	{
		/// <summary>
		/// 账户类型
		/// </summary>
		[JsonPropertyName("bank_account_type")]
		public string BankAccountType { get; set; }

		/// <summary>
		/// 开户名称
		/// 选择“经营者个人银行卡”时，开户名称必须与“经营者证件姓名”一致,
		/// 选择“对公银行账户”时，开户名称必须与营业执照/登记证书的“商户名称”一致。
		/// 需要加密
		/// </summary>
		[JsonPropertyName("account_name")]
		public string AccountName { get; set; }

		/// <summary>
		/// 开户银行
		/// </summary>
		[JsonPropertyName("account_bank")]
		public string AccountBank { get; set; }

		/// <summary>
		/// 开户银行省市编码
		/// 至少精确到市
		/// </summary>
		[JsonPropertyName("bank_address_code")]
		public string BankAddressCode { get; set; }

		/// <summary>
		/// 开户银行联行号
		/// </summary>
		[JsonPropertyName("bank_branch_id")]
		public string BankBranchId { get; set; }

		/// <summary>
		/// 开户银行全称（含支行)
		/// </summary>
		[JsonPropertyName("bank_name")]
		public string BankName { get; set; }

		/// <summary>
		/// 银行账号
		/// 需要加密
		/// </summary>
		[JsonPropertyName("account_number")]
		public string AccountNumber { get; set; }

		public void Encrypt(byte[] publicKey)
		{
			if (!string.IsNullOrWhiteSpace(AccountName))
			{
				this.AccountName = EncryptUtil.RSAEncrypt(this.AccountName, publicKey);
			}

			if (!string.IsNullOrWhiteSpace(AccountNumber))
			{
				this.AccountNumber = EncryptUtil.RSAEncrypt(this.AccountNumber, publicKey);
			}
		}
	}

	public class ApplyMentAdditionInfo
	{
		[JsonPropertyName("legal_person_commitment")]
		public string LegalPersonCommitment { get; set; }

		[JsonPropertyName("legal_person_video")]
		public string LegalPersonVideo { get; set; }

		[JsonPropertyName("business_addition_pics")]
		public string BusinessAdditionPics { get; set; }

		[JsonPropertyName("business_addition_msg")]
		public string BusinessAdditionMsg { get; set; }
	}
}