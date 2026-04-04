package bypass

// Split tunneling domain lists for countries where platforms enforce VPN detection.
//
// Russian platforms are required to block VPN users starting April 15, 2026.
// To let users access both Russian services and blocked foreign sites without
// disconnecting the proxy, traffic to these domains is routed DIRECT (bypassing
// the proxy) while everything else goes through the encrypted tunnel.
//
// These lists are used by:
//   - install.sh  (xray server-side routing)
//   - sub-server  (Clash and sing-box client configs)
//
// When adding domains, prefer the registrable domain (e.g. "yandex.ru") so that
// all subdomains are covered automatically.

// RussianDirectDomains contains domains that should bypass the proxy
// to avoid VPN detection by Russian platforms (effective April 15, 2026).
var RussianDirectDomains = []string{
	// Search & services
	"ya.ru",
	"yandex.ru",
	"yandex.com",
	"yandex.net",

	// Social networks
	"vk.com",
	"vk.me",
	"vkontakte.ru",
	"ok.ru",
	"mail.ru",

	// E-commerce
	"ozon.ru",
	"ozon.travel",
	"wildberries.ru",
	"wb.ru",
	"avito.ru",
	"cian.ru",
	"vkusvill.ru",

	// Banking
	"sber.ru",
	"sberbank.ru",
	"online.sberbank.ru",
	"tinkoff.ru",
	"alfa-bank.ru",
	"vtb.ru",

	// Government
	"gosuslugi.ru",
	"mos.ru",
	"nalog.ru",
	"nalog.gov.ru",

	// Job search
	"hh.ru",

	// News & media
	"ria.ru",
	"rbc.ru",
	"tass.ru",
	"rt.com",
	"1tv.ru",

	// Streaming
	"kinopoisk.ru",
	"ivi.ru",
	"okko.tv",
	"rutube.ru",
	"dzen.ru",
}

// ChineseDirectDomains contains domains that should bypass the proxy
// for users in China who need local services to work without disconnecting.
var ChineseDirectDomains = []string{
	// Search
	"baidu.com",

	// Social & messaging
	"qq.com",
	"weixin.qq.com",
	"weibo.com",
	"sina.com.cn",

	// E-commerce
	"taobao.com",
	"tmall.com",
	"jd.com",

	// Payments
	"alipay.com",

	// Email & portals
	"163.com",

	// Video
	"bilibili.com",
	"youku.com",
	"iqiyi.com",

	// Maps & delivery
	"amap.com",
	"meituan.com",
	"ele.me",
	"dianping.com",

	// Government
	"gov.cn",
}

// IranianDirectDomains contains domains that should bypass the proxy
// for users in Iran who need local services to work without disconnecting.
var IranianDirectDomains = []string{
	"digikala.com",
	"divar.ir",
	"shaparak.ir",
	"irancell.ir",
	"mci.ir",
}

// DirectDomainsForCountry returns the split tunneling domain list for a
// given two-letter country code (ISO 3166-1 alpha-2). Returns nil if no
// list is defined for that country.
func DirectDomainsForCountry(countryCode string) []string {
	switch countryCode {
	case "RU":
		return RussianDirectDomains
	case "CN":
		return ChineseDirectDomains
	case "IR":
		return IranianDirectDomains
	default:
		return nil
	}
}
