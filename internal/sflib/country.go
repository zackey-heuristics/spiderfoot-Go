package sflib

import "strings"

// countryCodes maps ISO 3166-1 alpha-2 codes to country names.
var countryCodes = map[string]string{
	"AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AD": "Andorra", "AO": "Angola",
	"AR": "Argentina", "AM": "Armenia", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan",
	"BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados", "BY": "Belarus",
	"BE": "Belgium", "BZ": "Belize", "BJ": "Benin", "BT": "Bhutan", "BO": "Bolivia",
	"BA": "Bosnia and Herzegovina", "BW": "Botswana", "BR": "Brazil", "BN": "Brunei", "BG": "Bulgaria",
	"BF": "Burkina Faso", "BI": "Burundi", "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada",
	"CL": "Chile", "CN": "China", "CO": "Colombia", "CD": "DR Congo", "CR": "Costa Rica",
	"HR": "Croatia", "CU": "Cuba", "CY": "Cyprus", "CZ": "Czech Republic", "DK": "Denmark",
	"EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "EE": "Estonia", "ET": "Ethiopia",
	"FI": "Finland", "FR": "France", "DE": "Germany", "GH": "Ghana", "GR": "Greece",
	"GT": "Guatemala", "HN": "Honduras", "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland",
	"IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq", "IE": "Ireland",
	"IL": "Israel", "IT": "Italy", "JM": "Jamaica", "JP": "Japan", "JO": "Jordan",
	"KZ": "Kazakhstan", "KE": "Kenya", "KR": "South Korea", "KW": "Kuwait", "LV": "Latvia",
	"LB": "Lebanon", "LY": "Libya", "LT": "Lithuania", "LU": "Luxembourg", "MY": "Malaysia",
	"MX": "Mexico", "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar", "NP": "Nepal",
	"NL": "Netherlands", "NZ": "New Zealand", "NI": "Nicaragua", "NG": "Nigeria", "NO": "Norway",
	"OM": "Oman", "PK": "Pakistan", "PA": "Panama", "PY": "Paraguay", "PE": "Peru",
	"PH": "Philippines", "PL": "Poland", "PT": "Portugal", "QA": "Qatar", "RO": "Romania",
	"RU": "Russia", "SA": "Saudi Arabia", "RS": "Serbia", "SG": "Singapore", "SK": "Slovakia",
	"SI": "Slovenia", "ZA": "South Africa", "ES": "Spain", "LK": "Sri Lanka", "SE": "Sweden",
	"CH": "Switzerland", "TW": "Taiwan", "TH": "Thailand", "TR": "Turkey", "UA": "Ukraine",
	"AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States", "UY": "Uruguay",
	"UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam", "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe",
}

// tldToCountry maps common country-code TLDs to country codes.
var tldToCountry = map[string]string{
	"uk": "GB", "jp": "JP", "cn": "CN", "de": "DE", "fr": "FR", "au": "AU",
	"br": "BR", "ca": "CA", "in": "IN", "it": "IT", "ru": "RU", "kr": "KR",
	"mx": "MX", "nl": "NL", "pl": "PL", "se": "SE", "ch": "CH", "es": "ES",
	"za": "ZA", "nz": "NZ", "sg": "SG", "ie": "IE", "no": "NO", "fi": "FI",
	"dk": "DK", "at": "AT", "be": "BE", "pt": "PT", "il": "IL", "tw": "TW",
}

// CountryNameFromCode returns the country name for a given ISO 3166-1 alpha-2 code.
func CountryNameFromCode(code string) string {
	return countryCodes[strings.ToUpper(code)]
}

// CountryNameFromTLD returns the country name for a ccTLD (e.g., "uk" -> "United Kingdom").
func CountryNameFromTLD(tld string) string {
	tld = strings.TrimPrefix(strings.ToLower(tld), ".")
	code, ok := tldToCountry[tld]
	if !ok {
		code = strings.ToUpper(tld)
	}
	return countryCodes[code]
}

// CountryCodes returns a copy of the country code to name mapping.
func CountryCodes() map[string]string {
	result := make(map[string]string, len(countryCodes))
	for k, v := range countryCodes {
		result[k] = v
	}
	return result
}
