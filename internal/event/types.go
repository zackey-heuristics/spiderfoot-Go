// Package event defines event types and transport primitives used by SpiderFoot-Go.
package event

import (
	"strings"
	"unicode"
)

// Type identifies a SpiderFoot event type.
type Type string

// Wildcard subscribes to every event type on the bus.
const Wildcard Type = "*"

// Event type constants.
const (
	ROOT                                     Type = "ROOT"
	AFFILIATE_DOMAIN_NAME                    Type = "AFFILIATE_DOMAIN_NAME"
	AFFILIATE_DOMAIN_UNRESOLVED              Type = "AFFILIATE_DOMAIN_UNRESOLVED"
	AFFILIATE_DOMAIN_WHOIS                   Type = "AFFILIATE_DOMAIN_WHOIS"
	AFFILIATE_EMAILADDR                      Type = "AFFILIATE_EMAILADDR"
	AFFILIATE_INTERNET_NAME                  Type = "AFFILIATE_INTERNET_NAME"
	AFFILIATE_INTERNET_NAME_UNRESOLVED       Type = "AFFILIATE_INTERNET_NAME_UNRESOLVED"
	AFFILIATE_IPADDR                         Type = "AFFILIATE_IPADDR"
	AFFILIATE_IPV6_ADDRESS                   Type = "AFFILIATE_IPV6_ADDRESS"
	AFFILIATE_WEB_CONTENT                    Type = "AFFILIATE_WEB_CONTENT"
	AMAZON_S3_BUCKET                         Type = "AMAZON_S3_BUCKET"
	AMAZON_S3_BUCKET_OPEN                    Type = "AMAZON_S3_BUCKET_OPEN"
	APPSTORE_ENTRY                           Type = "APPSTORE_ENTRY"
	ACCOUNT_EXTERNAL_OWNED                   Type = "ACCOUNT_EXTERNAL_OWNED"
	ACCOUNT_EXTERNAL_OWNED_COMPROMISED       Type = "ACCOUNT_EXTERNAL_OWNED_COMPROMISED"
	ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED Type = "ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED"
	BASE64_DATA                              Type = "BASE64_DATA"
	BGP_AS_MEMBER                            Type = "BGP_AS_MEMBER"
	BGP_AS_OWNER                             Type = "BGP_AS_OWNER"
	BGP_AS_PEER                              Type = "BGP_AS_PEER"
	BITCOIN_ADDRESS                          Type = "BITCOIN_ADDRESS"
	BITCOIN_BALANCE                          Type = "BITCOIN_BALANCE"
	BLACKLISTED_AFFILIATE_INTERNET_NAME      Type = "BLACKLISTED_AFFILIATE_INTERNET_NAME"
	BLACKLISTED_AFFILIATE_IPADDR             Type = "BLACKLISTED_AFFILIATE_IPADDR"
	BLACKLISTED_AFFILIATE_SUBNET             Type = "BLACKLISTED_AFFILIATE_SUBNET"
	BLACKLISTED_AFFILIATE_NETBLOCK           Type = "BLACKLISTED_AFFILIATE_NETBLOCK"
	BLACKLISTED_COHOST                       Type = "BLACKLISTED_COHOST"
	BLACKLISTED_INTERNET_NAME                Type = "BLACKLISTED_INTERNET_NAME"
	BLACKLISTED_IPADDR                       Type = "BLACKLISTED_IPADDR"
	BLACKLISTED_NETBLOCK                     Type = "BLACKLISTED_NETBLOCK"
	BLACKLISTED_SUBNET                       Type = "BLACKLISTED_SUBNET"
	CO_HOSTED_SITE                           Type = "CO_HOSTED_SITE"
	CO_HOSTED_SITE_DOMAIN                    Type = "CO_HOSTED_SITE_DOMAIN"
	CO_HOSTED_SITE_DOMAIN_WHOIS              Type = "CO_HOSTED_SITE_DOMAIN_WHOIS"
	CLOUD_STORAGE_BUCKET                     Type = "CLOUD_STORAGE_BUCKET"
	CLOUD_STORAGE_BUCKET_OPEN                Type = "CLOUD_STORAGE_BUCKET_OPEN"
	COMPANY_NAME                             Type = "COMPANY_NAME"
	COUNTRY_NAME                             Type = "COUNTRY_NAME"
	CREDIT_CARD_NUMBER                       Type = "CREDIT_CARD_NUMBER"
	DARKNET_MENTION_CONTENT                  Type = "DARKNET_MENTION_CONTENT"
	DARKNET_MENTION_URL                      Type = "DARKNET_MENTION_URL"
	DATE_HUMAN_DOB                           Type = "DATE_HUMAN_DOB"
	DEFACED_AFFILIATE_INTERNET_NAME          Type = "DEFACED_AFFILIATE_INTERNET_NAME"
	DEFACED_INTERNET_NAME                    Type = "DEFACED_INTERNET_NAME"
	DEFACED_AFFILIATE_IPADDR                 Type = "DEFACED_AFFILIATE_IPADDR"
	DEFACED_COHOST                           Type = "DEFACED_COHOST"
	DEFACED_IPADDR                           Type = "DEFACED_IPADDR"
	DESCRIPTION_ABSTRACT                     Type = "DESCRIPTION_ABSTRACT"
	DESCRIPTION_CATEGORY                     Type = "DESCRIPTION_CATEGORY"
	DEVICE_TYPE                              Type = "DEVICE_TYPE"
	DNS_SRV                                  Type = "DNS_SRV"
	DNS_TXT                                  Type = "DNS_TXT"
	DNS_SPF                                  Type = "DNS_SPF"
	DOMAIN_NAME                              Type = "DOMAIN_NAME"
	DOMAIN_NAME_PARENT                       Type = "DOMAIN_NAME_PARENT"
	DOMAIN_REGISTRAR                         Type = "DOMAIN_REGISTRAR"
	DOMAIN_WHOIS                             Type = "DOMAIN_WHOIS"
	EMAILADDR                                Type = "EMAILADDR"
	EMAILADDR_COMPROMISED                    Type = "EMAILADDR_COMPROMISED"
	EMAILADDR_DEALIASED                      Type = "EMAILADDR_DEALIASED"
	EMAILADDR_GENERIC                        Type = "EMAILADDR_GENERIC"
	ERROR_MESSAGE                            Type = "ERROR_MESSAGE"
	ETHEREUM_ADDRESS                         Type = "ETHEREUM_ADDRESS"
	GEOINFO                                  Type = "GEOINFO"
	GPS_ROUTE                                Type = "GPS_ROUTE"
	HACKED_EMAIL_ADDRESS                     Type = "HACKED_EMAIL_ADDRESS"
	HASH                                     Type = "HASH"
	HASH_COMPROMISED                         Type = "HASH_COMPROMISED"
	HTTP_CODE                                Type = "HTTP_CODE"
	HUMAN_NAME                               Type = "HUMAN_NAME"
	IBAN_NUMBER                              Type = "IBAN_NUMBER"
	INTERESTING_FILE                         Type = "INTERESTING_FILE"
	INTERESTING_FILE_CONTENT                 Type = "INTERESTING_FILE_CONTENT"
	INTERESTING_FILE_HISTORIC                Type = "INTERESTING_FILE_HISTORIC"
	URL_FORM_HISTORIC                        Type = "URL_FORM_HISTORIC"
	URL_FLASH_HISTORIC                       Type = "URL_FLASH_HISTORIC"
	URL_STATIC_HISTORIC                      Type = "URL_STATIC_HISTORIC"
	URL_JAVA_APPLET_HISTORIC                 Type = "URL_JAVA_APPLET_HISTORIC"
	URL_UPLOAD_HISTORIC                      Type = "URL_UPLOAD_HISTORIC"
	URL_JAVASCRIPT_HISTORIC                  Type = "URL_JAVASCRIPT_HISTORIC"
	URL_PASSWORD_HISTORIC                    Type = "URL_PASSWORD_HISTORIC"
	URL_WEB_FRAMEWORK_HISTORIC               Type = "URL_WEB_FRAMEWORK_HISTORIC"
	INTERNET_NAME                            Type = "INTERNET_NAME"
	INTERNET_NAME_UNRESOLVED                 Type = "INTERNET_NAME_UNRESOLVED"
	IP_ADDRESS                               Type = "IP_ADDRESS"
	IPV6_ADDRESS                             Type = "IPV6_ADDRESS"
	JUNK_FILE                                Type = "JUNK_FILE"
	LEAKSITE_CONTENT                         Type = "LEAKSITE_CONTENT"
	LEAKSITE_URL                             Type = "LEAKSITE_URL"
	LINKED_URL_EXTERNAL                      Type = "LINKED_URL_EXTERNAL"
	LINKED_URL_INTERNAL                      Type = "LINKED_URL_INTERNAL"
	MALICIOUS_BITCOIN_ADDRESS                Type = "MALICIOUS_BITCOIN_ADDRESS"
	MALICIOUS_AFFILIATE_INTERNET_NAME        Type = "MALICIOUS_AFFILIATE_INTERNET_NAME"
	MALICIOUS_AFFILIATE_IPADDR               Type = "MALICIOUS_AFFILIATE_IPADDR"
	MALICIOUS_ASN                            Type = "MALICIOUS_ASN"
	MALICIOUS_COHOST                         Type = "MALICIOUS_COHOST"
	MALICIOUS_EMAILADDR                      Type = "MALICIOUS_EMAILADDR"
	MALICIOUS_INTERNET_NAME                  Type = "MALICIOUS_INTERNET_NAME"
	MALICIOUS_IPADDR                         Type = "MALICIOUS_IPADDR"
	MALICIOUS_NETBLOCK                       Type = "MALICIOUS_NETBLOCK"
	MALICIOUS_PHONE_NUMBER                   Type = "MALICIOUS_PHONE_NUMBER"
	MALICIOUS_SUBNET                         Type = "MALICIOUS_SUBNET"
	NETBLOCK_MEMBER                          Type = "NETBLOCK_MEMBER"
	NETBLOCK_OWNER                           Type = "NETBLOCK_OWNER"
	NETBLOCKV6_MEMBER                        Type = "NETBLOCKV6_MEMBER"
	NETBLOCKV6_OWNER                         Type = "NETBLOCKV6_OWNER"
	OPERATING_SYSTEM                         Type = "OPERATING_SYSTEM"
	PASSWORD_COMPROMISED                     Type = "PASSWORD_COMPROMISED"
	PHONE_NUMBER                             Type = "PHONE_NUMBER"
	PHONE_NUMBER_COMPROMISED                 Type = "PHONE_NUMBER_COMPROMISED"
	PHYSICAL_ADDRESS                         Type = "PHYSICAL_ADDRESS"
	PHYSICAL_COORDINATES                     Type = "PHYSICAL_COORDINATES"
	PGP_KEY                                  Type = "PGP_KEY"
	PROVIDER_DNS                             Type = "PROVIDER_DNS"
	PROVIDER_HOSTING                         Type = "PROVIDER_HOSTING"
	PROVIDER_JAVASCRIPT                      Type = "PROVIDER_JAVASCRIPT"
	PROVIDER_MAIL                            Type = "PROVIDER_MAIL"
	PROVIDER_TELCO                           Type = "PROVIDER_TELCO"
	PUBLIC_CODE_REPO                         Type = "PUBLIC_CODE_REPO"
	RAW_DNS_RECORDS                          Type = "RAW_DNS_RECORDS"
	RAW_FILE_META_DATA                       Type = "RAW_FILE_META_DATA"
	RAW_RIR_DATA                             Type = "RAW_RIR_DATA"
	SEARCH_ENGINE_WEB_CONTENT                Type = "SEARCH_ENGINE_WEB_CONTENT"
	SIMILARDOMAIN                            Type = "SIMILARDOMAIN"
	SOCIAL_MEDIA                             Type = "SOCIAL_MEDIA"
	SOFTWARE_USED                            Type = "SOFTWARE_USED"
	SSL_CERTIFICATE_EXPIRED                  Type = "SSL_CERTIFICATE_EXPIRED"
	SSL_CERTIFICATE_EXPIRING                 Type = "SSL_CERTIFICATE_EXPIRING"
	SSL_CERTIFICATE_ISSUED                   Type = "SSL_CERTIFICATE_ISSUED"
	SSL_CERTIFICATE_ISSUER                   Type = "SSL_CERTIFICATE_ISSUER"
	SSL_CERTIFICATE_MISMATCH                 Type = "SSL_CERTIFICATE_MISMATCH"
	SSL_CERTIFICATE_RAW                      Type = "SSL_CERTIFICATE_RAW"
	TARGET_WEB_CONTENT                       Type = "TARGET_WEB_CONTENT"
	TARGET_WEB_CONTENT_TYPE                  Type = "TARGET_WEB_CONTENT_TYPE"
	TARGET_WEB_COOKIE                        Type = "TARGET_WEB_COOKIE"
	TCP_PORT_OPEN                            Type = "TCP_PORT_OPEN"
	UDP_PORT_OPEN                            Type = "UDP_PORT_OPEN"
	TCP_PORT_OPEN_BANNER                     Type = "TCP_PORT_OPEN_BANNER"
	TLD_PARENT                               Type = "TLD_PARENT"
	URL_ADBLOCKED_EXTERNAL                   Type = "URL_ADBLOCKED_EXTERNAL"
	URL_ADBLOCKED_INTERNAL                   Type = "URL_ADBLOCKED_INTERNAL"
	URL_FORM                                 Type = "URL_FORM"
	URL_FLASH                                Type = "URL_FLASH"
	URL_JAVASCRIPT                           Type = "URL_JAVASCRIPT"
	URL_JAVA_APPLET                          Type = "URL_JAVA_APPLET"
	URL_PASSWORD                             Type = "URL_PASSWORD"
	URL_STATIC                               Type = "URL_STATIC"
	URL_UPLOAD                               Type = "URL_UPLOAD"
	URL_WEB_FRAMEWORK                        Type = "URL_WEB_FRAMEWORK"
	USERNAME                                 Type = "USERNAME"
	VULNERABILITY_CVE_CRITICAL               Type = "VULNERABILITY_CVE_CRITICAL"
	VULNERABILITY_CVE_HIGH                   Type = "VULNERABILITY_CVE_HIGH"
	VULNERABILITY_CVE_INFO                   Type = "VULNERABILITY_CVE_INFO"
	VULNERABILITY_CVE_LOW                    Type = "VULNERABILITY_CVE_LOW"
	VULNERABILITY_CVE_MEDIUM                 Type = "VULNERABILITY_CVE_MEDIUM"
	VULNERABILITY_DISCLOSURE                 Type = "VULNERABILITY_DISCLOSURE"
	VULNERABILITY_GENERAL                    Type = "VULNERABILITY_GENERAL"
	WEBSERVER_BANNER                         Type = "WEBSERVER_BANNER"
	WEBSERVER_HTTPHEADERS                    Type = "WEBSERVER_HTTPHEADERS"
	WEBSERVER_STRANGEHEADER                  Type = "WEBSERVER_STRANGEHEADER"
	WEBSERVER_TECHNOLOGY                     Type = "WEBSERVER_TECHNOLOGY"
	WIFI_ACCESS_POINT                        Type = "WIFI_ACCESS_POINT"
	WIKIPEDIA_PAGE_EDIT                      Type = "WIKIPEDIA_PAGE_EDIT"
	WEB_ANALYTICS_ID                         Type = "WEB_ANALYTICS_ID"
	WEBSERVER_URL                            Type = "WEBSERVER_URL"
	WEBSERVER_URL_EXTERNAL                   Type = "WEBSERVER_URL_EXTERNAL"
)

// TypeInfo describes a single event type in the registry.
type TypeInfo struct {
	// Type is the canonical event type identifier.
	Type Type
	// Description is the human-readable label for the type.
	Description string
	// IsRaw reports whether events of this type are raw/high-volume data.
	IsRaw bool
	// Category groups the type into the SpiderFoot event taxonomy.
	Category string
}

var typeRegistry = buildRegistry()

// Registry returns a copy of the event type registry keyed by event type.
func Registry() map[Type]TypeInfo {
	out := make(map[Type]TypeInfo, len(typeRegistry))
	for k, v := range typeRegistry {
		out[k] = v
	}

	return out
}

func buildRegistry() map[Type]TypeInfo {
	types := []Type{
		ROOT, AFFILIATE_DOMAIN_NAME, AFFILIATE_DOMAIN_UNRESOLVED, AFFILIATE_DOMAIN_WHOIS,
		AFFILIATE_EMAILADDR, AFFILIATE_INTERNET_NAME, AFFILIATE_INTERNET_NAME_UNRESOLVED,
		AFFILIATE_IPADDR, AFFILIATE_IPV6_ADDRESS, AFFILIATE_WEB_CONTENT, AMAZON_S3_BUCKET,
		AMAZON_S3_BUCKET_OPEN, APPSTORE_ENTRY, ACCOUNT_EXTERNAL_OWNED,
		ACCOUNT_EXTERNAL_OWNED_COMPROMISED, ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED,
		BASE64_DATA, BGP_AS_MEMBER, BGP_AS_OWNER, BGP_AS_PEER, BITCOIN_ADDRESS,
		BITCOIN_BALANCE, BLACKLISTED_AFFILIATE_INTERNET_NAME, BLACKLISTED_AFFILIATE_IPADDR, BLACKLISTED_AFFILIATE_SUBNET,
		BLACKLISTED_AFFILIATE_NETBLOCK, BLACKLISTED_COHOST, BLACKLISTED_INTERNET_NAME,
		BLACKLISTED_IPADDR, BLACKLISTED_NETBLOCK, BLACKLISTED_SUBNET, CO_HOSTED_SITE,
		CO_HOSTED_SITE_DOMAIN, CO_HOSTED_SITE_DOMAIN_WHOIS, CLOUD_STORAGE_BUCKET,
		CLOUD_STORAGE_BUCKET_OPEN, COMPANY_NAME, COUNTRY_NAME, CREDIT_CARD_NUMBER,
		DARKNET_MENTION_CONTENT, DARKNET_MENTION_URL, DATE_HUMAN_DOB,
		DEFACED_AFFILIATE_INTERNET_NAME, DEFACED_INTERNET_NAME, DEFACED_AFFILIATE_IPADDR,
		DEFACED_COHOST, DEFACED_IPADDR, DESCRIPTION_ABSTRACT, DESCRIPTION_CATEGORY, DEVICE_TYPE,
		DNS_SRV, DNS_TXT, DNS_SPF, DOMAIN_NAME, DOMAIN_NAME_PARENT, DOMAIN_REGISTRAR,
		DOMAIN_WHOIS, EMAILADDR, EMAILADDR_COMPROMISED, EMAILADDR_DEALIASED,
		EMAILADDR_GENERIC, ERROR_MESSAGE, ETHEREUM_ADDRESS, GEOINFO, GPS_ROUTE,
		HACKED_EMAIL_ADDRESS, HASH, HASH_COMPROMISED, HTTP_CODE, HUMAN_NAME,
		IBAN_NUMBER, INTERESTING_FILE, INTERESTING_FILE_CONTENT, INTERESTING_FILE_HISTORIC,
		URL_FORM_HISTORIC, URL_FLASH_HISTORIC, URL_STATIC_HISTORIC,
		URL_JAVA_APPLET_HISTORIC, URL_UPLOAD_HISTORIC, URL_JAVASCRIPT_HISTORIC,
		URL_PASSWORD_HISTORIC, URL_WEB_FRAMEWORK_HISTORIC, INTERNET_NAME,
		INTERNET_NAME_UNRESOLVED, IP_ADDRESS, IPV6_ADDRESS, JUNK_FILE, LEAKSITE_CONTENT,
		LEAKSITE_URL, LINKED_URL_EXTERNAL, LINKED_URL_INTERNAL,
		MALICIOUS_BITCOIN_ADDRESS,
		MALICIOUS_AFFILIATE_INTERNET_NAME, MALICIOUS_AFFILIATE_IPADDR, MALICIOUS_ASN, MALICIOUS_COHOST,
		MALICIOUS_EMAILADDR, MALICIOUS_INTERNET_NAME, MALICIOUS_IPADDR,
		MALICIOUS_NETBLOCK, MALICIOUS_PHONE_NUMBER, MALICIOUS_SUBNET, NETBLOCK_MEMBER,
		NETBLOCK_OWNER, NETBLOCKV6_MEMBER, NETBLOCKV6_OWNER, OPERATING_SYSTEM,
		PASSWORD_COMPROMISED, PHONE_NUMBER, PHONE_NUMBER_COMPROMISED, PHYSICAL_ADDRESS, PHYSICAL_COORDINATES,
		PGP_KEY, PROVIDER_DNS, PROVIDER_HOSTING, PROVIDER_JAVASCRIPT, PROVIDER_MAIL,
		PROVIDER_TELCO, PUBLIC_CODE_REPO, RAW_DNS_RECORDS, RAW_FILE_META_DATA,
		RAW_RIR_DATA, SEARCH_ENGINE_WEB_CONTENT, SIMILARDOMAIN, SOCIAL_MEDIA,
		SOFTWARE_USED, SSL_CERTIFICATE_EXPIRED, SSL_CERTIFICATE_EXPIRING,
		SSL_CERTIFICATE_ISSUED, SSL_CERTIFICATE_ISSUER, SSL_CERTIFICATE_MISMATCH,
		SSL_CERTIFICATE_RAW, TARGET_WEB_CONTENT, TARGET_WEB_CONTENT_TYPE,
		TARGET_WEB_COOKIE, TCP_PORT_OPEN, TCP_PORT_OPEN_BANNER, UDP_PORT_OPEN, TLD_PARENT,
		URL_ADBLOCKED_EXTERNAL, URL_ADBLOCKED_INTERNAL, URL_FORM, URL_FLASH,
		URL_JAVASCRIPT, URL_JAVA_APPLET, URL_PASSWORD, URL_STATIC, URL_UPLOAD,
		URL_WEB_FRAMEWORK, USERNAME, VULNERABILITY_CVE_CRITICAL, VULNERABILITY_CVE_HIGH,
		VULNERABILITY_CVE_INFO, VULNERABILITY_CVE_LOW, VULNERABILITY_CVE_MEDIUM,
		VULNERABILITY_DISCLOSURE, VULNERABILITY_GENERAL, WEBSERVER_BANNER,
		WEBSERVER_HTTPHEADERS, WEBSERVER_STRANGEHEADER, WEBSERVER_TECHNOLOGY,
		WIFI_ACCESS_POINT, WIKIPEDIA_PAGE_EDIT, WEB_ANALYTICS_ID, WEBSERVER_URL,
		WEBSERVER_URL_EXTERNAL,
	}

	registry := make(map[Type]TypeInfo, len(types))
	for _, typ := range types {
		registry[typ] = TypeInfo{
			Type:        typ,
			Description: humanizeType(typ),
			IsRaw:       false,
			Category:    "ENTITY",
		}
	}

	for typ, info := range registryOverrides() {
		registry[typ] = info
	}

	return registry
}

func registryOverrides() map[Type]TypeInfo {
	return map[Type]TypeInfo{
		ROOT:                                     {Type: ROOT, Description: "Internal SpiderFoot Root Event", IsRaw: true, Category: "INTERNAL"},
		ACCOUNT_EXTERNAL_OWNED:                   {Type: ACCOUNT_EXTERNAL_OWNED, Description: "Account on External Site", Category: "ENTITY"},
		ACCOUNT_EXTERNAL_OWNED_COMPROMISED:       {Type: ACCOUNT_EXTERNAL_OWNED_COMPROMISED, Description: "Hacked Account on External Site", Category: "DESCRIPTOR"},
		ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED: {Type: ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED, Description: "Hacked User Account on External Site", Category: "DESCRIPTOR"},
		AFFILIATE_DOMAIN_NAME:                    {Type: AFFILIATE_DOMAIN_NAME, Description: "Affiliate - Domain Name", Category: "ENTITY"},
		AFFILIATE_DOMAIN_UNRESOLVED:              {Type: AFFILIATE_DOMAIN_UNRESOLVED, Description: "Affiliate - Domain Name - Unresolved", Category: "ENTITY"},
		AFFILIATE_DOMAIN_WHOIS:                   {Type: AFFILIATE_DOMAIN_WHOIS, Description: "Affiliate - Domain Whois", IsRaw: true, Category: "DATA"},
		AFFILIATE_EMAILADDR:                      {Type: AFFILIATE_EMAILADDR, Description: "Affiliate - Email Address", Category: "ENTITY"},
		AFFILIATE_INTERNET_NAME:                  {Type: AFFILIATE_INTERNET_NAME, Description: "Affiliate - Internet Name", Category: "ENTITY"},
		AFFILIATE_INTERNET_NAME_UNRESOLVED:       {Type: AFFILIATE_INTERNET_NAME_UNRESOLVED, Description: "Affiliate - Internet Name - Unresolved", Category: "ENTITY"},
		AFFILIATE_IPADDR:                         {Type: AFFILIATE_IPADDR, Description: "Affiliate - IP Address", Category: "ENTITY"},
		AFFILIATE_IPV6_ADDRESS:                   {Type: AFFILIATE_IPV6_ADDRESS, Description: "Affiliate - IPv6 Address", Category: "ENTITY"},
		AFFILIATE_WEB_CONTENT:                    {Type: AFFILIATE_WEB_CONTENT, Description: "Affiliate - Web Content", IsRaw: true, Category: "DATA"},
		AMAZON_S3_BUCKET:                         {Type: AMAZON_S3_BUCKET, Description: "Amazon S3 Bucket", Category: "ENTITY"},
		AMAZON_S3_BUCKET_OPEN:                    {Type: AMAZON_S3_BUCKET_OPEN, Description: "Amazon S3 Bucket Open", Category: "DESCRIPTOR"},
		APPSTORE_ENTRY:                           {Type: APPSTORE_ENTRY, Description: "App Store Entry", Category: "ENTITY"},
		BASE64_DATA:                              {Type: BASE64_DATA, Description: "Base64-Encoded Data", IsRaw: true, Category: "DATA"},
		BGP_AS_MEMBER:                            {Type: BGP_AS_MEMBER, Description: "BGP AS Membership", Category: "ENTITY"},
		BGP_AS_OWNER:                             {Type: BGP_AS_OWNER, Description: "BGP AS Ownership", Category: "ENTITY"},
		BGP_AS_PEER:                              {Type: BGP_AS_PEER, Description: "BGP AS Peer", Category: "ENTITY"},
		BITCOIN_ADDRESS:                          {Type: BITCOIN_ADDRESS, Description: "Bitcoin Address", Category: "ENTITY"},
		BITCOIN_BALANCE:                          {Type: BITCOIN_BALANCE, Description: "Bitcoin Balance", Category: "DESCRIPTOR"},
		BLACKLISTED_AFFILIATE_INTERNET_NAME:      {Type: BLACKLISTED_AFFILIATE_INTERNET_NAME, Description: "Blacklisted Affiliate Internet Name", Category: "DESCRIPTOR"},
		BLACKLISTED_AFFILIATE_IPADDR:             {Type: BLACKLISTED_AFFILIATE_IPADDR, Description: "Blacklisted Affiliate IP Address", Category: "DESCRIPTOR"},
		BLACKLISTED_AFFILIATE_SUBNET:             {Type: BLACKLISTED_AFFILIATE_SUBNET, Description: "Blacklisted Affiliate IP on Same Subnet", Category: "DESCRIPTOR"},
		BLACKLISTED_AFFILIATE_NETBLOCK:           {Type: BLACKLISTED_AFFILIATE_NETBLOCK, Description: "Blacklisted Affiliate IP on Owned Netblock", Category: "DESCRIPTOR"},
		BLACKLISTED_COHOST:                       {Type: BLACKLISTED_COHOST, Description: "Blacklisted Co-Hosted Site", Category: "DESCRIPTOR"},
		BLACKLISTED_INTERNET_NAME:                {Type: BLACKLISTED_INTERNET_NAME, Description: "Blacklisted Internet Name", Category: "DESCRIPTOR"},
		BLACKLISTED_IPADDR:                       {Type: BLACKLISTED_IPADDR, Description: "Blacklisted IP Address", Category: "DESCRIPTOR"},
		BLACKLISTED_NETBLOCK:                     {Type: BLACKLISTED_NETBLOCK, Description: "Blacklisted IP on Owned Netblock", Category: "DESCRIPTOR"},
		BLACKLISTED_SUBNET:                       {Type: BLACKLISTED_SUBNET, Description: "Blacklisted IP on Same Subnet", Category: "DESCRIPTOR"},
		CO_HOSTED_SITE:                           {Type: CO_HOSTED_SITE, Description: "Co-Hosted Site", Category: "ENTITY"},
		CO_HOSTED_SITE_DOMAIN:                    {Type: CO_HOSTED_SITE_DOMAIN, Description: "Co-Hosted Site - Domain Name", Category: "ENTITY"},
		CO_HOSTED_SITE_DOMAIN_WHOIS:              {Type: CO_HOSTED_SITE_DOMAIN_WHOIS, Description: "Co-Hosted Site - Domain Whois", IsRaw: true, Category: "DATA"},
		CLOUD_STORAGE_BUCKET:                     {Type: CLOUD_STORAGE_BUCKET, Description: "Cloud Storage Bucket", Category: "ENTITY"},
		CLOUD_STORAGE_BUCKET_OPEN:                {Type: CLOUD_STORAGE_BUCKET_OPEN, Description: "Cloud Storage Bucket Open", Category: "DESCRIPTOR"},
		COMPANY_NAME:                             {Type: COMPANY_NAME, Description: "Company Name", Category: "ENTITY"},
		COUNTRY_NAME:                             {Type: COUNTRY_NAME, Description: "Country Name", Category: "ENTITY"},
		CREDIT_CARD_NUMBER:                       {Type: CREDIT_CARD_NUMBER, Description: "Credit Card Number", Category: "ENTITY"},
		DARKNET_MENTION_CONTENT:                  {Type: DARKNET_MENTION_CONTENT, Description: "Darknet Mention Web Content", IsRaw: true, Category: "DATA"},
		DARKNET_MENTION_URL:                      {Type: DARKNET_MENTION_URL, Description: "Darknet Mention URL", Category: "DESCRIPTOR"},
		DATE_HUMAN_DOB:                           {Type: DATE_HUMAN_DOB, Description: "Date of Birth", Category: "ENTITY"},
		DEFACED_AFFILIATE_INTERNET_NAME:          {Type: DEFACED_AFFILIATE_INTERNET_NAME, Description: "Defaced Affiliate", Category: "DESCRIPTOR"},
		DEFACED_AFFILIATE_IPADDR:                 {Type: DEFACED_AFFILIATE_IPADDR, Description: "Defaced Affiliate IP Address", Category: "DESCRIPTOR"},
		DEFACED_COHOST:                           {Type: DEFACED_COHOST, Description: "Defaced Co-Hosted Site", Category: "DESCRIPTOR"},
		DEFACED_INTERNET_NAME:                    {Type: DEFACED_INTERNET_NAME, Description: "Defaced", Category: "DESCRIPTOR"},
		DEFACED_IPADDR:                           {Type: DEFACED_IPADDR, Description: "Defaced IP Address", Category: "DESCRIPTOR"},
		DESCRIPTION_ABSTRACT:                     {Type: DESCRIPTION_ABSTRACT, Description: "Description - Abstract", Category: "DESCRIPTOR"},
		DESCRIPTION_CATEGORY:                     {Type: DESCRIPTION_CATEGORY, Description: "Description - Category", Category: "DESCRIPTOR"},
		DNS_SRV:                                  {Type: DNS_SRV, Description: "DNS SRV Record", Category: "DATA"},
		DNS_SPF:                                  {Type: DNS_SPF, Description: "DNS SPF Record", Category: "DATA"},
		DNS_TXT:                                  {Type: DNS_TXT, Description: "DNS TXT Record", Category: "DATA"},
		DOMAIN_NAME:                              {Type: DOMAIN_NAME, Description: "Domain Name", Category: "ENTITY"},
		DOMAIN_NAME_PARENT:                       {Type: DOMAIN_NAME_PARENT, Description: "Domain Name (Parent)", Category: "ENTITY"},
		DOMAIN_REGISTRAR:                         {Type: DOMAIN_REGISTRAR, Description: "Domain Registrar", Category: "ENTITY"},
		DOMAIN_WHOIS:                             {Type: DOMAIN_WHOIS, Description: "Domain Whois", IsRaw: true, Category: "DATA"},
		EMAILADDR:                                {Type: EMAILADDR, Description: "Email Address", Category: "ENTITY"},
		EMAILADDR_COMPROMISED:                    {Type: EMAILADDR_COMPROMISED, Description: "Hacked Email Address", Category: "DESCRIPTOR"},
		EMAILADDR_DEALIASED:                      {Type: EMAILADDR_DEALIASED, Description: "Email Address - De-Aliased", Category: "DESCRIPTOR"},
		EMAILADDR_GENERIC:                        {Type: EMAILADDR_GENERIC, Description: "Email Address - Generic", Category: "ENTITY"},
		ERROR_MESSAGE:                            {Type: ERROR_MESSAGE, Description: "Error Message", Category: "DATA"},
		ETHEREUM_ADDRESS:                         {Type: ETHEREUM_ADDRESS, Description: "Ethereum Address", Category: "ENTITY"},
		GEOINFO:                                  {Type: GEOINFO, Description: "Physical Location", Category: "DESCRIPTOR"},
		GPS_ROUTE:                                {Type: GPS_ROUTE, Description: "GPS Route", IsRaw: true, Category: "DATA"},
		HACKED_EMAIL_ADDRESS:                     {Type: HACKED_EMAIL_ADDRESS, Description: "Hacked Email Address", Category: "DESCRIPTOR"},
		HASH:                                     {Type: HASH, Description: "Hash", Category: "DATA"},
		HASH_COMPROMISED:                         {Type: HASH_COMPROMISED, Description: "Compromised Password Hash", Category: "DATA"},
		HTTP_CODE:                                {Type: HTTP_CODE, Description: "HTTP Status Code", Category: "DATA"},
		HUMAN_NAME:                               {Type: HUMAN_NAME, Description: "Human Name", Category: "ENTITY"},
		IBAN_NUMBER:                              {Type: IBAN_NUMBER, Description: "IBAN Number", Category: "ENTITY"},
		INTERESTING_FILE:                         {Type: INTERESTING_FILE, Description: "Interesting File", Category: "DESCRIPTOR"},
		INTERESTING_FILE_CONTENT:                 {Type: INTERESTING_FILE_CONTENT, Description: "Interesting File Content", IsRaw: true, Category: "DATA"},
		INTERNET_NAME:                            {Type: INTERNET_NAME, Description: "Internet Name", Category: "ENTITY"},
		INTERNET_NAME_UNRESOLVED:                 {Type: INTERNET_NAME_UNRESOLVED, Description: "Internet Name - Unresolved", Category: "ENTITY"},
		IP_ADDRESS:                               {Type: IP_ADDRESS, Description: "IP Address", Category: "ENTITY"},
		IPV6_ADDRESS:                             {Type: IPV6_ADDRESS, Description: "IPv6 Address", Category: "ENTITY"},
		JUNK_FILE:                                {Type: JUNK_FILE, Description: "Junk File", Category: "DESCRIPTOR"},
		LEAKSITE_CONTENT:                         {Type: LEAKSITE_CONTENT, Description: "Leak Site Content", IsRaw: true, Category: "DATA"},
		LEAKSITE_URL:                             {Type: LEAKSITE_URL, Description: "Leak Site URL", Category: "ENTITY"},
		LINKED_URL_EXTERNAL:                      {Type: LINKED_URL_EXTERNAL, Description: "Linked URL - External", Category: "SUBENTITY"},
		LINKED_URL_INTERNAL:                      {Type: LINKED_URL_INTERNAL, Description: "Linked URL - Internal", Category: "SUBENTITY"},
		MALICIOUS_BITCOIN_ADDRESS:                {Type: MALICIOUS_BITCOIN_ADDRESS, Description: "Malicious Bitcoin Address", Category: "DESCRIPTOR"},
		MALICIOUS_AFFILIATE_INTERNET_NAME:        {Type: MALICIOUS_AFFILIATE_INTERNET_NAME, Description: "Malicious Affiliate", Category: "DESCRIPTOR"},
		MALICIOUS_AFFILIATE_IPADDR:               {Type: MALICIOUS_AFFILIATE_IPADDR, Description: "Malicious Affiliate IP Address", Category: "DESCRIPTOR"},
		MALICIOUS_COHOST:                         {Type: MALICIOUS_COHOST, Description: "Malicious Co-Hosted Site", Category: "DESCRIPTOR"},
		MALICIOUS_EMAILADDR:                      {Type: MALICIOUS_EMAILADDR, Description: "Malicious E-Mail Address", Category: "DESCRIPTOR"},
		MALICIOUS_INTERNET_NAME:                  {Type: MALICIOUS_INTERNET_NAME, Description: "Malicious Internet Name", Category: "DESCRIPTOR"},
		MALICIOUS_IPADDR:                         {Type: MALICIOUS_IPADDR, Description: "Malicious IP Address", Category: "DESCRIPTOR"},
		MALICIOUS_NETBLOCK:                       {Type: MALICIOUS_NETBLOCK, Description: "Malicious IP on Owned Netblock", Category: "DESCRIPTOR"},
		MALICIOUS_PHONE_NUMBER:                   {Type: MALICIOUS_PHONE_NUMBER, Description: "Malicious Phone Number", Category: "DESCRIPTOR"},
		MALICIOUS_SUBNET:                         {Type: MALICIOUS_SUBNET, Description: "Malicious IP on Same Subnet", Category: "DESCRIPTOR"},
		NETBLOCK_MEMBER:                          {Type: NETBLOCK_MEMBER, Description: "Netblock Membership", Category: "ENTITY"},
		NETBLOCK_OWNER:                           {Type: NETBLOCK_OWNER, Description: "Netblock Ownership", Category: "ENTITY"},
		NETBLOCKV6_MEMBER:                        {Type: NETBLOCKV6_MEMBER, Description: "Netblock IPv6 Membership", Category: "ENTITY"},
		NETBLOCKV6_OWNER:                         {Type: NETBLOCKV6_OWNER, Description: "Netblock IPv6 Ownership", Category: "ENTITY"},
		OPERATING_SYSTEM:                         {Type: OPERATING_SYSTEM, Description: "Operating System", Category: "DESCRIPTOR"},
		PASSWORD_COMPROMISED:                     {Type: PASSWORD_COMPROMISED, Description: "Compromised Password", Category: "DATA"},
		PHONE_NUMBER:                             {Type: PHONE_NUMBER, Description: "Phone Number", Category: "ENTITY"},
		PHYSICAL_ADDRESS:                         {Type: PHYSICAL_ADDRESS, Description: "Physical Address", Category: "ENTITY"},
		PHYSICAL_COORDINATES:                     {Type: PHYSICAL_COORDINATES, Description: "Physical Coordinates", Category: "ENTITY"},
		PGP_KEY:                                  {Type: PGP_KEY, Description: "PGP Public Key", Category: "DATA"},
		PROVIDER_DNS:                             {Type: PROVIDER_DNS, Description: "Name Server (DNS NS Records)", Category: "ENTITY"},
		PROVIDER_HOSTING:                         {Type: PROVIDER_HOSTING, Description: "Hosting Provider", Category: "ENTITY"},
		PROVIDER_JAVASCRIPT:                      {Type: PROVIDER_JAVASCRIPT, Description: "Externally Hosted Javascript", Category: "ENTITY"},
		PROVIDER_MAIL:                            {Type: PROVIDER_MAIL, Description: "Email Gateway (DNS MX Records)", Category: "ENTITY"},
		PROVIDER_TELCO:                           {Type: PROVIDER_TELCO, Description: "Telecommunications Provider", Category: "ENTITY"},
		PUBLIC_CODE_REPO:                         {Type: PUBLIC_CODE_REPO, Description: "Public Code Repository", Category: "ENTITY"},
		RAW_DNS_RECORDS:                          {Type: RAW_DNS_RECORDS, Description: "Raw DNS Records", IsRaw: true, Category: "DATA"},
		RAW_FILE_META_DATA:                       {Type: RAW_FILE_META_DATA, Description: "Raw File Meta Data", IsRaw: true, Category: "DATA"},
		RAW_RIR_DATA:                             {Type: RAW_RIR_DATA, Description: "Raw Data from RIRs/APIs", IsRaw: true, Category: "DATA"},
		SEARCH_ENGINE_WEB_CONTENT:                {Type: SEARCH_ENGINE_WEB_CONTENT, Description: "Search Engine Web Content", IsRaw: true, Category: "DATA"},
		SIMILARDOMAIN:                            {Type: SIMILARDOMAIN, Description: "Similar Domain", Category: "ENTITY"},
		SOCIAL_MEDIA:                             {Type: SOCIAL_MEDIA, Description: "Social Media Presence", Category: "ENTITY"},
		SOFTWARE_USED:                            {Type: SOFTWARE_USED, Description: "Software Used", Category: "SUBENTITY"},
		SSL_CERTIFICATE_EXPIRED:                  {Type: SSL_CERTIFICATE_EXPIRED, Description: "SSL Certificate Expired", Category: "DESCRIPTOR"},
		SSL_CERTIFICATE_EXPIRING:                 {Type: SSL_CERTIFICATE_EXPIRING, Description: "SSL Certificate Expiring", Category: "DESCRIPTOR"},
		SSL_CERTIFICATE_ISSUED:                   {Type: SSL_CERTIFICATE_ISSUED, Description: "SSL Certificate - Issued To", Category: "ENTITY"},
		SSL_CERTIFICATE_ISSUER:                   {Type: SSL_CERTIFICATE_ISSUER, Description: "SSL Certificate - Issued By", Category: "ENTITY"},
		SSL_CERTIFICATE_MISMATCH:                 {Type: SSL_CERTIFICATE_MISMATCH, Description: "SSL Certificate Host Mismatch", Category: "DESCRIPTOR"},
		SSL_CERTIFICATE_RAW:                      {Type: SSL_CERTIFICATE_RAW, Description: "SSL Certificate - Raw Data", IsRaw: true, Category: "DATA"},
		TARGET_WEB_CONTENT:                       {Type: TARGET_WEB_CONTENT, Description: "Web Content", IsRaw: true, Category: "DATA"},
		TARGET_WEB_CONTENT_TYPE:                  {Type: TARGET_WEB_CONTENT_TYPE, Description: "Web Content Type", Category: "DESCRIPTOR"},
		TARGET_WEB_COOKIE:                        {Type: TARGET_WEB_COOKIE, Description: "Cookies", Category: "DATA"},
		TCP_PORT_OPEN:                            {Type: TCP_PORT_OPEN, Description: "Open TCP Port", Category: "SUBENTITY"},
		TCP_PORT_OPEN_BANNER:                     {Type: TCP_PORT_OPEN_BANNER, Description: "Open TCP Port Banner", Category: "DATA"},
		TLD_PARENT:                               {Type: TLD_PARENT, Description: "Top-Level Domain (Parent)", Category: "ENTITY"},
		URL_ADBLOCKED_EXTERNAL:                   {Type: URL_ADBLOCKED_EXTERNAL, Description: "URL (AdBlocked External)", Category: "DESCRIPTOR"},
		URL_ADBLOCKED_INTERNAL:                   {Type: URL_ADBLOCKED_INTERNAL, Description: "URL (AdBlocked Internal)", Category: "DESCRIPTOR"},
		URL_FORM:                                 {Type: URL_FORM, Description: "URL (Form)", Category: "DESCRIPTOR"},
		URL_FLASH:                                {Type: URL_FLASH, Description: "URL (Uses Flash)", Category: "DESCRIPTOR"},
		URL_JAVASCRIPT:                           {Type: URL_JAVASCRIPT, Description: "URL (Uses Javascript)", Category: "DESCRIPTOR"},
		URL_JAVA_APPLET:                          {Type: URL_JAVA_APPLET, Description: "URL (Uses Java Applet)", Category: "DESCRIPTOR"},
		URL_PASSWORD:                             {Type: URL_PASSWORD, Description: "URL (Accepts Passwords)", Category: "DESCRIPTOR"},
		URL_STATIC:                               {Type: URL_STATIC, Description: "URL (Purely Static)", Category: "DESCRIPTOR"},
		URL_UPLOAD:                               {Type: URL_UPLOAD, Description: "URL (Accepts Uploads)", Category: "DESCRIPTOR"},
		URL_WEB_FRAMEWORK:                        {Type: URL_WEB_FRAMEWORK, Description: "URL (Uses a Web Framework)", Category: "DESCRIPTOR"},
		USERNAME:                                 {Type: USERNAME, Description: "Username", Category: "ENTITY"},
		VULNERABILITY_CVE_CRITICAL:               {Type: VULNERABILITY_CVE_CRITICAL, Description: "Vulnerability - CVE Critical", Category: "DESCRIPTOR"},
		VULNERABILITY_CVE_HIGH:                   {Type: VULNERABILITY_CVE_HIGH, Description: "Vulnerability - CVE High", Category: "DESCRIPTOR"},
		VULNERABILITY_CVE_INFO:                   {Type: VULNERABILITY_CVE_INFO, Description: "Vulnerability - CVE Info", Category: "DESCRIPTOR"},
		VULNERABILITY_CVE_LOW:                    {Type: VULNERABILITY_CVE_LOW, Description: "Vulnerability - CVE Low", Category: "DESCRIPTOR"},
		VULNERABILITY_CVE_MEDIUM:                 {Type: VULNERABILITY_CVE_MEDIUM, Description: "Vulnerability - CVE Medium", Category: "DESCRIPTOR"},
		VULNERABILITY_DISCLOSURE:                 {Type: VULNERABILITY_DISCLOSURE, Description: "Vulnerability - Third Party Disclosure", Category: "DESCRIPTOR"},
		VULNERABILITY_GENERAL:                    {Type: VULNERABILITY_GENERAL, Description: "Vulnerability - General", Category: "DESCRIPTOR"},
		WEB_ANALYTICS_ID:                         {Type: WEB_ANALYTICS_ID, Description: "Web Analytics", Category: "ENTITY"},
		WEBSERVER_BANNER:                         {Type: WEBSERVER_BANNER, Description: "Web Server", Category: "DATA"},
		WEBSERVER_HTTPHEADERS:                    {Type: WEBSERVER_HTTPHEADERS, Description: "HTTP Headers", IsRaw: true, Category: "DATA"},
		WEBSERVER_STRANGEHEADER:                  {Type: WEBSERVER_STRANGEHEADER, Description: "Non-Standard HTTP Header", Category: "DATA"},
		WEBSERVER_TECHNOLOGY:                     {Type: WEBSERVER_TECHNOLOGY, Description: "Web Technology", Category: "DESCRIPTOR"},
		WEBSERVER_URL:                            {Type: WEBSERVER_URL, Description: "Web Server URL", Category: "SUBENTITY"},
		WEBSERVER_URL_EXTERNAL:                   {Type: WEBSERVER_URL_EXTERNAL, Description: "Web Server URL - External", Category: "SUBENTITY"},
		WIFI_ACCESS_POINT:                        {Type: WIFI_ACCESS_POINT, Description: "WiFi Access Point Nearby", Category: "ENTITY"},
		WIKIPEDIA_PAGE_EDIT:                      {Type: WIKIPEDIA_PAGE_EDIT, Description: "Wikipedia Page Edit", Category: "DESCRIPTOR"},
	}
}

func humanizeType(typ Type) string {
	parts := strings.Split(string(typ), "_")
	for i, part := range parts {
		switch part {
		case "IP":
			parts[i] = "IP"
		case "IPV6":
			parts[i] = "IPv6"
		case "DNS":
			parts[i] = "DNS"
		case "TXT":
			parts[i] = "TXT"
		case "SRV":
			parts[i] = "SRV"
		case "SPF":
			parts[i] = "SPF"
		case "HTTP":
			parts[i] = "HTTP"
		case "URL":
			parts[i] = "URL"
		case "TCP":
			parts[i] = "TCP"
		case "TLD":
			parts[i] = "TLD"
		case "SSL":
			parts[i] = "SSL"
		case "PGP":
			parts[i] = "PGP"
		case "BGP":
			parts[i] = "BGP"
		case "CVE":
			parts[i] = "CVE"
		case "S3":
			parts[i] = "S3"
		case "IBAN":
			parts[i] = "IBAN"
		default:
			parts[i] = toTitle(part)
		}
	}

	return strings.Join(parts, " ")
}

func toTitle(s string) string {
	if s == "" {
		return s
	}

	runes := []rune(strings.ToLower(s))
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
