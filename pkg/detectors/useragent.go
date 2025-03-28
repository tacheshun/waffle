package detectors

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/tacheshun/waffle/pkg/types"
)

// UserAgentDetector detects suspicious user agents
type UserAgentDetector struct {
	enabled  bool
	patterns []*regexp.Regexp
}

// NewUserAgentDetector creates a new user agent detector
func NewUserAgentDetector() *UserAgentDetector {
	detector := &UserAgentDetector{
		enabled:  true,
		patterns: compileUserAgentPatterns(),
	}
	return detector
}

// Name returns the unique identifier for the User Agent detector.
func (d *UserAgentDetector) Name() string {
	return "user_agent"
}

// Match checks if the request contains suspicious user agent patterns
func (d *UserAgentDetector) Match(r *http.Request) (bool, *types.BlockReason) {
	if !d.enabled {
		return false, nil
	}

	// Check User-Agent header
	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		if d.checkString(userAgent) {
			return true, &types.BlockReason{
				Rule:    "user_agent",
				Message: "Suspicious user agent detected: " + userAgent,
			}
		}
	}

	return false, nil
}

// IsEnabled returns whether the detector is enabled
func (d *UserAgentDetector) IsEnabled() bool {
	return d.enabled
}

// Enable enables the detector
func (d *UserAgentDetector) Enable() {
	d.enabled = true
}

// Disable disables the detector
func (d *UserAgentDetector) Disable() {
	d.enabled = false
}

// checkString checks if a string contains suspicious user agent patterns
func (d *UserAgentDetector) checkString(s string) bool {
	// Normalize the string
	s = strings.ToLower(s)

	// Check against patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	return false
}

// compileUserAgentPatterns compiles and returns user agent detection patterns
func compileUserAgentPatterns() []*regexp.Regexp {
	patterns := []string{
		// Common security scanners and penetration testing tools
		`(?i)^.*(nessus|nmap|nikto|wikto|sf|sqlmap|bsqlbf|w3af|acunetix|havij|appscan).*$`,

		// Suspicious clients that are often used in automation
		`(?i)^.*(libwww-perl|python-requests|python-urllib|httpclient|java/|curl|wget|libcurl|urllib|ruby|mechanize|perl).*$`,

		// Empty or suspicious User-Agent values
		`(?i)^$`,
		`(?i)^(mozilla|chrome|safari|opera|msie|trident)$`,
		`(?i)^(mozilla|chrome|safari|opera|msie|trident)/[\d\.]+$`,

		// Common web vulnerability scanners
		`(?i)^.*(burpsuite|owasp-zap|paros|webinspect|websecurify|dirbuster|wfuzz|zgrab).*$`,

		// Common DDoS tools
		`(?i)^.*(loic|hoic|slowloris|goldeneye|hulk|hping|xerxes).*$`,

		// Common web shells
		`(?i)^.*(c99|r57|webshell|b374k|weevely|phpshell|backdoor).*$`,

		// Known malicious bots
		`(?i)^.*(80legs|aboundex|ahrefsbot|asp-audit|asynchttpclient|baidu|bingbot|blekkobot|blexbot|bot|casper|checkpriv|cheesebot|chinaclaw|chronos|clshttp|cmsworldmap|cmsworld|copernic|copyrightcheck|cosmos|crackmapexec|cusco|demon|diavol|domainappender|dotbot|dotnetdotcom|dts agent|emailcollector|emailextractor|emailsiphon|emailwolf|extractorpro|ezooms|fimap|findlinks|fuck-scanner|fyodor|gaisbot|galaxybot|genieo|getintent|grapefx|harvest|heritrix|httpclient|httplib|humanlinks|ia_archiver|indy library|kdnxj9|kraken|larbin|leechftp|loader|lwp-trivial|masscan|miner|morfeus|movabletype|mj12bot|msrabot|nagios|netcraft|netscoop|netluchs|nikto|nimbostratus|nuclear|nutch|octopus|pagegrabber|petalbot|planetwork|prawler|proximiac|repomonkey|rma|s.t.a.l.k.e.r.|scan|screenerbot|searchestate|semalt|siclab|sindice|sistrix|sitebot|site-scraper|sitesucker|spbot|sqlmap|stackrambler|stripper|sucker|surftbot|suzuran|swiftbot|tecniseek|teleport|telesoft|the\.bat|titan|turnitin|unister|updown_tester|urlspider|vagabondo|voideye|webauto|webbandit|webcollage|webdav|webenhancer|webmastercoffee|webpictures|websauger|webshag|webstripper|webvac|webviewer|webwhacker|webzip|wesee|wget|winhttp|wordpress|worm|www-collector-e|xaldon|xenu|zermelo|zmeu|zend|zeus|zyborg).*$`,

		// Suspicious encodings or numeric patterns
		`(?i)^.*(base64|eval|exec|system|passthru|shell_exec|phpinfo|chmod|mkdir|fopen|fclose|readfile|edoced_46esab).*$`,

		// IoT device scanners
		`(?i)^.*(iot|default|dvr|cam|camera|netcam|netgear|linksys|cisco|huawei|mikrotik|hikvision|avtech|dahua|axis|foscam|tenda|tp-link|ubiquiti).*$`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			compiled = append(compiled, re)
		}
	}

	return compiled
}
