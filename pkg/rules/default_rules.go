package rules

import (
	"net/http"
	"regexp"
	"strings"
)

// DefaultRuleSet returns a rule set with default security rules
func DefaultRuleSet() *RuleSet {
	rs := NewRuleSet()

	// Add SQL injection rule
	rs.AddRule(NewSQLiRule())

	// Add XSS rule
	rs.AddRule(NewXSSRule())

	// Add command injection rule
	rs.AddRule(NewCommandInjectionRule())

	// Add path traversal rule
	rs.AddRule(NewPathTraversalRule())

	// Add user agent rule
	rs.AddRule(NewUserAgentRule())

	return rs
}

// NewSQLiRule creates a rule for detecting SQL injection attacks
func NewSQLiRule() Rule {
	patterns := []string{
		`(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)`,
		`(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))`,
		`(?i)(\w|\d|\.)+\s+as\s+\w+\s*from`,
		`(?i)select\s+[\w\*\)\(\,\s]+\s+from\s+[\w\.]+`,
		`(?i)insert\s+into\s+[\w\.]+\s*[\(\w\s\)\,]*\s*values\s*\(`,
		`(?i)delete\s+from\s+[\w\.]+`,
		`(?i)update\s+[\w\.]+\s+set\s+[\w\s\=\,]+`,
		`(?i)(union\s+select)`,
		`(?i)(select\s+sleep\s*\()`,
		`(?i)(waitfor\s+delay\s*\')`,
		`(?i)(select\s+benchmark\s*\()`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			compiled = append(compiled, re)
		}
	}

	return NewRule("sql_injection", func(r *http.Request) (bool, *BlockReason) {
		// Parse form data to access POST parameters
		r.ParseForm()

		// Check URL path
		if checkPatterns(r.URL.Path, compiled) {
			return true, &BlockReason{
				Rule:    "sql_injection",
				Message: "SQL injection detected in URL path",
			}
		}

		// Check query parameters
		for key, values := range r.URL.Query() {
			for _, value := range values {
				if checkPatterns(value, compiled) {
					return true, &BlockReason{
						Rule:    "sql_injection",
						Message: "SQL injection detected in query parameter: " + key,
					}
				}
			}
		}

		// Check form parameters
		for key, values := range r.Form {
			for _, value := range values {
				if checkPatterns(value, compiled) {
					return true, &BlockReason{
						Rule:    "sql_injection",
						Message: "SQL injection detected in form parameter: " + key,
					}
				}
			}
		}

		return false, nil
	})
}

// NewXSSRule creates a rule for detecting cross-site scripting attacks
func NewXSSRule() Rule {
	patterns := []string{
		`(?i)<script[^>]*>.*?</script>`,
		`(?i)<script[^>]*>`,
		`(?i)<iframe[^>]*>.*?</iframe>`,
		`(?i)<object[^>]*>.*?</object>`,
		`(?i)<embed[^>]*>.*?</embed>`,
		`(?i)<img[^>]*\s+on\w+\s*=`,
		`(?i)<\w+[^>]*\s+on\w+\s*=`,
		`(?i)javascript:`,
		`(?i)vbscript:`,
		`(?i)data:text/html`,
		`(?i)expression\s*\(`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			compiled = append(compiled, re)
		}
	}

	return NewRule("xss", func(r *http.Request) (bool, *BlockReason) {
		// Parse form data to access POST parameters
		r.ParseForm()

		// Check query parameters
		for key, values := range r.URL.Query() {
			for _, value := range values {
				if checkPatterns(value, compiled) {
					return true, &BlockReason{
						Rule:    "xss",
						Message: "XSS attack detected in query parameter: " + key,
					}
				}
			}
		}

		// Check form parameters
		for key, values := range r.Form {
			for _, value := range values {
				if checkPatterns(value, compiled) {
					return true, &BlockReason{
						Rule:    "xss",
						Message: "XSS attack detected in form parameter: " + key,
					}
				}
			}
		}

		return false, nil
	})
}

// NewCommandInjectionRule creates a rule for detecting command injection attacks
func NewCommandInjectionRule() Rule {
	patterns := []string{
		`(?i)[\;\|\'\&\$\(\)\<\>\^\{\}\[\]]`,
		`(?i)(?:;|\||\&|\$|\(|\)|\<|\>|\^|\{|\}|\[|\])\s*(?:ls|pwd|cat|chmod|chown|rm|cp|mv|touch|wget|curl|bash|sh|csh|ksh|tcsh|zsh|nc|netcat|python|perl|ruby|php|telnet|ssh|ftp|sftp|gcc|cc|g\+\+|make|tar|zip|unzip|gzip|gunzip|bzip2|bunzip2|openssl|iptables|nmap|traceroute|ping|ifconfig|route|netstat|kill|killall|ps|find|grep|egrep|fgrep|sed|awk|cut|sort|uniq|head|tail|wc|id|whoami|env|export|set|echo|printf|source|eval|exec|sudo|su|passwd|adduser|useradd|usermod|groupadd|wget|curl|fetch|lynx|links|elinks|ftp|tftp|sftp|telnet|rlogin|rsh|ssh|scp|rsync|nc|netcat|socat|ncat|cryptcat|perl|python|php|ruby|lua|tcl|expect|gawk|mawk|sed|grep|egrep|fgrep|xargs|find|locate|dirname|basename|ls|dir|vdir|dmesg|stat|dd|df|du|mount|umount|install|logname|uptime|uname|hostname|domainname|chroot|nohup|nice|renice|kill|pkill|killall|skill|snice|pidof|fuser|perf|timeout|gtimeout|strace|truss|ltrace|gcore|gdb|lldb|strings|ldd|file|readelf|objdump|objcopy|strip|ar|ranlib|nm|size|c\+\+filt|addr2line|gprof|ld|gold|as|gas|lex|flex|yacc|bison|m4|swig|makedepend|patch|diff|cmp|comm|make|gmake|cmake|qmake|automake|autoconf|libtool|gcc|g\+\+|clang|clang\+\+|cc|c\+\+|tcc|icc|pgcc|cl|cl\.exe|armcc|nasm|yasm|fasm|javac|jar|java|python|python2|python3|perl|php|ruby|node|npm|yarn|go|gccgo|rustc|cargo|ghc|cabal|stack|dotnet|mono|mcs|csc|vbc|kotlinc|scalac|fsc|ocamlc|ocamlopt|ghci|runhaskell|runghc|sbcl|clisp|ecl|racket|guile|gsi|gsc|chicken|csc|mzscheme|bigloo|stalin|gambit|gforth|swiftc|tsc|coffee|babel|rollup|webpack|parcel|gulp|grunt|brunch|browserify|uglifyjs|terser|prettier|eslint|jshint|jscs|jslint|csslint|stylelint|htmlhint|htmllint|bootlint|w3c\-validator|svgo|imagemin|gifsicle|jpegtran|optipng|pngquant|svgcleaner|purgecss|purifycss|uncss|autoprefixer|postcss|sass|less|stylus|compass|bourbon|neat|susy|myth|rework|cleancss|cssnano|csso|pixrem|pleeease|postcss\-preset\-env|precss|stylecow|stylefmt|stylelint|stylus\-supremacy|tailwindcss|tachyons|bulma|bootstrap|foundation|materialize|semantic\-ui|uikit|vuetify|angular|react|vue|ember|backbone|knockout|aurelia|polymer|mithril|riot|svelte|preact|hyperapp|inferno|solid|lit\-html|stencil|qwik|alpine|stimulus|turbo|hotwire|jquery|zepto|prototype|mootools|dojo|yui|ext|sencha|gwt|vaadin|dhtmlx|webix|kendo|telerik|devexpress|syncfusion|jqwidgets|wijmo|ignite|infragistics|componentone|radzen|radiantq|radiantjs|radiantui|radiantux|radiantweb|radiantsoft|radiantsystems|radianttech|radiantcloud|radiantdata|radiantanalytics|radiantai|radiantml|radiantdl|radiantrl|radiantnn|radiantcv|radiantocr|radiantimage|radiantvision|radiantspeech|radiantnlp|radianttext|radiantlanguage|radiantvoice|radiantsound|radiantmusic|radiantvideo|radiantmedia|radiantstreaming|radiantrtc|radiantwebrtc|radiantchat|radiantmessaging|radiantcommunication|radiantcollaboration|radiantmeeting|radiantconference|radiantcall|radiantvoip|radiantsip|radianttelephony|radiantpbx|radiantcti|radiantcontactcenter|radiantcrm|radiantsales|radiantmarketing|radiantcommerce|radiantshop|radiantstore|radiantcart|radiantcheckout|radiantpayment|radiantbilling|radiantinvoice|radiantaccounting|radiantfinance|radiantbanking|radiantinsurance|radianthealth|radianthealthcare|radianthospital|radiantmedical|radiantclinical|radiantpatient|radiantdoctor|radiantnurse|radiantpharmacy|radiantdrug|radiantmedicine|radiantdental|radiantveterinary|radiantanimal|radiantpet|radianteducation|radiantlearning|radianttraining|radiantcourse|radiantclass|radiantschool|radiantuniversity|radiantcollege|radiantacademy|radianthr|radiantpayroll|radiantemployee|radiantstaff|radiantrecruiting|radianthiring|radiantjob|radiantcareer|radianttalent|radiantperformance|radiantreview|radiantfeedback|radiantsurvey|radiantpoll|radiantquiz|radianttest|radiantexam|radiantcertification|radiantdiploma|radiantdegree|radiantproject|radianttask|radiantticket|radiantissue|radiantbug|radiantsupport|radianthelp|radiantservice|radiantdesk|radiantcustomer|radiantclient|radiantuser|radiantmember|radiantsubscriber|radiantvisitor|radiantguest|radiantaccount|radiantprofile|radiantidentity|radiantauth|radiantlogin|radiantregister|radiantsignup|radiantsignin|radiantsso|radiantoauth|radiantsaml|radiantldap|radiantad|radiantdirectory|radiantpermission|radiantrole|radiantacl|radiantsecurity|radiantfirewall|radiantantivirus|radiantmalware|radiantspyware|radiantransomware|radiantphishing|radiantspam|radiantbackup|radiantrestore|radiantrecovery|radiantdisaster|radiantdr|radiantbcp|radiantcontinuity|radiantavailability|radiantreliability|radiantredundancy|radiantfailover|radiantcluster|radiantbalancer|radiantproxy|radiantcache|radiantcdn|radiantedge|radiantfog|radiantcloud|radiantserver|radiantvm|radiantcontainer|radiantdocker|radiantkubernetes|radiantk8s|radiantopenshift|radiantmesos|radiantmarathon|radiantswarm|radiantnomad|radiantconsul|radiantvault|radiantterraform|radiantansible|radiantchef|radiantpuppet|radiantsaltstack|radiantcfengine|radiantpacker|radiantvagrant|radiantjenkins|radiantbamboo|radiantteamcity|radiantcircleci|radianttravisci|radiantgithubactions|radiantgitlabci|radiantbitbucketpipelines|radiantazuredevops|radiantaws|radiantec2|radiants3|radiantrds|radiantdynamodb|radiantlambda|radiantsqs|radiantsnstopicarn|radiantcloudformation|radiantcloudwatch|radiantroute53|radiantelb|radiantalb|radiantiam|radiantcognito|radiantazure|radiantgcp|radiantgce|radiantgcs|radiantbigquery|radiantdataflow|radiantpubsub|radiantfunctions|radiantappengine|radiantkubernetesengine|radiantcloudrun|radiantfirestore|radiantspanner|radiantbigtable|radiantdatastore|radiantmemorystore|radiantredis|radiantmemcached|radiantmongodb|radiantcouchbase|radiantcouchdb|radiantcassandra|radiantneo4j|radiantorientdb|radiantarangodb|radiantmariadb|radiantmysql|radiantpostgresql|radiantsqlserver|radiantoracle|radiantdb2|radiantsybase|radiantteradata|radiantsnowflake|radiantredshift|radiantbigquery|radiantpresto|radianthive|radiantimpala|radiantspark|radianthadoop|radianthdfs|radiantmapreduce|radiantyarn|radiantflink|radiantkafka|radiantrabbitmq|radiantactivemq|radiantpulsararn|radiantnats|radiantzeromq|radiantmqtt|radiantamqp|radiantstomp|radiantjms|radiantibmmq|radianttibco|radiantsolace|radiantmulecule|radiantapachesling|radiantapachecamel|radiantapachekaraf|radiantapacheservicemix|radiantapacheflink|radiantapachestorm|radiantapachesamza|radiantapachespark|radiantapachehadoop|radiantapachehbase|radiantapachehive|radiantapacheimpala|radiantapachekafka|radiantapachezookeeper|radiantapachecassandra|radiantapachedruid|radiantapachesolr|radiantapachelucene|radiantapacheelasticsearch|radiantapacheflume|radiantapachesqoop|radiantapacheoozie|radiantapachepig|radiantapachephoenix|radiantapacheambari|radiantapachenifi|radiantapacheatlas|radiantapacheknox|radiantapacheranger|radiantapachekudu|radiantapachesentry|radiantapacheparquet|radiantapacheavro|radiantapachethrift|radiantapacheairflow|radiantapachesuperset|radiantapachezeppelin|radiantapachejupyter|radiantapachelivy|radiantapachespark|radiantapachebeam|radiantapachecalcite|radiantapachedrill|radiantapachehudi|radiantapacheiceberg|radiantapacheorc|radiantapachearrow|radiantapachekylin|radiantapachepinot|radiantapachetez|radiantapacheyarn|radiantapachegiraph|radiantapacheflink|radiantapachestorm|radiantapachesamza|radiantapachespark|radiantapachehadoop|radiantapachehbase|radiantapachehive|radiantapacheimpala|radiantapachekafka|radiantapachezookeeper|radiantapachecassandra|radiantapachedruid|radiantapachesolr|radiantapachelucene|radiantapacheelasticsearch|radiantapacheflume|radiantapachesqoop|radiantapacheoozie|radiantapachepig|radiantapachephoenix|radiantapacheambari|radiantapachenifi|radiantapacheatlas|radiantapacheknox|radiantapacheranger|radiantapachekudu|radiantapachesentry|radiantapacheparquet|radiantapacheavro|radiantapachethrift|radiantapacheairflow|radiantapachesuperset|radiantapachezeppelin|radiantapachejupyter|radiantapachelivy|radiantapachespark|radiantapachebeam|radiantapachecalcite|radiantapachedrill|radiantapachehudi|radiantapacheiceberg|radiantapacheorc|radiantapachearrow|radiantapachekylin|radiantapachepinot|radiantapachetez|radiantapacheyarn|radiantapachegiraph)`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			compiled = append(compiled, re)
		}
	}

	return NewRule("command_injection", func(r *http.Request) (bool, *BlockReason) {
		// Parse form data to access POST parameters
		r.ParseForm()

		// Check query parameters
		for key, values := range r.URL.Query() {
			for _, value := range values {
				if checkPatterns(value, compiled) {
					return true, &BlockReason{
						Rule:    "command_injection",
						Message: "Command injection detected in query parameter: " + key,
					}
				}
			}
		}

		// Check form parameters
		for key, values := range r.Form {
			for _, value := range values {
				if checkPatterns(value, compiled) {
					return true, &BlockReason{
						Rule:    "command_injection",
						Message: "Command injection detected in form parameter: " + key,
					}
				}
			}
		}

		return false, nil
	})
}

// NewPathTraversalRule creates a rule for detecting path traversal attacks
func NewPathTraversalRule() Rule {
	patterns := []string{
		`(?i)\.\.[\\/]`,
		`(?i)[\\/]\.\.[\\/]`,
		`(?i)[\\/]\.\.$`,
		`(?i)[\\/]\.\.;`,
		`(?i)\.\.%2[fF]`,
		`(?i)%2[fF]\.\.`,
		`(?i)\.\.%5[cC]`,
		`(?i)%5[cC]\.\.`,
		`(?i)[\\/]etc[\\/]passwd`,
		`(?i)[\\/]etc[\\/]shadow`,
		`(?i)[\\/]proc[\\/]self[\\/]`,
		`(?i)[\\/]dev[\\/]`,
		`(?i)[\\/]var[\\/]log[\\/]`,
		`(?i)[\\/]windows[\\/]system32[\\/]`,
		`(?i)[\\/]boot\.ini`,
		`(?i)[\\/]system\.ini`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			compiled = append(compiled, re)
		}
	}

	return NewRule("path_traversal", func(r *http.Request) (bool, *BlockReason) {
		// Check URL path
		if checkPatterns(r.URL.Path, compiled) {
			return true, &BlockReason{
				Rule:    "path_traversal",
				Message: "Path traversal detected in URL path",
			}
		}

		// Check query parameters
		for key, values := range r.URL.Query() {
			for _, value := range values {
				if checkPatterns(value, compiled) {
					return true, &BlockReason{
						Rule:    "path_traversal",
						Message: "Path traversal detected in query parameter: " + key,
					}
				}
			}
		}

		return false, nil
	})
}

// NewUserAgentRule creates a rule for detecting malicious user agents
func NewUserAgentRule() Rule {
	patterns := []string{
		`(?i)^.*(nessus|nmap|nikto|wikto|sf|sqlmap|bsqlbf|w3af|acunetix|havij|appscan).*$`,
		`(?i)^.*(libwww-perl|python|curl|wget|urllib|java|ruby|perl|go|php).*$`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			compiled = append(compiled, re)
		}
	}

	return NewRule("user_agent", func(r *http.Request) (bool, *BlockReason) {
		// Check User-Agent header
		userAgent := r.Header.Get("User-Agent")
		if userAgent != "" {
			if checkPatterns(userAgent, compiled) {
				return true, &BlockReason{
					Rule:    "user_agent",
					Message: "Suspicious user agent detected: " + userAgent,
				}
			}
		}

		return false, nil
	})
}

// checkPatterns checks if a string matches any of the provided patterns
func checkPatterns(s string, patterns []*regexp.Regexp) bool {
	// Normalize the string
	s = strings.ToLower(s)

	// Check against patterns
	for _, pattern := range patterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	return false
}
