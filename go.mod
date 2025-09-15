module github.com/siemens/Large-Scale-Discovery

go 1.24.0

// godebug settings are not inherited from imported dependencies. GoScans defines godebug "x509negativeserial",
// which is required for parsing negative serial numbers in SSL certificates.
godebug x509negativeserial=1

require (
	github.com/Pallinder/go-randomdata v1.2.0
	github.com/davecgh/go-spew v1.1.1
	github.com/gin-contrib/gzip v1.2.3
	github.com/gin-gonic/gin v1.10.1
	github.com/glebarez/go-sqlite v1.22.0
	github.com/glebarez/sqlite v1.11.0
	github.com/go-co-op/gocron v1.37.0
	github.com/go-ldap/ldap/v3 v3.4.11
	github.com/go-resty/resty/v2 v2.16.5
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/jackc/pgconn v1.14.3
	github.com/jackc/pgx/v5 v5.7.6
	github.com/juju/fslock v0.0.0-20160525022230-4d5c94c67b4b
	github.com/lestrrat-go/httprc/v3 v3.0.1
	github.com/lestrrat-go/jwx/v3 v3.0.10
	github.com/lib/pq v1.10.9
	github.com/lithammer/shortuuid/v4 v4.2.0
	github.com/microcosm-cc/bluemonday v1.0.27
	github.com/noneymous/PgProxy v0.0.0-20250602125028-9827ef61c838
	github.com/orcaman/concurrent-map/v2 v2.0.1
	github.com/sanyokbig/pqinterval v1.1.2
	github.com/segmentio/go-pg-escape v2.0.0+incompatible
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/siemens/GoScans v0.0.0-20250915131217-94db0a9f1b2e
	github.com/siemens/ZapSmtp v0.0.0-20250705095924-f7d70e8eea01
	github.com/vburenin/nsync v0.0.0-20160822015540-9a75d1c80410
	go.uber.org/multierr v1.11.0
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.41.0
	golang.org/x/net v0.43.0
	golang.org/x/oauth2 v0.31.0
	golang.org/x/sync v0.17.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gorm.io/driver/postgres v1.6.0
	gorm.io/gorm v1.30.5
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/PuerkitoBio/goquery v1.10.3 // indirect
	github.com/Ullaakut/nmap/v3 v3.0.6 // indirect
	github.com/alexbrainman/sspi v0.0.0-20231016080023-1a75b4708caa // indirect
	github.com/andybalholm/cascadia v1.3.3 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869 // indirect
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.14.1 // indirect
	github.com/bytedance/sonic/loader v0.3.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/cockroachdb/apd v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.10 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.27.0 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.3 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/krp2/go-nfs-client v0.0.0-20200713104628-eb4e3e9b6e95 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20231016141302-07b5767bb0ed // indirect
	github.com/mattn/go-adodb v0.0.2-0.20200211113401-5e535a33399b // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/neo4j/neo4j-go-driver/v5 v5.28.3 // indirect
	github.com/noneymous/GoSslyze v0.0.0-20250611082550-d3ca74beb1c0 // indirect
	github.com/noneymous/go-redistributable-checker v0.0.0-20210325125326-f5f65eef4761 // indirect
	github.com/noneymous/go-sqlfmt v0.0.0-20250228090247-2ab82cfa7872 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20221212215047-62379fc7944b // indirect
	github.com/rasky/go-xdr v0.0.0-20170124162913-1a41d1a06c93 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.13 // indirect
	github.com/tklauser/numcpus v0.7.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.3.0 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	github.com/vmware/go-nfs-client v0.0.0-20190605212624-d43b92724c1b // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/ziutek/telnet v0.1.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/arch v0.21.0 // indirect
	golang.org/x/exp v0.0.0-20250819193227-8b4c13bb791b // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.66.8 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.38.2 // indirect
)
