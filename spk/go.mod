module autoban

go 1.26.0

// Mindestens 1.26.3. Go 1.26.0 bis 1.26.2 stürzt auf Synology-ARM mit Kernel 3.2
// (armadaxp, z.B. DS214+) in runtime.futexwakeup ab, bevor die Oberfläche antwortet.
toolchain go1.26.10

require modernc.org/sqlite v1.61.0

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.49.0 // indirect
	modernc.org/libc v1.79.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
