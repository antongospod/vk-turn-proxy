// Package appcfg holds immutable startup configuration threaded from main()
// into subpackages. Replaces the old package-level globals in appstate
// (Debug, ManualCaptcha, AutoCaptchaSliderPOC, GlobalAppCancel) and dnsdial.Mode.
package appcfg

import "context"

type Config struct {
	Debug                bool
	ManualCaptcha        bool
	AutoCaptchaSliderPOC bool
	DNSMode              string
	UDP                  bool
	AllocsPerStream      int // K extra TURN allocations per stream under shared creds
	AppCancel            context.CancelFunc
}
