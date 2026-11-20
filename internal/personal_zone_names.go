package app

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/pfisterer/dynamic-zones/internal/helper"
)

// Personal zone names and their collisions.
//
// A rule with a placeholder (%u, %l) derives a zone name from the person's address, and making an address DNS-compliant is not injective: max.mueller@dhbw.de and max_mueller@dhbw.de both become max-mueller under %l (and max-mueller-at-dhbw-de under %u), and %l drops the domain altogether. Before, the second person was offered the first one's zone and got 409 "Die Zone gibt es bereits" when creating it.
//
// Now the second person is offered a variant of the name with a short hash of their full address appended to the placeholder's text (max-mueller-3f9a1c.users.example.org). The hash depends only on the address, so the variant is stable: the same person always gets the same variant, and nobody else does. Existing zones are never renamed; the variant is only what is OFFERED (and therefore what the person may create and what keeps their zone covered).
//
// Which name a person is offered:
//   - the variant, when they created a zone under it — it stays theirs even after the zone that forced it is deleted, or their zone would turn orphaned;
//   - the variant, when the plain name is a zone somebody else created;
//   - the plain name otherwise (free, or created by the person themselves).

// personalNameHashLength is the number of hex digits of the hash in a variant: 24 bits, so two addresses that already collide on the plain name practically never collide again.
const personalNameHashLength = 6

// personalNameSuffix is the part a variant appends to the placeholder's text for this identity: "-" and the first hex digits of the SHA-256 of the lower-cased address.
func personalNameSuffix(identity string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(identity))))
	return "-" + hex.EncodeToString(sum[:])[:personalNameHashLength]
}

// withSuffix appends suffix to a placeholder's text, shortening the text first so that the result still fits into one DNS label.
func withSuffix(text, suffix string) string {
	if max := helper.DnsMaxLabelLength - len(suffix); len(text) > max {
		text = strings.TrimRight(text[:max], "-")
	}
	return text + suffix
}

// expandZonePatternVariant is the collision-free variant of expandZonePattern: every placeholder expands to its usual text with personalNameSuffix(identity) appended. ok is false where expandZonePattern's is, and for a pattern without placeholder (it names one fixed zone, there is no variant of it).
func expandZonePatternVariant(pattern, identity string) (zone string, ok bool) {
	if !hasPlaceholder(pattern) {
		return "", false
	}
	user := helper.DnsMakeCompliant(identity)
	local := helper.DnsMakeCompliantLocalPart(identity)
	if (strings.Contains(pattern, placeholderUser) && user == "") || (strings.Contains(pattern, placeholderLocalPart) && local == "") {
		return "", false
	}
	suffix := personalNameSuffix(identity)
	return normalizeZone(strings.NewReplacer(placeholderUser, withSuffix(user, suffix), placeholderLocalPart, withSuffix(local, suffix)).Replace(pattern)), true
}

// personalZoneName is the zone a rule pattern offers the person, with collisions settled as described above. For a pattern without placeholder it is expandZonePattern.
func (app *AppData) personalZoneName(pattern, identity string) (string, bool, error) {
	plain, ok := expandZonePattern(pattern, identity)
	if !ok {
		return "", false, nil
	}
	variant, ok := expandZonePatternVariant(pattern, identity)
	if !ok || variant == plain || app.Storage == nil {
		return plain, true, nil
	}
	if mine, err := app.Storage.IsZoneCreator(identity, variant); err != nil {
		return "", false, err
	} else if mine {
		return variant, true, nil
	}
	creator, err := app.Storage.ZoneCreator(plain)
	if err != nil {
		return "", false, err
	}
	if creator != "" && !strings.EqualFold(creator, identity) {
		return variant, true, nil
	}
	return plain, true, nil
}
