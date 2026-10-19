//! Words from the BIP-39 English list: invitation words and the 4 safety words.

use zeroize::Zeroizing;

/// BIP-39 English list, SHA-256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda:
/// 2048 words, 11 bits each.
const WORDLIST: &str = include_str!("wordlist.txt");
/// Invitation words of a live or physical-token invitation: 66 bits.
pub const WORD_COUNT: usize = 6;
/// Words A draws for an appointment: 55 bits.
pub const APPOINTMENT_WORDS_A: usize = 5;
/// Words B draws for an appointment: 44 bits.
pub const APPOINTMENT_WORDS_B: usize = 4;

/// `count` words drawn uniformly from the list, 11 bits each. Words people pick themselves are
/// far easier to guess, so `normalize` accepts only list words.
pub fn words(count: usize) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new(vec![0u8; 2 * count]);
    getrandom::fill(&mut bytes).expect("OS random generator unavailable");
    to_words(&bytes)
}

/// One list word per 2 bytes, from their low 11 bits.
pub(crate) fn to_words(bytes: &[u8]) -> Zeroizing<String> {
    // Reserved up front (list words are at most 8 letters) so no unzeroized copy is left behind.
    let mut out = Zeroizing::new(String::with_capacity(9 * bytes.len() / 2));
    for pair in bytes.as_chunks::<2>().0 {
        let index = usize::from(u16::from_be_bytes(*pair) & 0x7ff);
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(
            WORDLIST
                .lines()
                .nth(index)
                .expect("the list has 2048 words"),
        );
    }
    out
}

/// Whether `typed` spells the words of `bytes`, ignoring case and spacing.
pub(crate) fn spells(typed: &str, bytes: &[u8]) -> bool {
    let typed = Zeroizing::new(typed.to_lowercase());
    typed.split_whitespace().eq(to_words(bytes).split(' '))
}

/// Lowercases and collapses whitespace. Exactly `count` list words or `None`.
pub(crate) fn normalize(words: &str, count: usize) -> Option<Zeroizing<String>> {
    let lower = Zeroizing::new(words.to_lowercase());
    let parts: Vec<&str> = lower.split_whitespace().collect();
    let known = |p: &&str| WORDLIST.lines().any(|w| w == *p);
    (parts.len() == count && parts.iter().all(known)).then(|| Zeroizing::new(parts.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS: &str = "alpha cable echo forest orbit velvet";

    #[test]
    fn generated_words_are_valid_and_random() {
        assert_eq!(WORDLIST.lines().count(), 2048);
        let (w1, w2) = (words(WORD_COUNT), words(WORD_COUNT));
        assert_ne!(w1, w2);
        for w in [&w1, &w2] {
            assert_eq!(normalize(w, WORD_COUNT), Some(w.clone()));
        }
        for count in [APPOINTMENT_WORDS_A, APPOINTMENT_WORDS_B] {
            assert_eq!(words(count).split(' ').count(), count);
        }
    }

    #[test]
    fn normalize_words() {
        assert_eq!(
            normalize(" Alpha  cable\nECHO forest Orbit   velvet ", 6)
                .as_deref()
                .map(String::as_str),
            Some(WORDS)
        );
        assert!(normalize("alpha cable echo forest orbit", 6).is_none());
        assert!(normalize("alpha cable echo forest orbit", 5).is_some());
        assert!(normalize("alpha cable echo forest orbit velvet zoo", 6).is_none());
        assert!(normalize("alpha cable echo forest orbit bravo", 6).is_none());
        assert!(normalize("my dog is called max now", 6).is_none());
    }

    #[test]
    fn words_spell_their_bytes() {
        // Index 0 is "abandon", 2047 is "zoo"; the top 5 bits of each pair are ignored.
        assert_eq!(
            &*to_words(&[0, 0, 0xff, 0xff, 0xf8, 0x00]),
            "abandon zoo abandon"
        );
        assert!(spells("  ABANDON zoo\tabandon ", &[0, 0, 0x07, 0xff, 0, 0]));
        assert!(!spells("abandon zoo", &[0, 0, 0x07, 0xff, 0, 0]));
    }
}
