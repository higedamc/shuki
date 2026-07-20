//! CSPRNG password generation.

use rand::rngs::OsRng;
use rand::Rng;

use crate::domain::SecretField;
use crate::error::{Result, ShukiError};

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
/// Shell-friendly symbol set (no quotes/backslash/backtick to keep copy-paste safe).
const SYMBOLS: &[u8] = b"!#$%&*+-./:;<=>?@[]^_{|}~";

/// Character-class spec for generated passwords.
#[derive(Clone, Debug)]
pub struct PassSpec {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PassSpec {
    fn default() -> Self {
        Self {
            length: 24,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
        }
    }
}

/// Generate a password from OS randomness; guarantees at least one character
/// of every enabled class. Errors if no class is enabled or the length can't
/// fit one of each enabled class.
pub fn generate(spec: &PassSpec) -> Result<SecretField> {
    let mut classes: Vec<&[u8]> = Vec::new();
    if spec.upper {
        classes.push(UPPER);
    }
    if spec.lower {
        classes.push(LOWER);
    }
    if spec.digits {
        classes.push(DIGITS);
    }
    if spec.symbols {
        classes.push(SYMBOLS);
    }
    if classes.is_empty() {
        return Err(ShukiError::Other(
            "password spec enables no character class".into(),
        ));
    }
    if spec.length < classes.len() {
        return Err(ShukiError::Other(format!(
            "length {} too short for {} enabled character classes",
            spec.length,
            classes.len()
        )));
    }

    let union: Vec<u8> = classes.concat();
    let mut rng = OsRng;
    let mut chars: Vec<u8> = Vec::with_capacity(spec.length);
    // One guaranteed char per enabled class…
    for class in &classes {
        chars.push(class[rng.gen_range(0..class.len())]);
    }
    // …rest from the union…
    for _ in classes.len()..spec.length {
        chars.push(union[rng.gen_range(0..union.len())]);
    }
    // …then an unbiased Fisher–Yates shuffle so class positions don't leak.
    for i in (1..chars.len()).rev() {
        let j = rng.gen_range(0..=i);
        chars.swap(i, j);
    }

    let s = String::from_utf8(chars).expect("charsets are ASCII");
    Ok(SecretField::new(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_any(s: &str, set: &[u8]) -> bool {
        s.bytes().any(|b| set.contains(&b))
    }

    #[test]
    fn respects_length_and_class_coverage() {
        for _ in 0..200 {
            let p = generate(&PassSpec::default()).unwrap();
            let s = p.expose();
            assert_eq!(s.len(), 24);
            assert!(has_any(s, UPPER));
            assert!(has_any(s, LOWER));
            assert!(has_any(s, DIGITS));
            assert!(has_any(s, SYMBOLS));
        }
    }

    #[test]
    fn restricted_classes_only() {
        let spec = PassSpec {
            length: 32,
            upper: false,
            lower: true,
            digits: true,
            symbols: false,
        };
        for _ in 0..50 {
            let p = generate(&spec).unwrap();
            assert!(p
                .expose()
                .bytes()
                .all(|b| LOWER.contains(&b) || DIGITS.contains(&b)));
        }
    }

    #[test]
    fn error_cases() {
        assert!(generate(&PassSpec {
            length: 24,
            upper: false,
            lower: false,
            digits: false,
            symbols: false
        })
        .is_err());
        assert!(generate(&PassSpec {
            length: 3,
            ..PassSpec::default()
        })
        .is_err());
    }

    #[test]
    fn outputs_differ() {
        let a = generate(&PassSpec::default()).unwrap();
        let b = generate(&PassSpec::default()).unwrap();
        assert_ne!(a, b);
    }
}
