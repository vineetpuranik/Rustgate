use color_eyre::eyre::{eyre, Result};
use validator::validate_email;

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Email(String);

impl Email {
    pub fn parse(s: String) -> Result<Email> {
        if validate_email(&s) {
            Ok(Self(s))
        } else {
            Err(eyre!("{} is not a valid email", s))
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Email;

    #[test]
    fn test_empty_string_invalid_email() {
        let test_string = "".to_string();
        assert!(Email::parse(test_string).is_err());
    }

    #[test]
    fn test_missing_at_invalid_email() {
        let test_string = "test.com".to_string();
        assert!(Email::parse(test_string).is_err());
    }

    #[test]
    fn test_correct_email() {
        let test_string = "mytest@test.com".to_string();
        assert!(Email::parse(test_string).is_ok());
    }
}
