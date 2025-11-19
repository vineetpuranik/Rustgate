use color_eyre::eyre::{eyre, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Password(String);

impl Password {
    pub fn parse(p: String) -> Result<Password> {
        if p.len() >= 8 {
            Ok(Self(p))
        } else {
            Err(eyre!(
                "{} is invalid password. Password needs to be at-least 8 characters long",
                p
            ))
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Password;

    #[test]
    fn test_empty_string_invalid_password() {
        let test_string = "".to_string();
        assert!(Password::parse(test_string).is_err());
    }

    #[test]
    fn test_less_than_8_characters_invalid_password() {
        let test_string = "e234".to_string();
        assert!(Password::parse(test_string).is_err());
    }

    #[test]
    fn test_valid_password() {
        let test_string = "ThisIsaValidPassword".to_string();
        assert!(Password::parse(test_string).is_ok());
    }
}
