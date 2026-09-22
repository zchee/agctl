//! Test doubles shared by the `commands::codex` unit tests.

use crate::commands::Prompt;
use crate::error::AppError;

/// A [`Prompt`] that answers every question the same way and keeps both sides
/// of the conversation, so a test can assert on what was asked and on the
/// words a person would have read.
pub(crate) struct Scripted {
    answer: bool,
    pub(crate) asked: Vec<String>,
    told: Vec<String>,
}

impl Scripted {
    pub(crate) fn saying(answer: bool) -> Self {
        Self { answer, asked: Vec::new(), told: Vec::new() }
    }

    /// Everything printed, joined — for a `contains` assertion.
    pub(crate) fn output(&self) -> String {
        self.told.join("\n")
    }
}

impl Prompt for Scripted {
    fn tell(&mut self, message: &str) {
        self.told.push(message.to_owned());
    }

    fn confirm(&mut self, question: &str) -> Result<bool, AppError> {
        self.asked.push(question.to_owned());
        Ok(self.answer)
    }
}
