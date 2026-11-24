//! Text a request chose, made safe to log or to answer with. A credential's holder writes
//! the checks of the blocks it appends, a runner names its frame's verb and lanes, and
//! a client its path; such text reaches the PEP's log through its refusals. Every
//! character outside printable ASCII is escaped, so a newline cannot forge a log line and
//! no control sequence reaches a terminal, and the text is cut short, so one request
//! cannot write a 32 KiB line.

/// The most characters printable text keeps, its cut marker included.
pub const MAX_CHARS: usize = 512;

/// Ends text that was cut short.
const CUT: &str = "...";

/// `text` with every character outside printable ASCII escaped (`\n`, `\r`, `\t`, else
/// `\u{...}`) and cut to [`MAX_CHARS`]. Printable ASCII up to that length is unchanged, so
/// a rule such as `check if lane("gpu")` reads as written, and so is text this already
/// made printable. A backslash stays as it is: written text that looks like an escape is
/// still only text on one line.
pub fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_CHARS + 1));
    for c in text.chars() {
        match c {
            ' '..='~' => out.push(c),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.extend(other.escape_unicode()),
        }
        if out.len() > MAX_CHARS {
            out.truncate(MAX_CHARS - CUT.len());
            out.push_str(CUT);
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_ascii_reads_as_written() {
        for text in [
            r#"check if lane("gpu")"#,
            r#"check if operation("cas_get"), address($a), allowed_get($a)"#,
            r#"right "lease" not granted"#,
            r"a backslash \n stays",
        ] {
            assert_eq!(printable(text), text);
        }
    }

    #[test]
    fn no_control_character_or_line_break_gets_through() {
        let hostile = "ok\nWARN forged line\r\t\u{1b}[2J\u{0}\u{7f}\u{85}\u{2028}\u{202e}é";
        let shown = printable(hostile);
        assert_eq!(
            shown,
            r"ok\nWARN forged line\r\t\u{1b}[2J\u{0}\u{7f}\u{85}\u{2028}\u{202e}\u{e9}"
        );
        assert!(shown.chars().all(|c| (' '..='~').contains(&c)), "{shown}");
    }

    #[test]
    fn long_text_is_cut_to_the_bound() {
        let shown = printable(&"x".repeat(32 * 1024));
        assert_eq!(shown.len(), MAX_CHARS);
        assert!(shown.ends_with(CUT));
        let escapes = printable(&"\u{1b}".repeat(1000));
        assert_eq!(escapes.len(), MAX_CHARS);
        assert_eq!(printable(&"y".repeat(MAX_CHARS)), "y".repeat(MAX_CHARS));
    }

    #[test]
    fn printable_text_stays_as_it_is() {
        for text in ["plain", "a\nb\u{1b}c", &"z\u{202e}".repeat(400)] {
            let once = printable(text);
            assert_eq!(printable(&once), once, "{text:?}");
        }
    }
}
