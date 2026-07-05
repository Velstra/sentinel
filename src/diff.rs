//! A minimal line-level diff for `compare` (candidate vs saved config).
//!
//! No external crate: a classic LCS walk over lines, emitting `-`/`+`/space
//! markers like VyOS's `compare`. Configs are tiny, so the O(n·m) table is fine.

/// Diff `old` against `new`, returning `-removed` / `+added` / ` unchanged`
/// lines (VyOS `compare` style). Empty when the two are identical.
pub fn unified(old: &str, new: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());

    // lcs[i][j] = length of the longest common subsequence of a[i..] and b[j..].
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    // Walk the table, preferring to keep matches; on a mismatch, drop from
    // whichever side preserves the longer remaining subsequence.
    let mut out = String::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            out.push_str(&format!(" {}\n", a[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push_str(&format!("-{}\n", a[i]));
            i += 1;
        } else {
            out.push_str(&format!("+{}\n", b[j]));
            j += 1;
        }
    }
    for line in &a[i..] {
        out.push_str(&format!("-{line}\n"));
    }
    for line in &b[j..] {
        out.push_str(&format!("+{line}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_inputs_produce_no_diff() {
        let diff = unified("a\nb\nc\n", "a\nb\nc\n");
        assert!(!diff.contains('+'));
        assert!(!diff.contains('-'));
    }

    #[test]
    fn marks_added_and_removed_lines() {
        // `b` replaced with `B`, `d` added.
        let diff = unified("a\nb\nc\n", "a\nB\nc\nd\n");
        assert!(diff.contains("-b\n"), "got:\n{diff}");
        assert!(diff.contains("+B\n"), "got:\n{diff}");
        assert!(diff.contains("+d\n"), "got:\n{diff}");
        assert!(
            diff.contains(" a\n"),
            "unchanged lines keep context: {diff}"
        );
    }
}
