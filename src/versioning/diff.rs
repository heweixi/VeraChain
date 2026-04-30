use serde::Serialize;

/// 差异类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DiffType {
    Added,
    Removed,
    Modified,
    Unchanged,
}

/// 差异行
#[derive(Debug, Clone, Serialize)]
pub struct DiffLine {
    pub line_number: usize,
    pub diff_type: DiffType,
    pub content: String,
}

/// 差异结果
#[derive(Debug, Clone, Serialize)]
pub struct DiffResult {
    pub old_version: String,
    pub new_version: String,
    pub lines: Vec<DiffLine>,
    pub additions: usize,
    pub deletions: usize,
    pub modifications: usize,
}

/// 差异计算器
pub struct DiffCalculator;

impl DiffCalculator {
    /// 计算两个文本的差异
    pub fn compute_diff(old_content: &str, new_content: &str) -> DiffResult {
        let old_lines: Vec<&str> = old_content.lines().collect();
        let new_lines: Vec<&str> = new_content.lines().collect();

        let mut diff_lines = Vec::new();
        let mut additions = 0;
        let mut deletions = 0;
        let mut modifications = 0;

        // 简单的逐行比较（可以用更复杂的 LCS 算法优化）
        let max_len = old_lines.len().max(new_lines.len());

        for i in 0..max_len {
            let old_line = old_lines.get(i);
            let new_line = new_lines.get(i);

            match (old_line, new_line) {
                (Some(old), Some(new)) if old == new => {
                    diff_lines.push(DiffLine {
                        line_number: i + 1,
                        diff_type: DiffType::Unchanged,
                        content: new.to_string(),
                    });
                }
                (Some(old), Some(new)) => {
                    diff_lines.push(DiffLine {
                        line_number: i + 1,
                        diff_type: DiffType::Modified,
                        content: format!("-{}\n+{}", old, new),
                    });
                    modifications += 1;
                }
                (Some(old), None) => {
                    diff_lines.push(DiffLine {
                        line_number: i + 1,
                        diff_type: DiffType::Removed,
                        content: old.to_string(),
                    });
                    deletions += 1;
                }
                (None, Some(new)) => {
                    diff_lines.push(DiffLine {
                        line_number: i + 1,
                        diff_type: DiffType::Added,
                        content: new.to_string(),
                    });
                    additions += 1;
                }
                (None, None) => {}
            }
        }

        DiffResult {
            old_version: String::new(),
            new_version: String::new(),
            lines: diff_lines,
            additions,
            deletions,
            modifications,
        }
    }

    /// 计算两个版本的差异
    pub fn compute_version_diff(
        old_version_id: &str,
        new_version_id: &str,
        old_content: &str,
        new_content: &str,
    ) -> DiffResult {
        let mut result = Self::compute_diff(old_content, new_content);
        result.old_version = old_version_id.to_string();
        result.new_version = new_version_id.to_string();
        result
    }

    /// 生成统一差异格式
    pub fn generate_unified_diff(
        old_path: &str,
        new_path: &str,
        old_content: &str,
        new_content: &str,
    ) -> String {
        let diff = Self::compute_diff(old_content, new_content);
        let mut output = String::new();

        output.push_str(&format!("--- {}\n", old_path));
        output.push_str(&format!("+++ {}\n", new_path));

        for line in &diff.lines {
            match line.diff_type {
                DiffType::Added => output.push_str(&format!("+{}\n", line.content)),
                DiffType::Removed => output.push_str(&format!("-{}\n", line.content)),
                DiffType::Modified => output.push_str(&format!("{}\n", line.content)),
                DiffType::Unchanged => output.push_str(&format!(" {}\n", line.content)),
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_diff() {
        let old = "line1\nline2\nline3";
        let new = "line1\nmodified\nline3\nline4";

        let diff = DiffCalculator::compute_diff(old, new);
        assert_eq!(diff.modifications, 1);
        assert_eq!(diff.additions, 1);
    }

    #[test]
    fn test_unified_diff() {
        let old = "hello\nworld";
        let new = "hello\nrust";

        let unified = DiffCalculator::generate_unified_diff("old.txt", "new.txt", old, new);
        assert!(unified.contains("--- old.txt"));
        assert!(unified.contains("+++ new.txt"));
    }
}
