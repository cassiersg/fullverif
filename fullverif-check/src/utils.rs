use itertools::Itertools;

/// For generic functions over various int types.
pub trait Int:
    std::fmt::Display + std::cmp::Ord + Copy + std::cmp::Eq + std::ops::Add<Output = Self>
{
    fn one() -> Self;
}
impl Int for usize {
    fn one() -> Self {
        1
    }
}
impl Int for u32 {
    fn one() -> Self {
        1
    }
}

/// Represents the input set of integers as a series of closed intervals.
fn abstract_set<T: Int>(it: impl Iterator<Item = T>) -> impl Iterator<Item = (T, T)> {
    let mut vals = it.collect::<Vec<_>>();
    vals.sort_unstable();
    vals.into_iter()
        .dedup()
        .map(|val| (val, val))
        .coalesce(|(s1, e1), (s2, e2)| {
            if e1 + T::one() == s2 {
                Ok((s1, e2))
            } else {
                Err(((s1, e1), (s2, e2)))
            }
        })
}

/// Represents the input set of integers as a human-readable short string.
pub fn format_set<T: Int>(it: impl Iterator<Item = T>) -> String {
    let mut res = String::new();
    for (start, end) in abstract_set(it) {
        if !res.is_empty() {
            res.push_str(", ");
        }
        if start == end {
            res.push_str(&format!("{}", start));
        } else if start + T::one() == end {
            res.push_str(&format!("{}, {}", start, end));
        } else {
            res.push_str(&format!("{{{}, ..., {}}}", start, end));
        }
    }
    res
}
