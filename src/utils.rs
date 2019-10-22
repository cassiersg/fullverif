use itertools::Itertools;

fn abstract_set(it: impl Iterator<Item = usize>) -> impl Iterator<Item = (usize, usize)> {
    let mut vals = it.collect::<Vec<_>>();
    vals.sort_unstable();
    vals
        .into_iter()
        .dedup()
        .map(|val| (val, val))
        .coalesce(|(s1, e1), (s2, e2)| {
            if e1 + 1 == s2 {
                Ok((s1, e2))
            } else {
                Err(((s1, e1), (s2, e2)))
            }
        })
}
pub fn format_set(it: impl Iterator<Item = usize>) -> String {
    let mut res = String::new();
    for (start, end) in abstract_set(it) {
        if !res.is_empty() {
            res.push_str(", ");
        }
        if start == end {
            res.push_str(&format!("{}", start));
        } else if start + 1 == end {
            res.push_str(&format!("{}, {}", start, end));
        } else {
            res.push_str(&format!("{{{}, ..., {}}}", start, end));
        }
    }
    res
}
