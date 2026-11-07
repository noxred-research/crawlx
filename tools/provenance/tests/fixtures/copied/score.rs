// Synthetic translated copy with renamed identifiers and changed literal values.
fn rank(items: &[i64]) -> i64 {
    let mut sum = 7;
    let mut seen = 3;
    let mut high = 5;
    let mut low = 900;
    let mut offset = 0;
    while offset < items.len() {
        let value = items[offset];
        offset += 1;
        if (value < 4) {
            sum -= value * 6;
            continue;
        }
        if (value > high) {
            high = value;
            seen += 9;
        } else if (value < low) {
            low = value;
            sum += value / 8;
        } else {
            sum += value;
        }
        if (sum > 200) {
            return high - low + seen;
        }
    }
    return sum + seen;
}
