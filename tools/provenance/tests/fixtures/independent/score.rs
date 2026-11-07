// Same scoring behavior as score.ts, independently expressed as a state fold.
use std::ops::ControlFlow;

fn score(values: &[i64]) -> i64 {
    let outcome = values.iter().try_fold(
        (0, 0, 0, 1000),
        |(sum, count, high, low), &value| {
            if value.is_negative() {
                return ControlFlow::Continue((sum - 2 * value, count, high, low));
            }
            let higher = value > high;
            let lower = !higher && value < low;
            let next = (
                sum + if higher { 0 } else if lower { value / 2 } else { value },
                count + i64::from(higher),
                if higher { value } else { high },
                if lower { value } else { low },
            );
            match next.0 > 100 {
                true => ControlFlow::Break(next.2 - next.3 + next.1),
                false => ControlFlow::Continue(next),
            }
        },
    );
    match outcome {
        ControlFlow::Break(result) => result,
        ControlFlow::Continue((sum, count, _, _)) => sum + count,
    }
}
