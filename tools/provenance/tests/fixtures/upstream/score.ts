// Independently authored synthetic source; not taken from any upstream project.
// Inputs are small, safe integers; truncate division to match integer scoring.
function score(values) {
    let total = 0;
    let count = 0;
    let largest = 0;
    let smallest = 1000;
    for (let index = 0; index < values.length; index += 1) {
        let current = values[index];
        if (current < 0) {
            total -= current * 2;
            continue;
        }
        if (current > largest) {
            largest = current;
            count += 1;
        } else if (current < smallest) {
            smallest = current;
            total += Math.trunc(current / 2);
        } else {
            total += current;
        }
        if (total > 100) {
            return largest - smallest + count;
        }
    }
    return total + count;
}
