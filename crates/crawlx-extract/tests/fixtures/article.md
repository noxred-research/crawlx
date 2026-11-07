# Parsing *Pipelines*

A pipeline turns **bytes** into `tokens`, then trees. See the [guide](https://example.com/docs/guide) or the [spec](https://example.org/spec?a=1&b=2).

## Steps

- Decode
  - UTF-8
  - Latin-1
- Tokenize
- Build tree

3. Third
4. Fourth
   1. Nested one

## Example

```rust
fn main() {
    println!("hello");

    let x = 1 < 2;
}
```

> Premature optimization is the root of all evil.
>
> — Knuth

Throughput

| Stage | MB/s |
| --- | ---: |
| decode | 900 |
| pipe \| char |  |

---

**Token**
: A lexical unit.

**Tree**
: A DOM.

Line one  
line two and a snake_case_name with 2 \* 3 and a_b.

![Pipeline diagram](https://example.com/img/diagram.png)

dead link and ~~removed~~.
