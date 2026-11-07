//! Layering of flag sets: `crawl` flags win over the `--config` file, which wins over defaults.
//!
//! A flag is *unset* when it is `None`, `false` or an empty list; only unset flags take the
//! value of the lower layer. Every flag struct lists all of its fields in one
//! [`fill_fields!`] call, which destructures the lower layer without `..`: adding a flag
//! without deciding how it layers is a compile error.

/// A flag value that can tell whether the user supplied it.
pub(crate) trait Unset {
    /// `true` when the flag was not given.
    fn is_unset(&self) -> bool;
}

impl<T> Unset for Option<T> {
    fn is_unset(&self) -> bool {
        self.is_none()
    }
}

impl Unset for bool {
    fn is_unset(&self) -> bool {
        !*self
    }
}

impl<T> Unset for Vec<T> {
    fn is_unset(&self) -> bool {
        self.is_empty()
    }
}

/// Replace `dst` with `lower` when `dst` is unset.
pub(crate) fn fill<T: Unset>(dst: &mut T, lower: T) {
    if dst.is_unset() {
        *dst = lower;
    }
}

/// `fill_fields!(self, lower, Type { a, b, c })`: `fill` every listed field of `self` from
/// `lower`. The struct pattern has no `..`, so the list must name every field of `Type`.
macro_rules! fill_fields {
    ($dst:ident, $lower:ident, $ty:ident { $($field:ident),* $(,)? }) => {{
        let $ty { $($field),* } = $lower;
        $( $crate::merge::fill(&mut $dst.$field, $field); )*
    }};
}
pub(crate) use fill_fields;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    #[derive(Default, Debug, PartialEq)]
    struct Flags {
        name: Option<String>,
        on: bool,
        list: Vec<u8>,
    }

    impl Flags {
        fn fill_from(&mut self, lower: Self) {
            fill_fields!(self, lower, Flags { name, on, list });
        }
    }

    #[test]
    fn set_values_win_and_unset_values_fall_through() {
        let mut top = Flags {
            name: Some("top".into()),
            on: false,
            list: vec![],
        };
        top.fill_from(Flags {
            name: Some("lower".into()),
            on: true,
            list: vec![1, 2],
        });
        assert_eq!(
            top,
            Flags {
                name: Some("top".into()),
                on: true,
                list: vec![1, 2]
            }
        );
        let mut set_list = Flags {
            list: vec![9],
            ..Flags::default()
        };
        set_list.fill_from(Flags {
            list: vec![1],
            ..Flags::default()
        });
        assert_eq!(set_list.list, [9]);
    }
}
