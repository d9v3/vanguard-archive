//! Cale : `tr!` et `trf!` de src/langue.rs, toujours en français. Le fuzzing cherche les plantages des lecteurs, pas
//! la langue de leurs messages.

#![allow(unused_macros)]

#[macro_export]
macro_rules! tr {
    ($fr:expr, $en:expr $(,)?) => {
        $fr
    };
}

#[macro_export]
macro_rules! trf {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        format!($fr $(, $arg)*)
    };
}
