#[macro_use]
extern crate criterion;

use criterion::{Criterion, black_box};

fn add_two(a: i32) -> i32 {
    a + 2
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("add two", |b| b.iter(
        || add_two(black_box(2))
    ));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);