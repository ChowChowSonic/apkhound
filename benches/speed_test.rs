use apkhound::commands::callgraph::handle_callgraph;
use apkhound::commands::compare::handle_compare;
use apkhound::commands::match_cmd::handle_match;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::path::PathBuf;

fn bench_run_match(c: &mut Criterion) {
    let old_apk = PathBuf::from("./co.kitetech.filemanager_old.apk");
    let new_apk = PathBuf::from("./co.kitetech.filemanager.apk");
    let threshold = 0.9;
    let change_threshold = 0.75;
    let wl_iterations = 3;
    let csv = false;
    let show_details = false;
    let filters: Vec<String> = vec![];

    let mut group = c.benchmark_group("run_match");
    group.sample_size(1000);
    group.bench_function("run_match", |b| {
        b.iter(|| {
            handle_match(
                black_box(old_apk.clone()),
                black_box(new_apk.clone()),
                black_box(threshold),
                black_box(change_threshold),
                black_box(wl_iterations),
                black_box(csv),
                black_box(show_details),
                black_box(filters.clone()),
            )
        });
    });
    group.finish();
}

fn bench_callgraph(c: &mut Criterion) {
    let apk_path = vec![PathBuf::from("./co.kitetech.filemanager_old.apk")];
    let filters: Vec<String> = vec![];

    let mut group = c.benchmark_group("callgraph");
    group.sample_size(1000);
    group.bench_function("callgraph", |b| {
        b.iter(|| {
            handle_callgraph(
                black_box(apk_path.clone()),
                black_box(filters.clone()),
            )
        });
    });
    group.finish();
}

fn bench_compare(c: &mut Criterion) {
    let old_apk = PathBuf::from("./co.kitetech.filemanager_old.apk");
    let new_apk = PathBuf::from("./co.kitetech.filemanager.apk");
    let filters: Vec<String> = vec![];

    let mut group = c.benchmark_group("compare");
    group.sample_size(1000);
    group.bench_function("compare", |b| {
        b.iter(|| {
            handle_compare(
                black_box(old_apk.clone()),
                black_box(new_apk.clone()),
                black_box(filters.clone()),
            )
        });
    });
    group.finish();
}

criterion_group!(benches, bench_run_match, bench_callgraph, bench_compare);
criterion_main!(benches);
