use criterion::{
    black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion, Throughput,
};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use xoodyak::XoodyakAead;

const KB: usize = 1024;

fn bench_for_size_inplace(b: &mut Bencher, rng: &mut dyn RngCore, size: usize) {
    let mut key = vec![0u8; 16];
    rng.fill_bytes(key.as_mut_slice());
    let mut nonce = vec![0u8; 16];
    rng.fill_bytes(nonce.as_mut_slice());
    let mut buffer = vec![0u8; size];
    rng.fill_bytes(buffer.as_mut_slice());

    let mut cipher = XoodyakAead::new(key.as_slice());

    b.iter(|| black_box(cipher.encrypt(nonce.as_mut_slice(), &[], buffer.as_mut_slice())));
}

fn criterion_benchmark_inplace(c: &mut Criterion) {
    let mut rng = StdRng::from_entropy();
    let mut group = c.benchmark_group("xoodyak");
    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            bench_for_size_inplace(b, &mut rng, size)
        });
    }
    group.finish();
}

criterion_group!(bench_128, criterion_benchmark_inplace);
criterion_main!(bench_128);
