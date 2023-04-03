use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes128Gcm;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

const KB: usize = 1024;

fn criterion_benchmark_inplace(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes-gcm");
    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].iter() {
        let buf = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            let cipher = Aes128Gcm::new(&Default::default());
            b.iter(|| cipher.encrypt(&Default::default(), &*buf))
        });
    }
    group.finish();
}

criterion_group!(bench_128, criterion_benchmark_inplace);
criterion_main!(bench_128);
