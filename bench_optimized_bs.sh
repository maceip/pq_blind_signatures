
echo "Scheme - Sig1 (ms), Sig2 (ms), Sig3 (ms), Ver (ms), Comm (KB), BS (KB)" > bench_log.txt
echo "--------------------------------------------------------" >> bench_log.txt

git submodule update --init --recursive
cd vole
# Getting optimized bench
chmod +x clean.sh
./clean.sh 
chmod +x build_opti_bs.sh
./build_opti_bs.sh > ../bench_log_misc.txt 2>&1
cd ..
cd vole-mayo-sys
cargo clean
cd ..
cd blind-signatures
cargo clean
cargo test test_and_bench_sign_loop_optimized_128sv1 --no-run >> ../bench_log_misc.txt 2>&1
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_128sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_128fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
echo "--------------------------------------------------------" >> ../bench_log.txt
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_192sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_192fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
echo "--------------------------------------------------------" >> ../bench_log.txt
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_256sv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
RUST_MIN_STACK=9999999999 cargo test test_and_bench_sign_loop_optimized_256fv1 -- --nocapture | sed -n '/MAYO/p' >> ../bench_log.txt
echo "--------------------------------------------------------" >> ../bench_log.txt
