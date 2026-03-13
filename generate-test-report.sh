#!/bin/bash

<<<<<<< HEAD
BASE_RUSTFLAGS="--cfg tokio_unstable"
CARGO_FEATURES=""
||||||| b3d58568
BASE_RUSTFLAGS=""
CARGO_FEATURES=""
=======
base_rustflags=""
cargo_features=""
>>>>>>> upstream/main

export RUSTFLAGS="${base_rustflags} --allow=warnings -Cinstrument-coverage"

# build-* ones are not parsed by grcov
export LLVM_PROFILE_FILE="profiling/build-%p-%m.profraw"
cargo build ${cargo_features} --all-targets --locked --workspace

# cleanup old values
find -name '*.profraw' | xargs rm

# different from the `cargo build` ones
LLVM_PROFILE_FILE="profiling/profile-%p-%m.profraw"
cargo nextest run --profile ci --no-fail-fast ${cargo_features} --all-targets --workspace

grcov $(find . -name "profile-*.profraw" -print) \
    --binary-path ./target/debug/ \
    --branch \
    --excl-br-line "^\s*((debug_)?assert(_eq|_ne)?!)" \
    --excl-br-start "mod tests \{" \
    --excl-line "(#\\[derive\\()|(^\s*.await[;,]?$)" \
    --excl-start "mod tests \{" \
    --ignore-not-existing \
    --keep-only "crates/**" \
    --llvm \
    --output-path ./reports/ \
    --output-type lcov,html,markdown \
    --source-dir .
