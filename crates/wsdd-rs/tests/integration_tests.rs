#![expect(clippy::tests_outside_test_module, reason = "Integration tests")]
use pretty_assertions::assert_eq;

#[test]
fn assert_world_ok() {
    let cls1 = || true;
    let cls2 = || true;
    assert_eq!(cls1(), cls2());
}

#[test]
fn assert_world_ok2() {
    let cls1 = || false;
    let cls2 = || false;
    assert_eq!(cls1(), cls2());
}

#[cfg_attr(not(miri), test)]
#[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}

// TODO test that tests http server and client at the same time
