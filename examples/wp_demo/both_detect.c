/*
 * Example 4: Computation error — both SP and WP detect.
 *
 * Bug: The function should return a * b but returns a + b.
 * Both SP and WP should catch this because:
 * - SP: forward derivation shows post-condition is "result == a + b",
 *   which contradicts spec post-condition "result == a * b".
 * - WP: backward derivation from "result == a * b" requires "the function
 *   computes multiplication", but the code does addition — the WP
 *   (paraphrased: "code must multiply a and b") is not satisfied by the code.
 *
 * This example serves as a baseline: bugs that are pure computation errors
 * are detectable by both methods.
 */

// [SPEC]
// Pre-condition:
//   a and b are integers.
//
// Post-condition:
//   result == a * b (integer multiplication of inputs).

int multiply(int a, int b) {
    // BUG: returns a + b instead of a * b
    return a + b;
}
