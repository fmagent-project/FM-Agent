/*
 * Example 3: Callee requirement unmet — WP catches via propagation, SP misses.
 *
 * Bug: The caller (safe_divide_wrapper) calls divide() without ensuring
 * divisor != 0. The spec for safe_divide_wrapper says "divisor is an integer"
 * (no constraint on zero), but divide() requires divisor != 0.
 *
 * Why SP misses: In top-down mode, the caller is analyzed before the callee.
 * The caller's [INFO] block (callee contract) may not yet include the precise
 * pre-condition that divide() requires. SP derives a forward post-condition
 * for the caller that doesn't catch the missing zero-check.
 *
 * Why WP catches: In bottom-up mode, divide() is analyzed first. Its WP
 * ("divisor != 0") is cached. When analyzing safe_divide_wrapper, the callee's
 * WP is injected into the reasoning context. WP derivation for the caller
 * includes "divisor != 0" (required by callee). But the spec pre-condition
 * only says "divisor is an integer" — MISMATCH.
 */

// [SPEC]
// Pre-condition:
//   dividend and divisor are integers.
//
// Post-condition:
//   Returns dividend / divisor on success.
//   Returns -1 and sets error flag if divisor == 0.

int divide(int dividend, int divisor) {
    // [SPEC]
    // Pre-condition:
    //   divisor != 0.
    //
    // Post-condition:
    //   Returns dividend / divisor (exact integer division).
    if (divisor == 0) {
        return 0;  // This path violates the spec — divide requires divisor != 0
    }
    return dividend / divisor;
}

int safe_divide_wrapper(int dividend, int divisor) {
    // BUG: no check for divisor == 0 before calling divide()
    // The callee divide() requires divisor != 0, but this caller doesn't guarantee it.
    int result = divide(dividend, divisor);
    return result;
}
