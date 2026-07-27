/*
 * Example 2: Missing branch — WP catches, SP misses.
 *
 * Bug: The function handles "positive" and "negative" cases but forgets
 * the "zero" case. When input == 0, the function falls through without
 * setting result, returning an uninitialized value.
 *
 * Why SP misses: SP derives forward from the pre-condition. For the zero
 * case, SP's derived post-condition simply says "result is unspecified for
 * zero input" — which doesn't contradict the spec post-condition if the
 * spec doesn't explicitly mention zero.
 *
 * Why WP catches: WP starts from the post-condition "result correctly
 * classifies the input" and derives backward: "to guarantee correct
 * classification, all cases (positive, negative, zero) must be handled."
 * The missing zero case means the WP includes "input != 0", but the spec
 * pre-condition allows input == 0 — MISMATCH.
 */

// [SPEC]
// Pre-condition:
//   input is an integer (any value, including zero).
//
// Post-condition:
//   result is 1 if input > 0, -1 if input < 0, 0 if input == 0.

int classify(int input) {
    int result;
    if (input > 0) {
        result = 1;
    } else if (input < 0) {
        result = -1;
    }
    // BUG: missing "else { result = 0; }" — result is uninitialized when input == 0
    return result;
}
