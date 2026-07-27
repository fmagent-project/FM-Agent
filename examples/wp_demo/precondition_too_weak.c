/*
 * Example 1: Pre-condition too weak — WP catches, SP misses.
 *
 * Bug: The spec says "index is non-negative" but the code accesses
 * array[index] without checking index < array_length. This is an
 * out-of-bounds access when index >= array_length.
 *
 * Why SP misses: SP starts from the (weak) pre-condition and derives
 * post-conditions forward. Since the pre-condition allows any non-negative
 * index, SP's forward derivation doesn't flag the missing upper-bound check —
 * it simply produces a post-condition that's also weak.
 *
 * Why WP catches: WP starts from the post-condition (array[index] is read
 * successfully) and derives backward: "to guarantee this, index must be
 * < array_length". Then it checks spec_pre ⊨ wp: the spec only guarantees
 * "index >= 0", which does NOT entail "index < array_length" — MISMATCH.
 */

// [SPEC]
// Pre-condition:
//   index is a non-negative integer.
//   array is a valid int array.
//
// Post-condition:
//   Returns the element at array[index].
//   No out-of-bounds memory access occurs.

int get_element(int *array, int array_length, int index) {
    if (index < 0) {
        return -1;
    }
    // BUG: no check for index >= array_length
    return array[index];
}
