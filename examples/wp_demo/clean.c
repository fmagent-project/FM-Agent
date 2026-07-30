/*
 * Example 5: Clean function — both SP and WP should pass.
 *
 * This is a correctly implemented binary search. Both reasoning directions
 * should verify it successfully:
 * - SP: forward derivation confirms the post-condition (returns correct index).
 * - WP: backward derivation confirms spec_pre is sufficient to guarantee
 *   the post-condition (array sorted + value in range → found or -1).
 *
 * This example ensures WP doesn't produce false positives on correct code.
 */

// [SPEC]
// Pre-condition:
//   array is sorted in ascending order.
//   array_length > 0.
//   array has at least array_length elements allocated.
//
// Post-condition:
//   If target is found in array[0..array_length-1], returns its index.
//   If target is not found, returns -1.
//   No out-of-bounds access occurs.

int binary_search(int *array, int array_length, int target) {
    int low = 0;
    int high = array_length - 1;

    while (low <= high) {
        int mid = low + (high - low) / 2;
        if (array[mid] == target) {
            return mid;
        } else if (array[mid] < target) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    return -1;
}
