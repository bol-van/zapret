#pragma once

// GNU qsort is 2x faster than musl

typedef int (*__gnu_compar_d_fn_t) (const void *, const void *, void *);
void gnu_quicksort (void *const pbase, size_t total_elems, size_t size, __gnu_compar_d_fn_t cmp, void *arg);
