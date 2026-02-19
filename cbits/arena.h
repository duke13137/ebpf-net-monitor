/**
 * @file arena.h
 * @brief Fast region-based memory allocator with optional commit-on-demand.
 *
 * Provides bump-pointer allocation in a contiguous memory region with:
 * - Fast O(1) allocation with minimal overhead
 * - Optional zero-initialization and lazy commit (mmap)
 * - String utilities (astr) and dynamic arrays (slice)
 * - OOM handling via setjmp/longjmp or NULL return
 *
 * @see https://nullprogram.com/blog/2023/09/27/
 * @see https://nullprogram.com/blog/2023/10/05/
 */

#ifndef ARENA_H_
#define ARENA_H_

#include <memory.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AlignPow2(x, b)     (((x) + (b) - 1) & (~((b) - 1)))
#define AlignDownPow2(x, b) ((x) & (~((b) - 1)))
#define AlignPadPow2(x, b)  (-(x) & ((b) - 1))
#define IsPow2(x)           ((x) != 0 && ((x) & ((x) - 1)) == 0)
#define IsPow2OrZero(x)     ((((x) - 1) & (x)) == 0)

#define Countof(arr) ((isize)(sizeof(arr) / sizeof((arr)[0])))

#define Min(a, b) ((a) < (b) ? (a) : (b))
#define Max(a, b) ((a) > (b) ? (a) : (b))

#define KB(n) (((size_t)(n)) << 10)
#define MB(n) (((size_t)(n)) << 20)
#define GB(n) (((size_t)(n)) << 30)
#define TB(n) (((size_t)(n)) << 40)

#ifdef __GNUC__
#define ARENA_INLINE static inline __attribute__((always_inline))
#else
#define ARENA_INLINE static inline
#endif

#ifdef __GNUC__
#define ARENA_LIKELY(xp)   __builtin_expect((bool)(xp), true)
#define ARENA_UNLIKELY(xp) __builtin_expect((bool)(xp), false)
#else
#define ARENA_LIKELY(xp)   (xp)
#define ARENA_UNLIKELY(xp) (xp)
#endif

// Detect Address Sanitizer support
#ifdef __has_feature
#if __has_feature(address_sanitizer)
#define ASAN_ENABLED
#endif
#elif defined(__SANITIZE_ADDRESS__)
#define ASAN_ENABLED
#endif

#ifdef ASAN_ENABLED
#include <sanitizer/asan_interface.h>
#else
#define ASAN_POISON_MEMORY_REGION(addr, size)   ((void)(addr), (void)(size))
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) ((void)(addr), (void)(size))
#endif

// Platform-specific debug breakpoint
#ifdef __clang__
#define DEBUG_TRAP() __builtin_debugtrap();
#elif defined(__x86_64__)
#define DEBUG_TRAP() __asm__("int3; nop");
#elif defined(__GNUC__)
#define DEBUG_TRAP() __builtin_trap();
#else
#include <signal.h>
#define DEBUG_TRAP() raise(SIGTRAP);
#endif

#ifndef NDEBUG
#define ASSERT_LOG(c) fprintf(stderr, "Assertion failed: " c " at %s %s:%d\n", __func__, __FILE__, __LINE__)
#else
#define ASSERT_LOG(c) (void)0
#endif

/**
 * @brief Runtime assertion with debug trap on failure.
 * @param c Condition to check
 *
 * Unlike standard assert(), this is not compiled out in release builds.
 */
#define Assert(c)               \
  do {                          \
    if (ARENA_UNLIKELY(!(c))) { \
      ASSERT_LOG(#c);           \
      DEBUG_TRAP();             \
    }                           \
  } while (0)

#ifdef OOM_COMMIT
#include <sys/mman.h>
#include <unistd.h>

// Pages to commit at once when growing arena (default 1MB on 4KB pages)
#ifndef ARENA_COMMIT_PAGE_COUNT
#define ARENA_COMMIT_PAGE_COUNT 256
#endif

// @return System page size in bytes
ARENA_INLINE size_t arena_os_pagesize(void) {
  return (size_t)sysconf(_SC_PAGESIZE);
}

/**
 * @brief Reserve virtual address space without physical memory.
 * @param size Bytes to reserve
 * @return Pointer to reserved space, or NULL on failure
 */
ARENA_INLINE void* arena_os_reserve(size_t size) {
  void* ptr = mmap(0, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return (ptr == MAP_FAILED) ? NULL : ptr;
}

/**
 * @brief Commit physical memory to reserved pages.
 * @param ptr Start of reserved region
 * @param size Bytes to commit
 * @return true on success, false on failure
 */
ARENA_INLINE bool arena_os_commit(void* ptr, size_t size) {
  return mprotect(ptr, size, PROT_READ | PROT_WRITE) == 0;
}

/**
 * @brief Release physical memory while keeping virtual reservation.
 * @param ptr Start of committed region
 * @param size Bytes to decommit
 */
ARENA_INLINE void arena_os_decommit(void* ptr, size_t size) {
  if (size > 0) {
    madvise(ptr, size, MADV_DONTNEED);
  }
}
#endif

typedef unsigned char byte;
typedef ptrdiff_t isize;  // Signed size type for pointer arithmetic

/**
 * @brief Arena allocator context.
 *
 * Manages contiguous memory region with bump-pointer allocation.
 * All fields are internal - use provided functions/macros.
 */
typedef struct Arena Arena;
struct Arena {
  byte* beg;  // Start of arena memory
  byte* cur;  // Current allocation position
  byte* end;  // End of committed memory
#ifndef OOM_TRAP
  jmp_buf* oom;  // Longjmp target for OOM recovery
#endif
#ifdef OOM_COMMIT
  isize commit_size;   // Bytes to commit per growth
  isize reserve_size;  // Total reserved virtual space
#endif
};

// Allocation flags
enum {
  _NO_INIT = 1u << 0,   // Skip zero-initialization
  _OOM_NULL = 1u << 1,  // Return NULL on OOM instead of longjmp
};

typedef struct {
  unsigned mask;
} ArenaFlag;

static const ArenaFlag NO_INIT = {_NO_INIT};
static const ArenaFlag OOM_NULL = {_OOM_NULL};

#ifdef __GNUC__
/**
 * Auto-free pointer when leaving scope.
 *
 * Usage:
 *   __autofree void *ptr = malloc(size);
 *   // ptr freed automatically on scope exit
 */
#define __autofree __attribute__((__cleanup__(autofree_impl)))
static void autofree_impl(void* p) {
  free(*((void**)p));
}
#else
#warning "__autofree not supported on this compiler"
#define __autofree
#endif

/**
 * Allocate memory for type T from arena.
 *
 * Usage:
 *   int *x = New(arena, int);                  // Single zeroed int
 *   int *arr = New(arena, int, 10);            // Array of 10 zeroed ints
 *   int *arr2 = New(arena, int, 10, NO_INIT);  // Uninitialized
 *   struct point *p2 = New(arena, struct point, 1, p);  // Copy from p
 */
#define New(...)                  _NEWX(__VA_ARGS__, _NEW4, _NEW3, _NEW2)(__VA_ARGS__)
#define _NEWX(a, b, c, d, e, ...) e
#define _NEW2(a, t)               (t*)arena_alloc(a, sizeof(t), _Alignof(t), 1, (ArenaFlag){0})
#define _NEW3(a, t, n)            (t*)arena_alloc(a, sizeof(t), _Alignof(t), n, (ArenaFlag){0})
#define _NEW4(a, t, n, z)                                                                                  \
  ({                                                                                                       \
    __auto_type _z = (z);                                                                                  \
    (t*)_Generic(_z, t *: arena_alloc_init, ArenaFlag: arena_alloc)(a, sizeof(t), _Alignof(t), n,          \
                                                                    _Generic(_z, t *: _z, ArenaFlag: _z)); \
  })

#define CONCAT_(a, b) a##b
#define CONCAT(a, b)  CONCAT_(a, b)
#define ARENA_ORIG    CONCAT(_arena_, __LINE__)

/**
 * Create a temporary arena scope.
 *
 * Arena state is automatically restored when scope exits.
 * Pointers allocated in this scope must not escape it.
 *
 * Usage:
 *   {
 *     Scratch(arena);
 *     char *temp = New(arena, char, 100);
 *     // use temp...
 *   } // arena reset here
 */
#define Scratch(arena)                       \
  __arena_restore Arena* ARENA_ORIG = arena; \
  Arena arena[] = {*ARENA_ORIG}

#ifdef __GNUC__
#define __arena_restore __attribute__((__cleanup__(arena_restore)))
#else
#define __arena_restore
#endif

static void arena_restore(Arena** a) {
  ASAN_POISON_MEMORY_REGION(a[0]->cur, a[0]->end - a[0]->cur);
#ifdef OOM_COMMIT
  if (a[0]->commit_size) {
    isize orig_size = a[0]->end - a[0]->beg;
    arena_os_decommit(a[0]->end, a[0]->reserve_size - orig_size);
  }
#endif
}

/**
 * Define a dynamic array type.
 *
 * Usage:
 *   typedef slice(long) i64s;
 */
#define slice(T)     \
  struct slice_##T { \
    T* data;         \
    isize len;       \
    isize cap;       \
  }

/**
 * Append an element to a slice, growing if needed.
 *
 * Returns pointer to the new uninitialized element.
 *
 * Usage:
 *   i64s fibs = {0};
 *   *Push(&fibs, arena) = 2;
 *   *Push(&fibs, arena) = 3;
 */
#define Push(arena, slice)                                                             \
  ({                                                                                   \
    __auto_type _s = slice;                                                            \
    Assert(_s->len >= 0 && "slice.len must be non-negative");                          \
    Assert(_s->cap >= 0 && "slice.cap must be non-negative");                          \
    Assert((_s->data == NULL || _s->len > 0) && "Invalid slice");                      \
    if (_s->len >= _s->cap) {                                                          \
      arena_slice_grow(arena, _s, sizeof(*_s->data), _Alignof(__typeof__(*_s->data))); \
    }                                                                                  \
    _s->data + _s->len++;                                                              \
  })

/**
 * Clone a slice (or subslice) into arena memory.
 *
 * Usage:
 *   fibs = Clone(arena, fibs);           // Full copy
 *   fibs = Clone(arena, fibs, 0, 2);     // First 2 elements
 */
#define Clone(...)                   _CloneX(__VA_ARGS__, _Clone4, _Clone3, _Clone2)(__VA_ARGS__)
#define _CloneX(a, b, c, d, e, ...)  e
#define _Clone2(arena, slice)        _Clone3(arena, slice, 0)
#define _Clone3(arena, slice, start) _Clone4(arena, slice, start, slice.len - (start))
#define _Clone4(arena, slice, start, length)                                  \
  ({                                                                          \
    __auto_type _s = slice;                                                   \
    isize _start = start;                                                     \
    isize _len = length;                                                      \
    Assert((_start <= _s.len) && (_len >= 0) && _len <= _s.len);              \
    if (_len > 0) {                                                           \
      Assert((_s.data + _start + _len) <= (_s.data + _s.len));                \
      _s.data = New(arena, __typeof__(_s.data[0]), _len, (_s.data + _start)); \
    } else                                                                    \
      _s.data = NULL;                                                         \
    _s.cap = _s.len = _len;                                                   \
    _s;                                                                       \
  })

/**
 * Initialize an arena allocator.
 *
 * Usage:
 *   // Static allocation
 *   void *mem = malloc(MB(64));
 *   Arena arena = arena_init(mem, MB(64));
 *
 *   // Commit-on-demand (with OOM_COMMIT defined)
 *   Arena arena = arena_init(NULL, GB(4));
 */
ARENA_INLINE Arena arena_init(byte* buf, isize size) {
  Arena a = {0};
#ifdef OOM_COMMIT
  if (!buf) {
    isize page_size = arena_os_pagesize();
    size = AlignPow2(size, page_size);
    a.commit_size = page_size * ARENA_COMMIT_PAGE_COUNT;
    a.reserve_size = Max(a.commit_size, size);

    buf = arena_os_reserve(a.reserve_size);
    if (!buf) {
      perror("arena_init mmap");
      abort();
    }

    if (!arena_os_commit(buf, a.commit_size)) {
      perror("arena_init mprotect");
      abort();
    }

    size = a.commit_size;
  }
#endif
  a.beg = a.cur = buf;
  a.end = buf ? buf + size : 0;

  ASAN_POISON_MEMORY_REGION(buf, size);
  return a;
}

/**
 * @brief Release arena memory back to OS.
 * @param arena Arena to release
 *
 * Invalidates all allocations. Arena struct is zeroed.
 */
ARENA_INLINE void arena_release(Arena* arena) {
#ifdef OOM_COMMIT
  if (arena->commit_size) {
    munmap(arena->beg, arena->reserve_size);
  } else {
    free(arena->beg);
  }
#else
  free(arena->beg);
#endif
  memset(arena, 0, sizeof(Arena));
}

/**
 * @brief Reset arena to initial state.
 * @param arena Arena to reset
 *
 * Invalidates all allocations but keeps memory. Bump pointer moves to start.
 */
ARENA_INLINE void arena_reset(Arena* arena) {
  ASAN_POISON_MEMORY_REGION(arena->beg, arena->end - arena->beg);
  arena->cur = arena->beg;
}

/**
 * Set up OOM (Out Of Memory) handling.
 *
 * Returns non-zero if OOM occurred (from longjmp).
 *
 * Usage:
 *   jmp_buf jmpbuf;
 *   if (ArenaOOM(arena, jmpbuf)) {
 *     fputs("!!! OOM exit !!!\n", stderr);
 *     exit(1);
 *   }
 */
#ifndef OOM_TRAP
#define ArenaOOM(arena, jmpbuf) ((arena)->oom = &jmpbuf, setjmp(jmpbuf))
#else
#define ArenaOOM(arena, jmpbuf) ((void)jmpbuf, false)
#endif

/**
 * @brief Allocate memory with potential growth (slow path).
 * @param arena Arena allocator
 * @param size Size per element
 * @param align Alignment requirement
 * @param count Number of elements
 * @param flags Allocation flags
 * @return Pointer to allocated memory, or NULL/longjmp on OOM
 *
 * Called internally when fast path fails. Handles commit-on-demand growth.
 */
static void* arena_alloc_grow(Arena* arena, isize size, isize align, isize count, ArenaFlag flags) {
  byte* current = arena->cur;
  isize avail = arena->end - current;
  isize pad = AlignPadPow2((uintptr_t)current, align);

  isize total_size;
  if (ARENA_UNLIKELY(__builtin_mul_overflow(size, count, &total_size))) {
    goto HANDLE_OOM;
  }

  // Try to commit more memory if using commit-on-demand
  while (total_size > avail - pad) {
#ifdef OOM_COMMIT
    if (arena->commit_size) {
      // Can't commit beyond reservation
      if (arena->end - arena->beg > arena->reserve_size - arena->commit_size) {
        goto HANDLE_OOM;
      }

      if (!arena_os_commit(arena->end, arena->commit_size)) {
        perror("arena_alloc mprotect");
        goto HANDLE_OOM;
      }

      ASAN_POISON_MEMORY_REGION(arena->end, arena->commit_size);
      arena->end += arena->commit_size;
      avail = arena->end - current;

      continue;
    }
#endif
    goto HANDLE_OOM;
  }

  arena->cur += pad + total_size;
  current += pad;

  ASAN_UNPOISON_MEMORY_REGION(current, total_size);
  return flags.mask & _NO_INIT ? current : memset(current, 0, total_size);

HANDLE_OOM:
  if (flags.mask & _OOM_NULL)
    return NULL;
#ifdef OOM_TRAP
  Assert(!OOM_TRAP);
#else
  Assert(arena->oom);
  longjmp(*arena->oom, 1);
#endif
  return NULL;
}

/**
 * @brief Allocate aligned memory from arena.
 * @param arena Allocator context
 * @param size Size of each element
 * @param align Alignment requirement (must be power of 2)
 * @param count Number of elements
 * @param flags Allocation flags (NO_INIT, OOM_NULL)
 * @return Pointer to allocated memory
 *
 * Fast path is inlined. Memory is zeroed unless NO_INIT flag is set.
 */
ARENA_INLINE void* arena_alloc(Arena* arena, isize size, isize align, isize count, ArenaFlag flags) {
  Assert(size > 0 && "size must be positive");
  Assert(count >= 0 && "count must be non-negative");
  Assert(IsPow2(align) && "align must be power of 2");

  byte* current = arena->cur;
  isize avail = arena->end - current;
  isize pad = AlignPadPow2((uintptr_t)current, align);

  // Fast path: allocation fits in current committed region
  isize total_size;
  if (ARENA_LIKELY(!__builtin_mul_overflow(size, count, &total_size) && total_size <= avail - pad)) {
    arena->cur += pad + total_size;
    current += pad;
    ASAN_UNPOISON_MEMORY_REGION(current, total_size);
    return flags.mask & _NO_INIT ? current : memset(current, 0, total_size);
  }

  return arena_alloc_grow(arena, size, align, count, flags);
}

/**
 * @brief Allocate and initialize memory by copying from source.
 * @param arena Arena allocator
 * @param size Size per element
 * @param align Alignment requirement
 * @param count Number of elements
 * @param initptr Source data to copy from
 * @return Pointer to allocated and initialized memory
 */
ARENA_INLINE void* arena_alloc_init(Arena* arena, isize size, isize align, isize count, const void* initptr) {
  Assert(initptr != NULL && "initptr cannot be NULL");
  void* ptr = arena_alloc(arena, size, align, count, NO_INIT);
  memmove(ptr, initptr, size * count);
  return ptr;
}

/**
 * @brief Grow a slice's capacity.
 * @param arena Arena to allocate from
 * @param slice Pointer to slice struct
 * @param size Size per element
 * @param align Alignment requirement
 *
 * Attempts in-place growth when possible, otherwise reallocates.
 * Called automatically by Push() macro.
 */
ARENA_INLINE void arena_slice_grow(Arena* arena, void* slice, isize size, isize align) {
  struct {
    void* data;
    isize len;
    isize cap;
  } tmp;
  memcpy(&tmp, slice, sizeof(tmp));

  enum { GROW = 16 };

  if (tmp.cap == 0) {
    // Move slice from stack to arena
    tmp.cap = tmp.len + GROW;
    void* ptr = arena_alloc(arena, size, align, tmp.cap, NO_INIT);
    tmp.data = tmp.len == 0 ? ptr : memmove(ptr, tmp.data, size * tmp.len);
  } else if (ARENA_LIKELY((uintptr_t)tmp.data == (uintptr_t)arena->cur - size * tmp.cap)) {
    // Slice is at arena tip - grow in place
    tmp.cap += GROW;
    arena_alloc(arena, size, 1, GROW, NO_INIT);
  } else {
    // Slice is not at tip - must reallocate
    tmp.cap += Max(tmp.cap / 2, GROW);
    void* ptr = arena_alloc(arena, size, align, tmp.cap, NO_INIT);
    tmp.data = memmove(ptr, tmp.data, size * tmp.len);
  }

  memcpy(slice, &tmp, sizeof(tmp));
}

/**
 * @brief malloc-compatible allocation from arena.
 * @param size Bytes to allocate
 * @param arena Arena to allocate from
 * @return Pointer to allocated memory
 *
 * For use with generic data structures requiring malloc/free interface.
 */
ARENA_INLINE void* arena_malloc(size_t size, Arena* arena) {
  Assert(arena != NULL && "arena cannot be NULL");
  return arena_alloc(arena, size, _Alignof(max_align_t), 1, NO_INIT);
}

/**
 * @brief free-compatible deallocation.
 * @param ptr Pointer to free
 * @param size Size of allocation
 * @param arena Arena that allocated it
 *
 * Only works if ptr is the most recent allocation (at arena tip).
 */
ARENA_INLINE void arena_free(void* ptr, size_t size, Arena* arena) {
  Assert(arena != NULL && "arena cannot be NULL");
  if (!ptr)
    return;

  // Can only free most recent allocation
  if ((uintptr_t)ptr == (uintptr_t)arena->cur - size) {
    ASAN_POISON_MEMORY_REGION(ptr, size);
    arena->cur = ptr;
  }
}

/**
 * @brief Arena-allocated string with length.
 *
 * Not null-terminated by default. Use astr_to_cstr() for that.
 */
typedef struct astr {
  char* data;  // String data (may not be null-terminated)
  isize len;   // Length in bytes
} astr;

/**
 * Create astr from string literal.
 *
 * Usage:
 *   astr s = astr("hello");
 */
#define astr(s) ((astr){(s), sizeof(s) - 1})

/**
 * Format specifier for printf-style functions.
 *
 * Usage:
 *   astr s = astr("hello");
 *   printf("%.*s\n", S(s));
 */
#define S(s) (int)(s).len, (s).data

/**
 * @brief Clone string into arena memory.
 * @param arena Arena to allocate in
 * @param s String to clone
 * @return New astr with copied data
 *
 * No-op if string is empty or already at arena tip.
 */
ARENA_INLINE astr astr_clone(Arena* arena, astr s) {
  if (s.len == 0 || s.data + s.len == (char*)arena->cur)
    return s;

  astr s2 = s;
  s2.data = New(arena, char, s.len, NO_INIT);
  memmove(s2.data, s.data, s.len);
  return s2;
}

/**
 * @brief Concatenate two strings in arena.
 * @param arena Arena to allocate in
 * @param head First string
 * @param tail Second string
 * @return New astr with concatenated data
 *
 * Optimized to avoid copying when possible.
 */
ARENA_INLINE astr astr_concat(Arena* arena, astr head, astr tail) {
  if (head.len == 0) {
    return tail.len && tail.data + tail.len == (char*)arena->cur ? tail : astr_clone(arena, tail);
  }

  astr result = head;
  result = astr_clone(arena, head);
  result.len += astr_clone(arena, tail).len;
  return result;
}

/**
 * @brief Create astr from raw bytes.
 * @param arena Arena to allocate in
 * @param bytes Pointer to bytes
 * @param nbytes Number of bytes
 * @return Arena-allocated astr
 */
ARENA_INLINE astr astr_from_bytes(Arena* arena, const void* bytes, size_t nbytes) {
  return astr_clone(arena, (astr){(char*)bytes, nbytes});
}

/**
 * @brief Create astr from null-terminated C string.
 * @param arena Arena to allocate in
 * @param str Null-terminated string
 * @return Arena-allocated astr
 */
ARENA_INLINE astr astr_from_cstr(Arena* arena, const char* str) {
  return astr_from_bytes(arena, str, strlen(str));
}

/**
 * @brief Concatenate string with raw bytes.
 * @param arena Arena to allocate in
 * @param head String prefix
 * @param bytes Bytes to append
 * @param nbytes Number of bytes
 * @return Concatenated astr
 */
ARENA_INLINE astr astr_cat_bytes(Arena* arena, astr head, const void* bytes, size_t nbytes) {
  return astr_concat(arena, head, (astr){(char*)bytes, nbytes});
}

/**
 * @brief Concatenate string with C string.
 * @param arena Arena to allocate in
 * @param head String prefix
 * @param str C string to append
 * @return Concatenated astr
 */
ARENA_INLINE astr astr_cat_cstr(Arena* arena, astr head, const char* str) {
  return astr_cat_bytes(arena, head, str, strlen(str));
}

/**
 * Format string using printf-style format.
 *
 * Returns arena-allocated formatted string.
 *
 * Usage:
 *   astr s1 = astr_format(arena, "%.10f, $%d, %.*s", 3.1415926, 42, S(s));
 */
static astr astr_format(Arena* arena, const char* format, ...) {
  va_list args;
  va_start(args, format);
  int nbytes = vsnprintf(NULL, 0, format, args);
  va_end(args);
  Assert(nbytes >= 0);

  void* data = New(arena, char, nbytes + 1, NO_INIT);
  va_start(args, format);
  int nbytes2 = vsnprintf(data, nbytes + 1, format, args);
  va_end(args);
  Assert(nbytes2 == nbytes);

  arena->cur--;  // Drop null terminator so astr_concat still works

  return (astr){.data = data, .len = nbytes};
}

/**
 * Convert astr to null-terminated C string.
 *
 * Pass temporary arena by value - lifetime ends at current expression.
 *
 * Usage:
 *   printf("test: %s\n", astr_to_cstr(*arena, s));
 */
ARENA_INLINE const char* astr_to_cstr(Arena arena, astr s) {
  return astr_concat(&arena, s, astr("\0")).data;
}

/**
 * Duplicate astr as malloc'd C string.
 *
 * Caller must free the returned pointer.
 *
 * Usage:
 *   __autofree char *cs = astr_cstrdup(s);
 *   for (char *p = cs; *p; ++p) {
 *     // modify cs...
 *   }
 */
ARENA_INLINE char* astr_cstrdup(astr s) {
  return strndup(s.data, s.len);
}

// Internal helper for astr_split_by_char
ARENA_INLINE astr _astr_split_by_char(astr s, const char* charset, isize* pos) {
  isize i = *pos;

  // 256-bit lookup table for O(1) charset membership
  unsigned char table[256 / 8] = {0};
  for (const char* c = charset; *c; c++) {
    unsigned char ch = (unsigned char)*c;
    table[ch >> 3] |= (1u << (ch & 7));
  }

#define _ASTR_IN_SET(ch) (table[(unsigned char)(ch) >> 3] & (1u << ((unsigned char)(ch) & 7)))

  // Skip leading separators
  while (i < s.len && _ASTR_IN_SET(s.data[i]))
    i++;

  isize start = i;

  // Scan for next separator
  while (i < s.len && !_ASTR_IN_SET(s.data[i]))
    i++;

  astr token = {s.data + start, i - start};

  // Skip trailing separators
  while (i < s.len && _ASTR_IN_SET(s.data[i]))
    i++;

  *pos = i;
  return token;
#undef _ASTR_IN_SET
}

/**
 * Split string by any character in charset.
 *
 * Usage:
 *   int i = 0;
 *   for (astr_split_by_char(it, ",| $", s3)) {
 *     printf("'%.*s'\n", S(it.token));
 *     i++;
 *   }
 */
#define astr_split_by_char(it, charset, str) \
  struct {                                   \
    astr input, token;                       \
    const char* sep;                         \
    isize pos;                               \
  } it = {.input = str, .sep = charset};     \
  it.pos < it.input.len && (it.token = _astr_split_by_char(it.input, it.sep, &it.pos)).len > 0;

// Internal helper for astr_split
ARENA_INLINE astr _astr_split(astr s, astr sep, isize* pos) {
  astr slice = {s.data + *pos, s.len - *pos};
  const char* res = memmem(slice.data, slice.len, sep.data, sep.len);
  astr token = {slice.data, res && res != slice.data ? (res - slice.data) : slice.len};
  *pos += token.len + sep.len;
  return token;
}

/**
 * Split string by multi-character separator.
 *
 * Usage:
 *   for (astr_split(it, ",", s3)) {
 *     printf("|%.*s|\n", S(astr_trim(it.token)));
 *   }
 */
#define astr_split(it, strsep, str)                             \
  struct {                                                      \
    astr input, token, sep;                                     \
    isize pos;                                                  \
  } it = {.input = str, .sep = (astr){strsep, strlen(strsep)}}; \
  it.pos < it.input.len && (it.token = _astr_split(it.input, it.sep, &it.pos)).data;

/**
 * @brief Compare two strings for equality.
 * @param a First string
 * @param b Second string
 * @return true if equal, false otherwise
 */
ARENA_INLINE bool astr_equals(astr a, astr b) {
  if (a.len != b.len)
    return false;

  return !a.len || !memcmp(a.data, b.data, a.len);
}

/**
 * @brief Check if string starts with prefix.
 * @param s String to check
 * @param prefix Prefix to test
 * @return true if s starts with prefix
 */
ARENA_INLINE bool astr_starts_with(astr s, astr prefix) {
  isize n = prefix.len;
  return n <= s.len && !memcmp(s.data, prefix.data, n);
}

/**
 * @brief Check if string ends with suffix.
 * @param s String to check
 * @param suffix Suffix to test
 * @return true if s ends with suffix
 */
ARENA_INLINE bool astr_ends_with(astr s, astr suffix) {
  isize n = suffix.len;
  return n <= s.len && !memcmp(s.data + s.len - n, suffix.data, n);
}

/**
 * @brief Extract substring starting at pos with length len.
 * @param s Source string
 * @param pos Start position
 * @param len Length (clamped to string bounds)
 * @return Substring view (no allocation)
 */
ARENA_INLINE astr astr_substr(astr s, isize pos, isize len) {
  Assert(((size_t)pos <= (size_t)s.len) & (len >= 0));
  if (pos + len > s.len)
    len = s.len - pos;
  s.data += pos, s.len = len;
  return s;
}

/**
 * @brief Extract substring from position p1 to p2 (exclusive).
 * @param s Source string
 * @param p1 Start position (inclusive)
 * @param p2 End position (exclusive, clamped to string length)
 * @return Substring view (no allocation)
 */
ARENA_INLINE astr astr_slice(astr s, isize p1, isize p2) {
  Assert(((size_t)p1 <= (size_t)p2) & ((size_t)p1 <= (size_t)s.len));
  if (p2 > s.len)
    p2 = s.len;
  s.data += p1, s.len = p2 - p1;
  return s;
}

/**
 * @brief Remove leading whitespace (ASCII <= ' ').
 * @param s String to trim
 * @return View of string without leading whitespace
 */
ARENA_INLINE astr astr_trim_left(astr s) {
  while (s.len && *s.data <= ' ')
    ++s.data, --s.len;
  return s;
}

/**
 * @brief Remove trailing whitespace (ASCII <= ' ').
 * @param s String to trim
 * @return View of string without trailing whitespace
 */
ARENA_INLINE astr astr_trim_right(astr s) {
  while (s.len && s.data[s.len - 1] <= ' ')
    --s.len;
  return s;
}

/**
 * @brief Remove leading and trailing whitespace.
 * @param sv String to trim
 * @return View of trimmed string
 */
ARENA_INLINE astr astr_trim(astr sv) {
  return astr_trim_right(astr_trim_left(sv));
}

/**
 * @brief Compute FNV-1a hash of string.
 * @param key String to hash
 * @return 64-bit hash value
 *
 * Suitable for hash tables.
 */
ARENA_INLINE uint64_t astr_hash(astr key) {
  uint64_t hash = 0xcbf29ce484222325ull;
  for (isize i = 0; i < key.len; i++)
    hash = ((byte)key.data[i] ^ hash) * 0x100000001b3ull;

  return hash;
}

/**
 * Hash table integration example:
 *
 * @code
 * #include "cc.h"
 *
 * static inline uint64_t astr_wyhash(astr key) {
 *   return cc_wyhash(key.data, key.len);
 * }
 *
 * static inline void *vt_arena_malloc(size_t size, Arena **ctx) {
 *   return arena_malloc(size, *ctx);
 * }
 *
 * static inline void vt_arena_free(void *ptr, size_t size, Arena **ctx) {
 *   arena_free(ptr, size, *ctx);
 * }
 *
 * #define NAME      Map_astr_astr
 * #define KEY_TY    astr
 * #define VAL_TY    astr
 * #define CTX_TY    Arena *
 * #define CMPR_FN   astr_equals
 * #define HASH_FN   astr_wyhash
 * #define MALLOC_FN vt_arena_malloc
 * #define FREE_FN   vt_arena_free
 * #include "verstable.h"
 * @endcode
 */

#endif  // ARENA_H_
