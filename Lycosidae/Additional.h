#pragma once
#include "windows.h"
#include <stdlib.h>

#define THRESHOLD sizeof(long)

static std::size_t min_add_header(size_t a, size_t b)
{
  return (a > b) ? a : b;
}

static void big_copy(void *dest, const void *src, size_t iterations)
{
  long *d = (long *)dest;
  const long *s = (const long *)src;
  size_t eight = iterations / 8;
  size_t single = iterations % 8;
  while (eight > 0) {
    *d++ = *s++;
    *d++ = *s++;
    *d++ = *s++;
    *d++ = *s++;
    *d++ = *s++;
    *d++ = *s++;
    *d++ = *s++;
    *d++ = *s++;
    --eight;
  }
  while (single > 0) {
    *d++ = *s++;
    --single;
  }
}

static void small_copy(void *dest, const void *src, size_t iterations)
{
  char *d = (char *)dest;
  const char *s = (const char *)src;
  while (iterations > 0) {
    *d++ = *s++;
    --iterations;
  }
}

void *copy_memory(void *dest, const void *src, size_t size)
{
  //Small size is handled here
  if (size < THRESHOLD) {
    small_copy(dest, src, size);
    return dest;
  }
  //Start copying 8 bytes as soon as one of the pointers is aligned
  size_t bytes_to_align = min_add_header((size_t)dest % sizeof(long), (size_t)src % sizeof(long));
  void *position = dest;
  //Align
  if (bytes_to_align > 0) {
    small_copy(position, src, bytes_to_align);
    position = (char *)position + bytes_to_align;
    src = (char *)src + bytes_to_align;
    size -= bytes_to_align;
  }
  //How many iterations can be done
  size_t safe_big_iterations = size / sizeof(long);
  size_t remaining_bytes = size % sizeof(long);
  //Copy most bytes here
  big_copy(position, src, safe_big_iterations);
  position = (char *)position + safe_big_iterations * sizeof(long);
  src = (char *)src + safe_big_iterations * sizeof(long);
  //Process the remaining bytes
  small_copy(position, src, remaining_bytes);
  return dest;
}

char *__strncpy(char *s, const char *ct, size_t n) {
  char *saver = s;
  while (n--)
    *saver++ = *ct++;
  *saver = '\0';
  return s;
}
