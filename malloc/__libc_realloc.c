void *
__libc_realloc (void *oldmem, size_t bytes)
{
  mstate ar_ptr;
  INTERNAL_SIZE_T nb;         /* padded request size */

  void *newp;             /* chunk to return */

  void *(*hook) (void *, size_t, const void *) =
    atomic_forced_read (__realloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(oldmem, bytes, RETURN_ADDRESS (0));

#if REALLOC_ZERO_BYTES_FREES
  if (bytes == 0 && oldmem != NULL)
    {
      __libc_free (oldmem); return 0;
    }
#endif

  /* realloc of null is supposed to be same as malloc */
  if (oldmem == 0)
    return __libc_malloc (bytes);

  /* chunk corresponding to oldmem */
  const mchunkptr oldp = mem2chunk (oldmem);
  /* its size */
  const INTERNAL_SIZE_T oldsize = chunksize (oldp);

  if (chunk_is_mmapped (oldp))
    ar_ptr = NULL;
  else
    ar_ptr = arena_for_chunk (oldp);

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) oldp > (uintptr_t) -oldsize, 0)
      || __builtin_expect (misaligned_chunk (oldp), 0))
    {
      malloc_printerr (check_action, "realloc(): invalid pointer", oldmem,
		       ar_ptr);
      return NULL;
    }

  checked_request2size (bytes, nb);

  if (chunk_is_mmapped (oldp))
    {
      void *newmem;

#if HAVE_MREMAP
      newp = mremap_chunk (oldp, nb);
      if (newp)
        return chunk2mem (newp);
#endif
      /* Note the extra SIZE_SZ overhead. */
      if (oldsize - SIZE_SZ >= nb)
        return oldmem;                         /* do nothing */

      /* Must alloc, copy, free. */
      newmem = __libc_malloc (bytes);
      if (newmem == 0)
        return 0;              /* propagate failure */

      memcpy (newmem, oldmem, oldsize - 2 * SIZE_SZ);
      munmap_chunk (oldp);
      return newmem;
    }

  (void) mutex_lock (&ar_ptr->mutex);

  newp = _int_realloc (ar_ptr, oldp, oldsize, nb);

  (void) mutex_unlock (&ar_ptr->mutex);
  assert (!newp || chunk_is_mmapped (mem2chunk (newp)) ||
          ar_ptr == arena_for_chunk (mem2chunk (newp)));

  if (newp == NULL)
    {
      /* Try harder to allocate memory in other arenas.  */
      LIBC_PROBE (memory_realloc_retry, 2, bytes, oldmem);
      newp = __libc_malloc (bytes);
      if (newp != NULL)
        {
          memcpy (newp, oldmem, oldsize - SIZE_SZ);
          _int_free (ar_ptr, oldp, 0);
        }
    }

  return newp;
}
