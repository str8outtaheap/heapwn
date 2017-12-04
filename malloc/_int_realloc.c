void*
_int_realloc(mstate av, mchunkptr oldp, INTERNAL_SIZE_T oldsize,
	     INTERNAL_SIZE_T nb)
{
  mchunkptr        newp;            /* chunk to return */
  INTERNAL_SIZE_T  newsize;         /* its size */
  void*          newmem;          /* corresponding user mem */

  mchunkptr        next;            /* next contiguous chunk after oldp */

  mchunkptr        remainder;       /* extra space at end of newp */
  unsigned long    remainder_size;  /* its size */

  mchunkptr        bck;             /* misc temp for linking */
  mchunkptr        fwd;             /* misc temp for linking */

  unsigned long    copysize;        /* bytes to copy */
  unsigned int     ncopies;         /* INTERNAL_SIZE_T words to copy */
  INTERNAL_SIZE_T* s;               /* copy source */
  INTERNAL_SIZE_T* d;               /* copy destination */

  /* oldmem size */
  if (__builtin_expect (chunksize_nomask (oldp) <= 2 * SIZE_SZ, 0)
      || __builtin_expect (oldsize >= av->system_mem, 0))
    malloc_printerr ("realloc(): invalid old size");

  check_inuse_chunk (av, oldp);

  /* All callers already filter out mmap'ed chunks.  */
  assert (!chunk_is_mmapped (oldp));

  next = chunk_at_offset (oldp, oldsize);
  INTERNAL_SIZE_T nextsize = chunksize (next);
  if (__builtin_expect (chunksize_nomask (next) <= 2 * SIZE_SZ, 0)
      || __builtin_expect (nextsize >= av->system_mem, 0))
    malloc_printerr ("realloc(): invalid next size");

  if ((unsigned long) (oldsize) >= (unsigned long) (nb))
    {
      /* already big enough; split below */
      newp = oldp;
      newsize = oldsize;
    }

  else
    {
      /* Try to expand forward into top */
      if (next == av->top &&
          (unsigned long) (newsize = oldsize + nextsize) >=
          (unsigned long) (nb + MINSIZE))
        {
          set_head_size (oldp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
          av->top = chunk_at_offset (oldp, nb);
          set_head (av->top, (newsize - nb) | PREV_INUSE);
          check_inuse_chunk (av, oldp);
          return chunk2mem (oldp);
        }

      /* Try to expand forward into next chunk;  split off remainder below */
      else if (next != av->top &&
               !inuse (next) &&
               (unsigned long) (newsize = oldsize + nextsize) >=
               (unsigned long) (nb))
        {
          newp = oldp;
          unlink (av, next, bck, fwd);
        }

      /* allocate, copy, free */
      else
        {
          newmem = _int_malloc (av, nb - MALLOC_ALIGN_MASK);
          if (newmem == 0)
            return 0; /* propagate failure */

          newp = mem2chunk (newmem);
          newsize = chunksize (newp);

          /*
             Avoid copy if newp is next chunk after oldp.
           */
          if (newp == next)
            {
              newsize += oldsize;
              newp = oldp;
            }
          else
            {
              /*
                 Unroll copy of <= 36 bytes (72 if 8byte sizes)
                 We know that contents have an odd number of
                 INTERNAL_SIZE_T-sized words; minimally 3.
               */

              copysize = oldsize - SIZE_SZ;
              s = (INTERNAL_SIZE_T *) (chunk2mem (oldp));
              d = (INTERNAL_SIZE_T *) (newmem);
              ncopies = copysize / sizeof (INTERNAL_SIZE_T);
              assert (ncopies >= 3);

              if (ncopies > 9)
                memcpy (d, s, copysize);

              else
                {
                  *(d + 0) = *(s + 0);
                  *(d + 1) = *(s + 1);
                  *(d + 2) = *(s + 2);
                  if (ncopies > 4)
                    {
                      *(d + 3) = *(s + 3);
                      *(d + 4) = *(s + 4);
                      if (ncopies > 6)
                        {
                          *(d + 5) = *(s + 5);
                          *(d + 6) = *(s + 6);
                          if (ncopies > 8)
                            {
                              *(d + 7) = *(s + 7);
                              *(d + 8) = *(s + 8);
                            }
                        }
                    }
                }

              _int_free (av, oldp, 1);
              check_inuse_chunk (av, newp);
              return chunk2mem (newp);
            }
        }
    }

  /* If possible, free extra space in old or extended chunk */

  assert ((unsigned long) (newsize) >= (unsigned long) (nb));

  remainder_size = newsize - nb;

  if (remainder_size < MINSIZE)   /* not enough extra to split off */
    {
      set_head_size (newp, newsize | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_inuse_bit_at_offset (newp, newsize);
    }
  else   /* split remainder */
    {
      remainder = chunk_at_offset (newp, nb);
      set_head_size (newp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE |
                (av != &main_arena ? NON_MAIN_ARENA : 0));
      /* Mark remainder as inuse so free() won't complain */
      set_inuse_bit_at_offset (remainder, remainder_size);
      _int_free (av, remainder, 1);
    }

  check_inuse_chunk (av, newp);
  return chunk2mem (newp);
}
